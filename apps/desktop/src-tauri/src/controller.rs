use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tauri::{AppHandle, State, WebviewWindow};
use tauri_plugin_shell::ShellExt;

const MAX_REQUEST: usize = 32 * 1024;
const MAX_RESPONSE: usize = 1024 * 1024 + 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// The controller's exit status when another controller holds the data directory.
const EXIT_CONTROLLER_RUNNING: i32 = 3;

type Reply = Result<Value, String>;
type Job = (Vec<u8>, Instant, mpsc::Sender<Reply>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesktopRequest {
    method: String,
    path: String,
    body: Value,
}

struct ControllerSession {
    // Shared with the supervisor, so that shutdown can stop it while a request holds the session.
    child: Arc<Mutex<Child>>,
    sender: mpsc::Sender<Job>,
}

impl ControllerSession {
    // Only the bundled controller binary is ever started.
    fn start(app: &AppHandle) -> Result<Self, String> {
        let command: Command = app
            .shell()
            .sidecar("egresslab-controller")
            .map_err(|_| "Controller sidecar is missing".to_string())?
            .into();

        Self::spawn(command)
    }

    fn spawn(mut command: Command) -> Result<Self, String> {
        let mut child = command
            .arg("-desktop")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| "Could not start controller".to_string())?;

        let Some(mut input) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Controller stdin unavailable".into());
        };

        let Some(output) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Controller stdout unavailable".into());
        };

        let mut output = BufReader::new(output);
        let (sender, receiver) = mpsc::channel::<Job>();

        let worker = thread::Builder::new()
            .name("controller-ipc".into())
            .spawn(move || {
                for (request, deadline, reply) in receiver {
                    let result = (|| -> Reply {
                        if Instant::now() >= deadline {
                            return Err(
                                "Controller busy; the request expired before it was sent".into()
                            );
                        }

                        input
                            .write_all(&request)
                            .map_err(|_| "Controller write failed")?;
                        input.flush().map_err(|_| "Controller flush failed")?;

                        let mut response = Vec::new();

                        (&mut output)
                            .take(MAX_RESPONSE as u64)
                            .read_until(b'\n', &mut response)
                            .map_err(|_| "Controller read failed")?;

                        if response.last() != Some(&b'\n') {
                            return Err("Incomplete or oversized response".into());
                        }

                        let value: Value = serde_json::from_slice(&response)
                            .map_err(|_| "Invalid controller response")?;

                        let status = value["status"].as_u64();

                        if value["version"].as_u64() != Some(1)
                            || !matches!(status, Some(200..=599))
                            || value.get("body").is_none()
                        {
                            return Err("Unsupported controller response".into());
                        }

                        Ok(value)
                    })();

                    let failed = result.is_err();
                    let _ = reply.send(result);

                    if failed {
                        break;
                    }
                }
            });

        if worker.is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("Could not start IPC worker".into());
        }

        Ok(Self {
            child: Arc::new(Mutex::new(child)),
            sender,
        })
    }

    fn request(&mut self, request: DesktopRequest, deadline: Instant) -> Reply {
        let payload = json!({
            "version": 1,
            "method": request.method,
            "path": request.path,
            "body": request.body
        });

        let mut bytes = serde_json::to_vec(&payload).map_err(|_| "Could not encode request")?;

        if bytes.len() + 1 >= MAX_REQUEST {
            return Err("Request too large".into());
        }

        bytes.push(b'\n');

        let (tx, rx) = mpsc::channel();

        self.sender
            .send((bytes, deadline, tx))
            .map_err(|_| "Controller is offline")?;

        rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "Controller unavailable or request timed out")?
    }
}

impl Drop for ControllerSession {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// Why a controller that failed a request stopped, when it says so through its exit status.
fn exit_reason(child: &Arc<Mutex<Child>>) -> Option<String> {
    let deadline = Instant::now() + Duration::from_millis(500);

    loop {
        if let Some(status) = child.lock().ok()?.try_wait().ok()? {
            return (status.code() == Some(EXIT_CONTROLLER_RUNNING)).then(|| {
                "Another EgressLab controller is using this data directory. Stop it, then retry."
                    .to_string()
            });
        }

        if Instant::now() >= deadline {
            return None;
        }

        thread::sleep(Duration::from_millis(20));
    }
}

pub struct ControllerSupervisor {
    session: Mutex<Option<ControllerSession>>,
    running: Mutex<Option<Arc<Mutex<Child>>>>,
    closing: AtomicBool,
    timeout: Duration,
}

impl Default for ControllerSupervisor {
    fn default() -> Self {
        Self {
            session: Mutex::default(),
            running: Mutex::default(),
            closing: AtomicBool::default(),
            timeout: REQUEST_TIMEOUT,
        }
    }
}

impl ControllerSupervisor {
    fn request(&self, app: &AppHandle, request: DesktopRequest) -> Reply {
        self.request_with(|| ControllerSession::start(app), request)
    }

    fn request_with(
        &self,
        start: impl FnOnce() -> Result<ControllerSession, String>,
        request: DesktopRequest,
    ) -> Reply {
        // The deadline counts the wait behind earlier requests too.
        let deadline = Instant::now() + self.timeout;

        let mut session = self
            .session
            .lock()
            .map_err(|_| "Controller supervisor unavailable")?;

        if self.closing.load(Ordering::Acquire) {
            return Err("Application is shutting down".into());
        }

        if Instant::now() >= deadline {
            return Err("Controller busy; the request expired before it was sent".into());
        }

        if session.is_none() {
            let started = start()?;

            // Registered under the lock shutdown takes, so a shutdown that began meanwhile is seen
            // here, before any work is sent.
            let mut running = self
                .running
                .lock()
                .map_err(|_| "Controller supervisor unavailable")?;

            if self.closing.load(Ordering::Acquire) {
                drop(running);
                drop(started);
                return Err("Application is shutting down".into());
            }

            *running = Some(Arc::clone(&started.child));
            drop(running);

            *session = Some(started);
        }

        // Starting a controller takes time too; the reply waits only for what is left.
        if Instant::now() >= deadline {
            return Err("Controller busy; the request expired before it was sent".into());
        }

        let result = session
            .as_mut()
            .ok_or("Controller unavailable")?
            .request(request, deadline);

        if let Err(error) = result {
            // The outcome is unknown: discard the session and never replay the request.
            let reason = session.as_ref().and_then(|s| exit_reason(&s.child));
            session.take();

            return Err(reason.unwrap_or(error));
        }

        result
    }

    // Stops the controller at once, even while a request waits on it; that request then fails and
    // releases the session.
    pub fn shutdown(&self) {
        self.closing.store(true, Ordering::Release);

        if let Ok(running) = self.running.lock() {
            if let Some(child) = running.as_ref() {
                if let Ok(mut child) = child.lock() {
                    let _ = child.kill();
                }
            }
        }

        if let Ok(mut session) = self.session.lock() {
            session.take();
        }
    }
}

#[tauri::command]
pub async fn controller_request(
    app: AppHandle,
    window: WebviewWindow,
    supervisor: State<'_, Arc<ControllerSupervisor>>,
    request: DesktopRequest,
) -> Reply {
    if window.label() != "main" {
        return Err("Window is not authorized".into());
    }

    let supervisor = Arc::clone(supervisor.inner());

    tauri::async_runtime::spawn_blocking(move || supervisor.request(&app, request))
        .await
        .map_err(|_| "Controller task failed".to_string())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    // The sidecar that `yarn build:sidecar` built for this target.
    fn sidecar() -> PathBuf {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("binaries")
            .join(format!(
                "egresslab-controller-{}{}",
                env!("EGRESSLAB_TARGET_TRIPLE"),
                std::env::consts::EXE_SUFFIX
            ));

        assert!(path.is_file(), "run `yarn build:sidecar` first");

        path
    }

    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(name: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "egresslab-desktop-{name}-{}-{nanos}",
                std::process::id()
            ));

            fs::create_dir_all(&dir).unwrap();

            Self(dir)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn controller(data: &ScratchDir) -> Command {
        let mut command = Command::new(sidecar());
        command.env("EGRESSLAB_DATA_DIR", &data.0);
        command
    }

    fn call(session: &mut ControllerSession, method: &str, path: &str, body: Value) -> Value {
        session
            .request(
                DesktopRequest {
                    method: method.into(),
                    path: path.into(),
                    body,
                },
                Instant::now() + REQUEST_TIMEOUT,
            )
            .unwrap()
    }

    #[test]
    fn manages_profiles_and_refuses_activation() {
        let data = ScratchDir::new("profiles");
        let mut session = ControllerSession::spawn(controller(&data)).unwrap();

        let created = call(
            &mut session,
            "POST",
            "/profiles",
            json!({ "name": "Desktop Test" }),
        );
        assert_eq!(created["status"], 201);

        let id = created["body"]["id"].as_str().unwrap().to_string();

        let listed = call(&mut session, "GET", "/profiles", Value::Null);
        assert_eq!(listed["status"], 200);
        assert_eq!(listed["body"]["items"].as_array().unwrap().len(), 1);

        let start = call(
            &mut session,
            "POST",
            "/endpoints/proxy_0123456789abcdef/start",
            Value::Null,
        );
        assert_eq!(start["status"], 403);
        assert_eq!(start["body"]["error"]["code"], "IPC_OPERATION_DENIED");

        drop(session);

        // A new controller reads what the previous one saved.
        let mut session = ControllerSession::spawn(controller(&data)).unwrap();

        let listed = call(&mut session, "GET", "/profiles", Value::Null);
        assert_eq!(listed["body"]["items"][0]["id"], id.as_str());

        let deleted = call(
            &mut session,
            "DELETE",
            &format!("/profiles/{id}"),
            Value::Null,
        );
        assert_eq!(deleted["status"], 204);
        assert_eq!(deleted["body"], Value::Null);
    }

    #[test]
    fn refuses_a_second_writer() {
        let data = ScratchDir::new("writer");
        let mut session = ControllerSession::spawn(controller(&data)).unwrap();

        // The first controller holds the lock once it answered.
        assert_eq!(
            call(&mut session, "GET", "/health", Value::Null)["status"],
            200
        );

        let mut second = controller(&data)
            .arg("-desktop")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);

        let status = loop {
            if let Some(status) = second.try_wait().unwrap() {
                break status;
            }

            assert!(
                Instant::now() < deadline,
                "the second controller kept running"
            );
            thread::sleep(Duration::from_millis(50));
        };

        assert!(!status.success());
    }

    #[test]
    fn refuses_oversized_requests() {
        let data = ScratchDir::new("oversized");
        let mut session = ControllerSession::spawn(controller(&data)).unwrap();

        let result = session.request(
            DesktopRequest {
                method: "POST".into(),
                path: "/profiles".into(),
                body: json!({ "name": "x".repeat(MAX_REQUEST) }),
            },
            Instant::now() + REQUEST_TIMEOUT,
        );

        assert_eq!(result.unwrap_err(), "Request too large");
    }

    #[cfg(unix)]
    #[test]
    fn leaves_no_controller_behind() {
        let data = ScratchDir::new("exit");
        let session = ControllerSession::spawn(controller(&data)).unwrap();
        let pid = session.child.lock().unwrap().id().to_string();

        drop(session);

        let alive = Command::new("kill")
            .args(["-0", &pid])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success();

        assert!(!alive, "the controller outlived its session");
    }

    #[cfg(unix)]
    #[test]
    fn shutdown_does_not_wait_for_a_request() {
        let supervisor = Arc::new(ControllerSupervisor::default());
        let busy = Arc::clone(&supervisor);

        // A controller that never answers.
        let request = thread::spawn(move || {
            busy.request_with(
                || {
                    let mut command = Command::new("sh");
                    command.args(["-c", "exec sleep 30", "sh"]);
                    ControllerSession::spawn(command)
                },
                DesktopRequest {
                    method: "GET".into(),
                    path: "/health".into(),
                    body: Value::Null,
                },
            )
        });

        thread::sleep(Duration::from_millis(300));

        let started = Instant::now();
        supervisor.shutdown();

        assert!(
            started.elapsed() < Duration::from_secs(3),
            "shutdown waited for the request"
        );
        assert!(request.join().unwrap().is_err());
        assert!(supervisor.session.lock().unwrap().is_none());
    }

    fn never_answering() -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", "exec sleep 30", "sh"]);
        command
    }

    fn health() -> DesktopRequest {
        DesktopRequest {
            method: "GET".into(),
            path: "/health".into(),
            body: Value::Null,
        }
    }

    fn alive(pid: u32) -> bool {
        Command::new("kill")
            .args(["-0", &pid.to_string()])
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    }

    // A shutdown that begins while a controller starts stops it before any work is sent.
    #[cfg(unix)]
    #[test]
    fn shutdown_during_start_sends_nothing() {
        let supervisor = ControllerSupervisor::default();
        let pid = Mutex::new(None);

        let started = Instant::now();
        let result = supervisor.request_with(
            || {
                let session = ControllerSession::spawn(never_answering())?;
                *pid.lock().unwrap() = Some(session.child.lock().unwrap().id());
                supervisor.closing.store(true, Ordering::Release);
                Ok(session)
            },
            health(),
        );

        assert_eq!(result.unwrap_err(), "Application is shutting down");
        assert!(started.elapsed() < Duration::from_secs(3));
        assert!(supervisor.session.lock().unwrap().is_none());
        assert!(supervisor.running.lock().unwrap().is_none());
        assert!(!alive(pid.lock().unwrap().unwrap()));
    }

    // A request whose deadline passed while it waited for the session is never sent.
    #[test]
    fn expired_requests_are_not_sent() {
        let supervisor = Arc::new(ControllerSupervisor {
            timeout: Duration::from_millis(300),
            ..ControllerSupervisor::default()
        });

        let held = supervisor.session.lock().unwrap();
        let queued = Arc::clone(&supervisor);
        let starts = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&starts);

        let request = thread::spawn(move || {
            queued.request_with(
                || {
                    *counted.lock().unwrap() += 1;
                    Err("started".into())
                },
                health(),
            )
        });

        thread::sleep(Duration::from_millis(500));
        drop(held);

        let result = request.join().unwrap();

        assert!(result.unwrap_err().contains("expired"));
        assert_eq!(*starts.lock().unwrap(), 0);
    }

    // A request whose deadline passed while its controller started is not sent.
    #[test]
    fn expired_after_start_is_not_sent() {
        let data = ScratchDir::new("late");
        let supervisor = ControllerSupervisor {
            timeout: Duration::from_millis(300),
            ..ControllerSupervisor::default()
        };

        let result = supervisor.request_with(
            || {
                thread::sleep(Duration::from_millis(400));
                ControllerSession::spawn(controller(&data))
            },
            DesktopRequest {
                method: "POST".into(),
                path: "/profiles".into(),
                body: json!({ "name": "Late" }),
            },
        );

        assert!(result.unwrap_err().contains("expired"));
        assert!(
            !data.0.join("state.json").exists()
                || !fs::read_to_string(data.0.join("state.json"))
                    .unwrap()
                    .contains("Late")
        );
    }

    // A controller stopped by another one's writer lock is reported as such, not as a pipe error.
    #[test]
    fn reports_a_controller_already_running() {
        let data = ScratchDir::new("held");
        let mut first = ControllerSession::spawn(controller(&data)).unwrap();
        assert_eq!(
            call(&mut first, "GET", "/health", Value::Null)["status"],
            200
        );

        let supervisor = ControllerSupervisor::default();
        let result =
            supervisor.request_with(|| ControllerSession::spawn(controller(&data)), health());

        assert!(result
            .unwrap_err()
            .starts_with("Another EgressLab controller is using this data directory"));
        assert!(supervisor.session.lock().unwrap().is_none());
    }

    #[test]
    fn worker_does_not_send_an_expired_request() {
        let data = ScratchDir::new("worker-expired");
        let mut session = ControllerSession::spawn(controller(&data)).unwrap();

        let result = session.request(
            DesktopRequest {
                method: "POST".into(),
                path: "/profiles".into(),
                body: json!({ "name": "Expired" }),
            },
            Instant::now(),
        );
        assert!(result.is_err());

        let waited = Instant::now() + Duration::from_secs(5);
        while session.child.lock().unwrap().try_wait().unwrap().is_none() {
            assert!(Instant::now() < waited, "the expired request was sent");
            thread::sleep(Duration::from_millis(20));
        }
        drop(session);

        let mut session = ControllerSession::spawn(controller(&data)).unwrap();
        let profiles = call(&mut session, "GET", "/profiles", Value::Null);
        assert_eq!(profiles["body"]["items"], json!([]));
    }
}
