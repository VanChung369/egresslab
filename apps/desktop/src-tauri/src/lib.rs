mod controller;

use controller::ControllerSupervisor;
use std::sync::Arc;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(Arc::new(ControllerSupervisor::default()))
        .invoke_handler(tauri::generate_handler![controller::controller_request])
        .build(tauri::generate_context!())
        .expect("Could not build EgressLab")
        .run(|app, event| {
            if let tauri::RunEvent::Exit = event {
                app.state::<Arc<ControllerSupervisor>>().shutdown();
            }
        });
}
