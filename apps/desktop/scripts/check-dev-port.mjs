import { createConnection } from 'node:net';

// `tauri dev` loads whatever answers on the dev URL, and that page gets the desktop IPC. Refuse to
// start while another process already holds the port.
const socket = createConnection({ host: '127.0.0.1', port: 5173 });

socket.setTimeout(1000);

socket.once('connect', () => {
  console.error('Port 5173 is already in use; stop that process before running the desktop app.');
  socket.destroy();
  process.exit(1);
});

socket.once('timeout', () => {
  console.error('Could not check port 5173.');
  socket.destroy();
  process.exit(1);
});

socket.once('error', (error) => {
  if (error.code === 'ECONNREFUSED') {
    process.exit(0);
  }

  console.error(`Could not check port 5173: ${error.code}`);
  process.exit(1);
});
