const { spawn } = require('child_process');
const http = require('http');

const DEV_SERVER_URL = 'http://127.0.0.1:5173';

function checkServer() {
  return new Promise((resolve) => {
    http.get(DEV_SERVER_URL, (res) => {
      resolve(res.statusCode === 200);
    }).on('error', () => {
      resolve(false);
    });
  });
}

async function start() {
  console.log('[Launcher] Waiting for Vite dev server...');
  let attempts = 0;
  while (!(await checkServer()) && attempts < 30) {
    attempts++;
    await new Promise(r => setTimeout(r, 1000));
  }

  if (attempts >= 30) {
    console.error('[Launcher] Timeout waiting for Vite.');
    process.exit(1);
  }

  console.log('[Launcher] Vite is up! Starting Electron...');
  
  const electronPath = process.platform === 'win32' 
    ? '.\\node_modules\\.bin\\electron.cmd' 
    : './node_modules/.bin/electron';

  const child = spawn(electronPath, ['main.cjs'], {
    stdio: 'inherit',
    env: { ...process.env, VITE_DEV_SERVER_URL: DEV_SERVER_URL },
    shell: true
  });

  child.on('close', (code) => {
    console.log(`[Launcher] Electron exited with code ${code}`);
    process.exit(code);
  });
}

start();
