import { app, BrowserWindow, Tray, Menu } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

console.log('[Electron] Main process starting...');
console.log('[Electron] __dirname:', __dirname);

let mainWindow;
let tray;

function createWindow() {
  console.log('[Electron] Creating window...');
  
  // Use src/logo.svg but only if found, otherwise no icon
  const iconPath = path.join(__dirname, 'src/logo.svg');
  console.log('[Electron] Using icon:', iconPath);

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    backgroundColor: '#0a0a0c',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
    title: 'Sentinel // Autonomous Defense',
    autoHideMenuBar: true,
  });

  const devServerUrl = process.env.VITE_DEV_SERVER_URL;
  if (devServerUrl) {
    console.log('[Electron] Connecting to dev server:', devServerUrl);
    mainWindow.loadURL(devServerUrl);
  } else {
    const prodPath = path.join(__dirname, 'dist/index.html');
    console.log('[Electron] Loading production build:', prodPath);
    mainWindow.loadFile(prodPath);
  }

  mainWindow.on('closed', () => {
    console.log('[Electron] Window closed.');
    mainWindow = null;
  });
}

function createTray() {
  console.log('[Electron] Creating tray...');
  try {
    const trayIconPath = path.join(__dirname, 'src/logo.svg');
    tray = new Tray(trayIconPath);
    const contextMenu = Menu.buildFromTemplate([
      { label: 'Open Sentinel', click: () => { if (mainWindow) mainWindow.show(); else createWindow(); } },
      { type: 'separator' },
      { label: 'Quit', click: () => { app.quit(); } }
    ]);
    tray.setToolTip('Sentinel Autonomous Defense');
    tray.setContextMenu(contextMenu);
    console.log('[Electron] Tray created.');
  } catch (e) {
    console.error('[Electron] Tray error:', e.message);
  }
}

app.on('ready', () => {
  console.log('[Electron] App ready!');
  createWindow();
  createTray();
});

app.on('window-all-closed', () => {
  console.log('[Electron] All windows closed.');
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
