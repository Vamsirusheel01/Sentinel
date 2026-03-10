const { app, BrowserWindow, Tray, Menu } = require('electron');
const path = require('path');

console.log('[Electron] CommonJS process starting...');

let mainWindow;
let tray;

function createWindow() {
  console.log('[Electron] Creating window...');
  
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
    mainWindow.loadURL(devServerUrl).catch(err => {
        console.error('[Electron] Failed to load URL:', err.message);
    });
  } else {
    const prodPath = path.join(__dirname, 'dist/index.html');
    console.log('[Electron] Loading production build:', prodPath);
    mainWindow.loadFile(prodPath);
  }

  mainWindow.on('close', (event) => {
    if (!app.isQuiting) {
      event.preventDefault();
      mainWindow.hide();
      console.log('[Electron] Window hidden to tray.');
    }
  });

  mainWindow.on('closed', () => {
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
      { label: 'Quit', click: () => { 
        app.isQuiting = true;
        app.quit(); 
      } }
    ]);
    tray.setToolTip('Sentinel Autonomous Defense');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => {
      if (mainWindow) mainWindow.show();
      else createWindow();
    });
    console.log('[Electron] Tray created.');
  } catch (e) {
    console.warn('[Electron] Tray error (likely icon not found):', e.message);
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
