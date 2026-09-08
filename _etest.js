// Minimal Electron reproduction: does a WebContentsView with persist:proxysession
// partition actually route its requests through the local MITM proxy?
const { app, BrowserWindow, WebContentsView } = require('electron');

const PARTITION = 'persist:proxysession';
const PROXY = 'http=127.0.0.1:8899;https=127.0.0.1:8899';
const BYPASS = '<local>';
const URL_TO_LOAD = process.argv[2] || 'https://example.com/';

app.commandLine.appendSwitch('ignore-certificate-errors');

let win;
let view;
let viewWC;

function layout() {
  if (!win || win.isDestroyed() || !view) return;
  const [w, h] = win.getContentSize();
  view.setBounds({ x: 0, y: 0, width: w, height: h });
}

async function make() {
  win = new BrowserWindow({ width: 1000, height: 700, show: false, autoHideMenuBar: true });
  view = new WebContentsView({ webPreferences: { partition: PARTITION } });
  win.contentView.addChildView(view);
  layout();
  win.on('resize', layout);
  viewWC = view.webContents;

  // Apply proxy exactly like main.js: applyBrowserProxy
  await viewWC.session.setProxy({ proxyRules: PROXY, proxyBypassRules: BYPASS })
    .then(() => console.log('SETPROXY ok'))
    .catch((e) => console.log('SETPROXY err', e && e.message));

  // Set UA like main.js
  viewWC.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  viewWC.on('did-finish-load', () => console.log('DID-FINISH-LOAD'));
  viewWC.on('did-fail-load', (_e, code, desc, url, isMain) => {
    if (isMain) console.log('DID-FAIL-LOAD', code, desc, url);
  });
  viewWC.on('did-start-loading', () => console.log('DID-START-LOADING'));
  viewWC.on('did-stop-loading', () => console.log('DID-STOP-LOADING'));
  viewWC.on('did-navigate', (_e, url) => console.log('DID-NAVIGATE', url));
  viewWC.on('console-message', (_e, level, msg) => console.log('RENDERER:', msg));

  console.log('LOADING', URL_TO_LOAD);
  await viewWC.loadURL(URL_TO_LOAD).catch((e) => console.log('loadURL err', e && e.message));
  console.log('LOADED, url=', viewWC.getURL());
}

app.whenReady().then(() => {
  console.log('ELECTRON READY');
  make().then(() => {
    console.log('DONE, waiting 8s...');
    setTimeout(() => app.exit(0), 8000);
  });
});
app.on('window-all-closed', () => app.quit());
