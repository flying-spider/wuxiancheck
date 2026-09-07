const { contextBridge, ipcRenderer } = require('electron');

// 暴露给工具栏页面的安全接口
contextBridge.exposeInMainWorld('proxyApi', {
  navigate: (url) => ipcRenderer.invoke('navigate', url),
  refreshProxy: () => ipcRenderer.invoke('refresh-proxy'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (s) => ipcRenderer.invoke('save-settings', s),
  getCurrentUrl: () => ipcRenderer.invoke('get-current-url'),
  getStatus: () => ipcRenderer.invoke('get-status'),
  setSettingsOpen: (open) => ipcRenderer.invoke('set-settings-open', open),
  setLogOpen: (open) => ipcRenderer.invoke('set-log-open', open),
  getLogs: () => ipcRenderer.invoke('get-logs'),
  getZoom: () => ipcRenderer.invoke('get-zoom'),
  zoomBy: (delta) => ipcRenderer.invoke('zoom-by', delta),
  zoomReset: () => ipcRenderer.invoke('zoom-reset'),
  onUrlChanged: (cb) => ipcRenderer.on('url-changed', (_e, url) => cb(url)),
  onLoading: (cb) => ipcRenderer.on('loading', (_e, loading) => cb(loading)),
  onLoadError: (cb) => ipcRenderer.on('load-error', (_e, info) => cb(info)),
  onPoolStatus: (cb) => ipcRenderer.on('pool-status', (_e, status) => cb(status)),
  onLog: (cb) => ipcRenderer.on('log', (_e, line) => cb(line)),
});
