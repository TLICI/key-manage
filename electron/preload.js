const { ipcRenderer } = require('electron');

// 主进程的保存结果转成 DOM 事件：既不用 contextBridge 往页面塞全局对象，
// 也不受 contextIsolation 的隔离世界限制（DOM 事件在两个世界之间是共享的）
ipcRenderer.on('export-result', (_event, state) => {
  document.dispatchEvent(new CustomEvent('export-result', { detail: String(state || '') }));
});
