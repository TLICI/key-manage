const { app, BrowserWindow, Menu, shell, dialog, session, screen } = require('electron');
const path = require('node:path');
const fs = require('node:fs');

const isDev = !app.isPackaged;
let mainWindow = null;

// 窗口位置/尺寸落盘，下次启动还原；损坏或超出屏幕时回落到默认值
const STATE_FILE = () => path.join(app.getPath('userData'), 'window-state.json');
const DEFAULT_BOUNDS = { width: 1060, height: 900 };

// Windows 的任务栏分组、跳转列表与通知都依赖 AppUserModelID，必须与 electron-builder 的 appId 一致
if (process.platform === 'win32') app.setAppUserModelId('com.randomkey.manager');

// 剪贴板是唯一放行的权限，其余（摄像头/麦克风/定位/通知/全屏…）全部拒绝
const CLIPBOARD_PERMISSIONS = new Set(['clipboard-read', 'clipboard-sanitized-write']);

function readWindowState() {
  try {
    const raw = JSON.parse(fs.readFileSync(STATE_FILE(), 'utf8'));
    const ok = ['x', 'y', 'width', 'height'].every(k => Number.isFinite(raw[k]));
    if (!ok || raw.width < 380 || raw.height < 560) return null;
    // 拔掉外接屏/改分辨率后，旧坐标可能落在屏幕外，检查窗口标题栏还在可视区域内
    const visible = screen.getAllDisplays().some(d => {
      const a = d.workArea;
      return raw.x < a.x + a.width - 80 && raw.x + raw.width > a.x + 80 &&
        raw.y < a.y + a.height - 40 && raw.y + raw.height > a.y;
    });
    if (!visible) return null;
    // 只取出这四个数值：这份文件在用户目录里可以被随意编辑，
    // 若把整个对象交给 BrowserWindow，写入 webPreferences 就能关掉
    // contextIsolation/sandbox 并加载任意 preload，等于本地任意代码执行。
    return { x: raw.x, y: raw.y, width: raw.width, height: raw.height };
  } catch (err) {
    return null;
  }
}

function saveWindowState() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  try {
    // 最大化/全屏时记录还原后的尺寸，否则下次启动会卡在全屏
    const b = mainWindow.isMaximized() || mainWindow.isFullScreen()
      ? mainWindow.getNormalBounds()
      : mainWindow.getBounds();
    fs.writeFileSync(STATE_FILE(), JSON.stringify(b));
  } catch (err) {
    /* 磁盘/权限问题不影响主流程 */
  }
}

// 拖动/缩放窗口时每帧都写盘没必要，停手 400ms 再落一次
let saveStateTimer = null;
function scheduleSaveWindowState() {
  clearTimeout(saveStateTimer);
  saveStateTimer = setTimeout(saveWindowState, 400);
}

// 下载（导出 JSON / CSV）时询问保存位置；只注册一次，避免窗口重建后重复弹窗
function attachDownloadHandler() {
  session.defaultSession.on('will-download', (event, item) => {
    const target = mainWindow && !mainWindow.isDestroyed()
      ? dialog.showSaveDialogSync(mainWindow, {
        title: '保存导出文件',
        defaultPath: path.join(app.getPath('downloads'), item.getFilename()),
        filters: [{ name: '导出文件', extensions: ['json', 'csv'] }]
      })
      : null;
    if (!target) {
      item.cancel();
      replyExport('cancelled');
      return;
    }
    item.setSavePath(target);
    // 用户选的目录可能不可写，成败都要让页面知道，否则 UI 只会谎报「已导出」
    item.once('done', (_e, state) => replyExport(state));
  });
}

function replyExport(state) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send('export-result', state);
}

function createWindow() {
  const saved = readWindowState();
  mainWindow = new BrowserWindow(Object.assign({
    width: DEFAULT_BOUNDS.width,
    height: DEFAULT_BOUNDS.height,
    minWidth: 380,
    minHeight: 560,
    title: 'random 密码生成器',
    backgroundColor: '#0f1117',
    autoHideMenuBar: true,
    icon: path.join(__dirname, '..', 'build', 'icon.png'),
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
      // 只做一件事：把「保存成功/取消/失败」转成 DOM 事件交给页面
      preload: path.join(__dirname, 'preload.js')
    }
  }, saved || {}));

  mainWindow.loadFile(path.join(__dirname, '..', 'www', 'index.html'));

  // 站点内不允许跳转或开新窗口，外链交给系统浏览器
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith('file://')) {
      event.preventDefault();
      if (/^https?:/i.test(url)) shell.openExternal(url);
    }
  });

  // 渲染进程崩溃时至少给用户一句解释，而不是留个白窗口
  mainWindow.webContents.on('render-process-gone', (_e, details) => {
    if (isDev) return;
    dialog.showMessageBox(mainWindow, {
      type: 'error',
      title: '界面异常退出',
      message: '页面进程意外结束（' + details.reason + '）。',
      detail: '本地密钥数据保存在应用目录中，重新打开即可继续使用。',
      buttons: ['重新载入', '退出']
    }).then(res => {
      if (res.response === 0 && mainWindow && !mainWindow.isDestroyed()) mainWindow.reload();
      else app.quit();
    });
  });

  mainWindow.on('resize', scheduleSaveWindowState);
  mainWindow.on('move', scheduleSaveWindowState);

  if (isDev) mainWindow.webContents.openDevTools({ mode: 'detach' });
}

function buildMenu() {
  const template = [
    {
      label: '文件',
      submenu: [
        {
          label: '重新载入',
          accelerator: 'CmdOrCtrl+R',
          click: () => mainWindow && mainWindow.reload()
        },
        { type: 'separator' },
        { role: 'quit', label: '退出' }
      ]
    },
    {
      label: '编辑',
      submenu: [
        { role: 'undo', label: '撤销' },
        { role: 'redo', label: '重做' },
        { type: 'separator' },
        { role: 'cut', label: '剪切' },
        { role: 'copy', label: '复制' },
        { role: 'paste', label: '粘贴' },
        { role: 'selectAll', label: '全选' }
      ]
    },
    {
      label: '视图',
      submenu: viewSubmenu()
    }
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

// 视图菜单：打包版不提供「开发者工具」，避免一键打开控制台读走本地明文
function viewSubmenu() {
  const items = [
    { role: 'resetZoom', label: '实际大小' },
    { role: 'zoomIn', label: '放大' },
    { role: 'zoomOut', label: '缩小' },
    { type: 'separator' },
    { role: 'togglefullscreen', label: '全屏' }
  ];
  if (isDev) items.push({ type: 'separator' }, { role: 'toggleDevTools', label: '开发者工具' });
  return items;
}

// 只允许一个实例
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    // 页面不申请任何系统能力（无摄像头/麦克风/定位/通知），默认一律拒绝。
    // 唯独剪贴板必须放行：Chromium 把 clipboard.writeText / readText 也算作权限，
    // 全拒会让「复制密码」失败，并让 45 秒自动清空剪贴板静默失效。
    session.defaultSession.setPermissionRequestHandler((_wc, permission, callback) => {
      callback(CLIPBOARD_PERMISSIONS.has(permission));
    });
    session.defaultSession.setPermissionCheckHandler((_wc, permission) => {
      return CLIPBOARD_PERMISSIONS.has(permission);
    });
    attachDownloadHandler();
    buildMenu();
    createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });

  app.on('before-quit', saveWindowState);
  app.on('window-all-closed', () => {
    saveWindowState();
    if (process.platform !== 'darwin') app.quit();
  });
}
