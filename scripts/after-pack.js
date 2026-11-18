// 打包后写入 exe 图标与版本信息。
// 说明：Windows 上 electron-builder 内置的 rcedit 需要解压 winCodeSign 包，
// 该包内含 darwin 符号链接，非管理员会话解压会失败。这里改为复用缓存里已存在的
// rcedit-x64.exe，因此 package.json 中关闭了内置的 signAndEditExecutable。
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

function findRcedit() {
  if (process.env.RCEDIT_PATH && fs.existsSync(process.env.RCEDIT_PATH)) return process.env.RCEDIT_PATH;
  const cache = path.join(process.env.LOCALAPPDATA || '', 'electron-builder', 'Cache', 'winCodeSign');
  if (!fs.existsSync(cache)) return null;
  for (const dir of fs.readdirSync(cache)) {
    const candidate = path.join(cache, dir, 'rcedit-x64.exe');
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

module.exports = async function afterPack(context) {
  if (context.electronPlatformName !== 'win32') return;
  const rcedit = findRcedit();
  if (!rcedit) {
    console.warn('[afterPack] ✗ 未找到 rcedit-x64.exe：exe 图标与版本信息不会写入。');
    console.warn('[afterPack]   可设置环境变量 RCEDIT_PATH 指向 rcedit，或先联网构建一次让 electron-builder 缓存该工具。');
    return;
  }
  const pkg = require('../package.json');
  const exe = path.join(context.appOutDir, pkg.build.productName + '.exe');
  if (!fs.existsSync(exe)) {
    console.warn('[afterPack] ✗ 未找到 ' + exe + '，跳过资源写入');
    return;
  }
  const icon = path.join(__dirname, '..', 'build', 'icon.ico');
  const args = [
    exe,
    '--set-file-version', pkg.version,
    '--set-product-version', pkg.version,
    '--set-version-string', 'ProductName', 'random 密码生成器',
    '--set-version-string', 'FileDescription', 'random 密码生成器 · 密钥管理',
    '--set-version-string', 'CompanyName', pkg.author
  ];
  if (fs.existsSync(icon)) args.push('--set-icon', icon);
  try {
    execFileSync(rcedit, args, { stdio: 'inherit' });
  } catch (err) {
    console.warn('[afterPack] 写入 exe 资源失败：' + err.message);
  }
};
