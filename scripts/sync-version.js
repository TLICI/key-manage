// 版本号单一来源：package.json 的 version。
// 构建前自动同步到 www/app.js（界面显示）与 android/app/build.gradle（versionName / versionCode）。
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const version = pkg.version;
const changes = [];

// 1) 前端显示用常量（www/index.html 里由脚本写入 #appVersion）
const appJsPath = path.join(root, 'www', 'app.js');
const appJs = fs.readFileSync(appJsPath, 'utf8');
const nextAppJs = appJs.replace(/const APP_VERSION = '[^']*';/, "const APP_VERSION = '" + version + "';");
if (nextAppJs !== appJs) {
  fs.writeFileSync(appJsPath, nextAppJs);
  changes.push('www/app.js -> ' + version);
}

// 2) 安卓 versionName / versionCode，versionCode 在版本变化时单调 +1
const gradlePath = path.join(root, 'android', 'app', 'build.gradle');
if (fs.existsSync(gradlePath)) {
  let gradle = fs.readFileSync(gradlePath, 'utf8');
  const nameMatch = gradle.match(/versionName\s+"([^"]+)"/);
  const codeMatch = gradle.match(/versionCode\s+(\d+)/);
  if (!nameMatch || nameMatch[1] !== version) {
    if (nameMatch) gradle = gradle.replace(/versionName\s+"[^"]+"/, 'versionName "' + version + '"');
    const nextCode = (codeMatch ? Number(codeMatch[1]) : 0) + 1;
    if (codeMatch) gradle = gradle.replace(/versionCode\s+\d+/, 'versionCode ' + nextCode);
    fs.writeFileSync(gradlePath, gradle);
    changes.push('android -> ' + version + ' (versionCode ' + nextCode + ')');
  }
}

console.log(changes.length ? '[sync-version] ' + changes.join('; ') : '[sync-version] 已是最新 ' + version);
