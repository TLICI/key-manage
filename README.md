# random 密码生成器 · 密钥管理

同一套 `www/` 网页代码，同时打包成 **Windows 桌面客户端** 与 **安卓 APK**。

## 目录结构

```
www/                 共用页面（index.html / styles.css / app.js），全部逻辑都在这里
electron/main.js     Electron 主进程（窗口、菜单、下载保存对话框）
scripts/             图标生成、版本同步、打包后处理（写版本号/图标进 exe）
build/               图标源文件 icon.svg 及生成的 icon.png / icon.ico
android/             Capacitor 安卓工程（Gradle）；keystore.properties 用于 release 签名
dist/                构建产物
```

## 直接使用

| 产物 | 说明 |
| --- | --- |
| `dist/random-key-manager-<版本>-setup.exe` | Windows 安装包（可选安装目录、创建快捷方式） |
| `dist/random-key-manager-<版本>-portable.exe` | 免安装单文件，双击即用 |
| `dist/random-key-manager-<版本>-debug.apk` | 安卓调试包（Android 5.1+，debug 签名） |

APK 安装时需允许「安装未知来源应用」。数据保存在各自应用内（WebView 的 localStorage），
跨设备同步用「导出 JSON / CSV → 另一台设备批量导入」。

**备份注意**：桌面端导出会弹系统保存对话框，只有保存成功才会提示「已导出」，取消或写入失败会如实提示；
安卓 WebView 不能直接下载文件，导出会弹出可复制的文本框，点「复制全部」后自己粘到备忘录或文件传输助手里保存。
用 Excel 打开 CSV 会把纯数字密码当数字处理（前导 0 丢失、超长变科学计数法），重要备份请用 JSON。

## 开发与构建

```bash
npm install          # 安装依赖

npm start            # 本地运行桌面客户端（开发模式）
npm run desktop:build:win    # 打包 Windows（NSIS 安装包 + portable）
npm run desktop:pack         # 只解包不压缩，便于排查

npm run icon                 # 重新生成桌面图标
node scripts/make-android-icons.js   # 重新生成安卓图标与启动图

npm run self-check           # 回归自检：导出→导入闭环、存储字段、键盘可达性
npm run android:build        # 同步网页资源并编译 debug APK
# 产物：android/app/build/outputs/apk/debug/app-debug.apk
```

改了 `www/app.js` 或 `www/styles.css` 后先跑一次 `npm run self-check`，它会用隐藏窗口真实加载页面，把导出/导入、加密往返、本地存储字段和键盘条目逐个验一遍；打包 APK 前记得 `npm run cap:sync`，否则装进 APK 的还是上一次的网页资源。

需要 Node 18+、JDK 17/21、Android SDK（`ANDROID_HOME` 已配置，含 platform 34 与 build-tools）。

### 安卓 release 签名

在 `android/keystore.properties` 写入四项后直接 `assembleRelease`：

```properties
storeFile=../keystore/你的.jks
storePassword=...
keyAlias=...
keyPassword=...
```

文件不存在时 `build.gradle` 自动回退到 debug 签名，不会构建失败（适合自用）；
正式分发给他人时请务必配置，否则对方无法覆盖升级。

## 功能

- 长度 15–20，可选 a-z / A-Z / 0-9 / `!@#$=+-_`，可选排除易混淆字符，`crypto.getRandomValues` 生成
- 长度与字符集勾选会被记住，下次启动沿用；拖动滑块或改动字符集会立刻按新设置重算密码
- 命名保存、手动记录自有密钥、批量导入（文本 / CSV / JSON）、搜索、显示 / 隐藏、复制、删除、重命名
- **AES-256-GCM 加密存储**：勾选记录批量加密，主密钥 8–20 字符；解密只缓存在内存，切到后台即丢弃
- 批量解密按密文盐分组复用派生密钥，几十条也不会逐条重算 PBKDF2
- 导出 JSON / CSV（可只导出选中项，可保留密文），导入支持 UTF-8 / GBK / UTF-16（记事本「Unicode」）
- 导入自动识别逗号 / 全角逗号 / Tab 分隔（按前几行投票，首行没分隔符也能正确判断），单文件上限 8MB
- 明文存储时给出提示，支持一键补加密
- 多窗口 / 多标签同时打开会互相同步
- 列表可用键盘操作：Tab 聚焦名称后按 Enter/F2 重命名，聚焦密码区后按 Enter 复制或展开
- 安卓实体返回键优先关闭弹窗，没有弹窗时才退出应用
