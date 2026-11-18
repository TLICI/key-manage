// 回归自检：用隐藏窗口真实加载 www/index.html，跑一遍容易出错的链路。
// 用途：改了 app.js / styles.css 后立刻确认「导出→导入」闭环、键盘可达性和存储字段没退化。
// 运行：npm run self-check（内部用 electron 起一个隐藏窗口，不会碰真实用户数据）
const { app, BrowserWindow } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

const root = path.join(__dirname, '..');
const results = [];

function check(name, ok, detail) {
  results.push({ name, ok, detail });
}

// 静态检查：app.js 引用的 DOM id 必须都在 index.html 里
function staticChecks() {
  const html = fs.readFileSync(path.join(root, 'www', 'index.html'), 'utf8');
  const js = fs.readFileSync(path.join(root, 'www', 'app.js'), 'utf8');
  const htmlIds = [...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]);
  const dup = htmlIds.filter((id, i) => htmlIds.indexOf(id) !== i);
  const used = new Set();
  for (const m of js.matchAll(/\$\('([^']+)'\)/g)) used.add(m[1]);
  for (const m of js.matchAll(/getElementById\('([^']+)'\)/g)) used.add(m[1]);
  const missing = [...used].filter(id => !htmlIds.includes(id));
  check('index.html 无重复 id', dup.length === 0, dup.join(', '));
  check('app.js 引用的 id 都存在', missing.length === 0, missing.join(', '));
}

const PROBE = `(async function(){
  const out = {};
  const PASS = 'pw123456';
  const tricky = [
    'a,b"c', 'line1\\nline2', '=SUM(A1)', '  前后空格  ',
    '中文·符号!@#$%^&*()', "'=x", '0123456789', 'tab\\there',
    '全角，逗号', '全角＝等号　全角空格'
  ];
  const mk = (arr, enc) => arr.map((p, i) => ({
    id: 'id' + i, name: '名' + i, password: p, enc: !!enc, batchId: enc ? 'b1' : '',
    createdAt: Date.now(), poolSize: 0, source: 'manual'
  }));

  /* 明文往返：CSV / JSON */
  entries = mk(tricky, false);
  for (const fmt of ['csv', 'json']) {
    const ex = await doExport(entries, fmt, 'plain', 't-' + fmt);
    const got = parseImport(ex.text).map(r => r.password);
    out['plain_' + fmt] = tricky.filter((p, i) => got[i] !== p).length;
  }

  /* 密文往返：导出「保持加密」再导入，能否原样解回 */
  const ciphers = [];
  for (const p of tricky) ciphers.push(await aesEncrypt(p, PASS));
  entries = mk(ciphers, true);
  for (const fmt of ['csv', 'json']) {
    const ex = await doExport(entries, fmt, 'enc', 'e-' + fmt);
    const recs = parseImport(ex.text);
    const back = [];
    for (const r of recs) {
      try { back.push(await aesDecrypt(r.password, PASS)); } catch (e) { back.push('<fail>'); }
    }
    out['enc_' + fmt] = {
      notEnc: recs.filter(r => !r.enc).length,
      mismatch: tricky.filter((p, i) => back[i] !== p).length
    };
  }

  /* 名称往返：JSON 是无损格式，'= 开头的名字不能被当成 Excel 前缀剥掉 */
  const oddNames = ["'=x", "''=x", "'+1", "'abc", '=x'];
  entries = oddNames.map((n, i) => ({
    id: 'n' + i, name: n, password: 'p', enc: false, batchId: '',
    createdAt: Date.now(), poolSize: 0, source: 'manual'
  }));
  for (const fmt of ['csv', 'json']) {
    const ex = await doExport(entries, fmt, 'plain', 'n-' + fmt);
    const got = parseImport(ex.text).map(r => r.name);
    out['name_' + fmt] = oddNames.filter((n, i) => got[i] !== n).length;
  }

  /* 导入分隔符：全角逗号（中文输入法最常见）与导入框占位示例里的半角/全角混排 */
  const fw = parseImport('邮箱主账号,kR7#vd2=Qm!4sT\\n公司 VPN，Xy9+_ab3Lp#Wz1');
  out.fwComma = fw.map(r => r.name + '｜' + r.password);
  /* 引号里的内容是中转格式原样写入的，全角字符不能被改成半角 */
  const quoted = parseImport('名称,密码\\na,"x，y＝z"');
  out.quotedKeep = quoted.length === 1 ? quoted[0].password : '<' + quoted.length + ' 条>';

  /* 存储只写白名单字段（内存明文不能落盘） */
  entries = mk(['x'], false);
  entries[0]._plain = 'should-not-persist';
  persist();
  renderList();
  const raw = JSON.parse(localStorage.getItem('pwd-vault-v1') || '[]');
  out.storedKeys = raw.length ? Object.keys(raw[0]).sort() : [];

  /* 键盘可达性：全选 / 导出格式 / 重绘后焦点 */
  const selAll = document.getElementById('selAll');
  selAll.focus();
  out.selAllFocusable = document.activeElement === selAll;

  document.getElementById('exportBtn').click();
  await new Promise(r => setTimeout(r, 50));
  out.focusInExportModal = document.getElementById('exportModal').contains(document.activeElement);
  closeExport();

  const btn = document.querySelector('#list .item button.mini[data-act="toggle"]');
  if (btn) {
    const id = btn.dataset.id;
    btn.focus();
    btn.click();
    await new Promise(r => setTimeout(r, 50));
    const ae = document.activeElement;
    out.focusKeptAfterRender = !!(ae && ae.classList.contains('mini') && ae.dataset.id === id);
  } else {
    out.focusKeptAfterRender = false;
  }

  /* 密钥弹窗：焦点不在输入框时 Esc 也要能关掉 */
  const pending = askPassword({ title: 'T', confirm: false });
  await new Promise(r => setTimeout(r, 80));
  const title = document.getElementById('unlockTitle');
  title.tabIndex = -1;
  title.focus();
  document.activeElement.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await new Promise(r => setTimeout(r, 60));
  out.unlockEscFromOutside = document.getElementById('unlockModal').hidden;
  if (!out.unlockEscFromOutside) document.getElementById('unlockCancel').click();
  await pending;

  /* 勾选状态必须在整表重绘后保持（选中项的底色与复选框不能丢） */
  entries = mk(['p1', 'p2'], false);
  selectedIds.clear();
  selectedIds.add(entries[0].id);
  renderList();
  const rows2 = listEl.querySelectorAll('.item');
  out.selectedKept = rows2.length === 2 &&
    rows2[0].classList.contains('selected') && !rows2[1].classList.contains('selected') &&
    rows2[0].querySelector('.item-check').checked === true &&
    rows2[1].querySelector('.item-check').checked === false;
  selectedIds.clear();

  /* 弹窗刚开就关：30ms 后的延迟聚焦不能落到隐藏元素上 */
  const quick = askPassword({ title: 'T2', confirm: false });
  await new Promise(r => setTimeout(r, 5));
  document.getElementById('unlockCancel').click();
  await new Promise(r => setTimeout(r, 80));
  await quick;
  const ae2 = document.activeElement;
  out.noFocusOnHidden = !(ae2 && ae2.offsetParent === null && ae2 !== document.body);
  return out;
})()`;

app.whenReady().then(() => {
  const tmpDir = path.join(os.tmpdir(), 'rkm-selfcheck-' + Date.now());
  fs.mkdirSync(tmpDir, { recursive: true });
  app.setPath('userData', tmpDir);

  staticChecks();

  const win = new BrowserWindow({
    show: false,
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true }
  });

  win.webContents.once('did-finish-load', async () => {
    let out = {};
    try {
      out = await win.webContents.executeJavaScript(PROBE, true);
    } catch (err) {
      check('页面脚本执行', false, (err && err.message) || String(err));
    }

    if (out && out.storedKeys) {
      check('明文往返（CSV）无字符丢失', out.plain_csv === 0, '不一致 ' + out.plain_csv + ' 条');
      check('明文往返（JSON）无字符丢失', out.plain_json === 0, '不一致 ' + out.plain_json + ' 条');
      check('密文往返（CSV）仍识别为加密', out.enc_csv.notEnc === 0, '未识别 ' + out.enc_csv.notEnc + ' 条');
      check('密文往返（CSV）可原样解回', out.enc_csv.mismatch === 0, '解不回 ' + out.enc_csv.mismatch + ' 条');
      check('密文往返（JSON）仍识别为加密', out.enc_json.notEnc === 0, '未识别 ' + out.enc_json.notEnc + ' 条');
      check('密文往返（JSON）可原样解回', out.enc_json.mismatch === 0, '解不回 ' + out.enc_json.mismatch + ' 条');
      check('名称往返（CSV）不被公式前缀吃掉字符', out.name_csv === 0, '不一致 ' + out.name_csv + ' 条');
      check('名称往返（JSON）不被公式前缀吃掉字符', out.name_json === 0, '不一致 ' + out.name_json + ' 条');
      check('全角逗号分隔的记录解析正确（导入框示例）',
        out.fwComma.length === 2 &&
        out.fwComma[0] === '邮箱主账号｜kR7#vd2=Qm!4sT' &&
        out.fwComma[1] === '公司 VPN｜Xy9+_ab3Lp#Wz1',
        JSON.stringify(out.fwComma));
      check('引号字段里的全角字符原样保留', out.quotedKeep === 'x，y＝z', String(out.quotedKeep));
      const expectKeys = ['batchId', 'createdAt', 'enc', 'id', 'name', 'password', 'poolSize', 'source'];
      check('本地存储只写白名单字段', JSON.stringify(out.storedKeys) === JSON.stringify(expectKeys),
        out.storedKeys.join(','));
      check('「全选」可被键盘聚焦', out.selAllFocusable === true);
      check('导出弹窗打开后焦点进入弹窗', out.focusInExportModal === true);
      check('列表重绘后焦点留在原控件', out.focusKeptAfterRender === true);
      check('密钥弹窗在任意焦点下都能 Esc 关闭', out.unlockEscFromOutside === true);
      check('勾选状态在整表重绘后保持', out.selectedKept === true);
      check('弹窗快速关闭后焦点不落在隐藏元素', out.noFocusOnHidden === true);
    }

    const failed = results.filter(r => !r.ok);
    for (const r of results) {
      console.log((r.ok ? '  ok   ' : '  FAIL ') + r.name + (r.ok || !r.detail ? '' : '  → ' + r.detail));
    }
    console.log(failed.length ? '\n自检失败：' + failed.length + ' 项' : '\n自检通过：' + results.length + ' 项');
    app.exit(failed.length ? 1 : 0);
  });

  win.loadFile(path.join(root, 'www', 'index.html'));
});

app.on('window-all-closed', () => app.quit());
setTimeout(() => { console.log('  FAIL 自检超时'); app.exit(2); }, 60000);
