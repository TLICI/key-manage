const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digit: '0123456789',
  symbol: '!@#$=+-_'
};
const AMBIGUOUS = '0Oo1lIi|`\'"\\';
const STORAGE_KEY = 'pwd-vault-v1';
const MIN_LEN = 15;
const MAX_LEN = 20;
// 版本号由 scripts/sync-version.js 从 package.json 注入，避免多处硬编码
const APP_VERSION = '2.0.7';
const IMPORT_MAX = 2000;      // 单次导入条数上限
const IMPORT_FILE_MAX = 8 * 1048576;   // 导入文件体积上限（超过基本是选错文件了）
const IMPORT_TEXT_MAX = 2 * 1048576;   // 解码后的文本长度上限
const NAME_MAX = 40;          // 名称长度上限（与输入框 maxlength 一致）
const PWD_MAX = 200;          // 单条密码长度上限
// 密文比明文长得多（v2 ≈ 明文 × 4/3 + 44，200 位明文的密文约 333 字符）。
// 按明文上限去截密文会把它切废，导入后再也解不开，所以密文单独给一个大上限。
const CIPHER_MAX = 4096;
const CLIP_CLEAR_MS = 45000;  // 复制后自动清空剪贴板
const PLAIN_HIDE_MS = 60000;  // 明文展示自动收起
const SEC_HINT_KEY = 'pwd-vault-v1-sec-hint-closed'; // 「明文存储」提示是否已关闭
const GEN_OPTS_KEY = 'pwd-vault-v1-gen-options';     // 生成选项（长度/字符集）

const $ = id => document.getElementById(id);
const lengthEl = $('length');
const lenText = $('lenText');
const passwordEl = $('password');
const errorEl = $('error');
const nameInput = $('keyName');
const listEl = $('list');
const emptyEl = $('empty');
const countEl = $('count');
const boxes = {
  lower: $('optLower'),
  upper: $('optUpper'),
  digit: $('optDigit'),
  symbol: $('optSymbol')
};
const exclusiveEl = $('optExclusive');
const searchInput = $('search');

let entries = [];
let storageOk = true;
let storageBroken = false;   // 本地存储里存在读不出来的旧数据
let backupFailed = false;    // 旧数据没能备份成功：此时禁止写入，避免覆盖原始内容
let storageToastAt = 0;
let currentPwd = '';
let currentPoolSize = 0;
let importReadToken = 0;
let hideTimer = null;
let clipTimer = null;
let pendingClipClear = null; // 复制后切走了窗口：回到前台再清剪贴板
let previewTimer = null;
let searchTimer = null;
let secHintClosed = false;   // 用户已关闭「明文存储」提示
const shownIds = new Set();
const focusStack = [];       // 弹窗打开前的焦点，关闭时按栈归还

// 加密状态：不保存任何加密密钥在内存里，每次查看/解密都要当场输入
let selectedIds = new Set();

/* ---------------- random数 ---------------- */

// 加密安全random整数 [0, max)
function randomInt(max) {
  if (max <= 0) return 0;
  // 2^32 个取值里只接受 limit 个（limit 是 max 的整数倍），保证取模无偏
  const limit = Math.floor(0x100000000 / max) * max;
  const buf = new Uint32Array(1);
  let v;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

function shuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function uid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

function activeSets() {
  return Object.keys(SETS).filter(k => boxes[k].checked);
}

function buildPool(key) {
  let chars = SETS[key];
  if (exclusiveEl.checked) {
    chars = [...chars].filter(c => !AMBIGUOUS.includes(c)).join('');
  }
  return chars;
}

function clampLength() {
  let length = parseInt(lengthEl.value, 10);
  if (isNaN(length)) length = 16;
  length = Math.min(MAX_LEN, Math.max(MIN_LEN, length));
  lengthEl.value = length;
  lenText.textContent = length;
  return length;
}

// 记住上次用的长度与字符集，省得每次启动都要重设一遍
function saveGenerateOptions() {
  try {
    localStorage.setItem(GEN_OPTS_KEY, JSON.stringify({
      length: parseInt(lengthEl.value, 10) || 16,
      lower: boxes.lower.checked,
      upper: boxes.upper.checked,
      digit: boxes.digit.checked,
      symbol: boxes.symbol.checked,
      exclusive: exclusiveEl.checked
    }));
  } catch (err) { /* 隐私模式忽略 */ }
}

function loadGenerateOptions() {
  let saved;
  try {
    saved = JSON.parse(localStorage.getItem(GEN_OPTS_KEY) || 'null');
  } catch (err) {
    return;
  }
  if (!saved || typeof saved !== 'object') return;
  const length = parseInt(saved.length, 10);
  if (length >= MIN_LEN && length <= MAX_LEN) {
    lengthEl.value = length;
    lenText.textContent = length;
  }
  ['lower', 'upper', 'digit', 'symbol'].forEach(k => {
    if (typeof saved[k] === 'boolean') boxes[k].checked = saved[k];
  });
  if (typeof saved.exclusive === 'boolean') exclusiveEl.checked = saved.exclusive;
  // 全都不勾会生成不出密码，回落成默认的四种字符集
  if (!activeSets().length) {
    ['lower', 'upper', 'digit', 'symbol'].forEach(k => { boxes[k].checked = true; });
  }
}

/* ---------------- 生成 ---------------- */

function generate() {
  errorEl.textContent = '';
  const length = clampLength();
  const keys = activeSets().map(k => ({ key: k, pool: buildPool(k) })).filter(o => o.pool.length > 0);

  if (keys.length === 0) {
    showError('请至少勾选一种字符集');
    return;
  }
  if (length < keys.length) {
    showError('密码长度不能小于已选字符集数量（' + keys.length + '）');
    return;
  }

  // 每个已选字符集至少出现一次
  const chars = keys.map(o => o.pool[randomInt(o.pool.length)]);
  const all = keys.map(o => o.pool).join('');
  while (chars.length < length) chars.push(all[randomInt(all.length)]);

  const pwd = shuffle(chars).join('');
  currentPwd = pwd;
  currentPoolSize = all.length;
  passwordEl.textContent = pwd;
  passwordEl.classList.remove('placeholder');
  updateStrength(pwd, all.length);

  // 填了名称就自动归档；名称统一走 normalizeName，避免多余空格/超长
  const name = normalizeName(nameInput.value);
  if (name) {
    const dup = findByName(name);
    // meta 需要对象：直接传数字会让 poolSize 落成 undefined -> 0
    addEntry(name, pwd, { poolSize: all.length });
    nameInput.value = '';
    nameInput.blur();
    showToast(dup ? '已另存为新记录（同名「' + dup.name + '」已存在）' : '已保存到密钥列表：' + name);
  }
}

// 保存当前（未命名）密码
function saveCurrent() {
  if (!currentPwd) {
    showToast('请先生成一条密码');
    return;
  }
  const name = normalizeName(nameInput.value) || nextAutoName();
  // 与「手动记录」一致：同名先确认，避免连点保存堆出一串同名记录
  const dup = findByName(name);
  if (dup && !confirm('已存在同名记录「' + dup.name + '」，仍要再保存一条吗？')) {
    nameInput.focus();
    return;
  }
  addEntry(name, currentPwd, { poolSize: currentPoolSize });
  nameInput.value = '';
  showToast('已保存到密钥列表：' + name);
}

function updateStrength(pwd, poolSize) {
  const entropy = pwd.length * Math.log2(poolSize || 1);
  const bars = document.querySelectorAll('.bars i');
  let level, label, color;
  if (entropy < 40) { level = 1; label = '很弱'; color = '#ff6b6b'; }
  else if (entropy < 60) { level = 2; label = '较弱'; color = '#ffa94d'; }
  else if (entropy < 90) { level = 3; label = '中等'; color = '#ffd43b'; }
  else if (entropy < 128) { level = 4; label = '强'; color = '#33d69f'; }
  else { level = 4; label = '非常强'; color = '#33d69f'; }
  bars.forEach((b, i) => { b.style.background = i < level ? color : '#2a2f3c'; });
  $('strengthText').textContent = label + ' · ' + Math.round(entropy) + ' bit';
  $('strengthText').style.color = color;
}

function showError(msg) {
  errorEl.textContent = msg;
  currentPwd = '';
  passwordEl.textContent = msg;
  passwordEl.classList.add('placeholder');
  document.querySelectorAll('.bars i').forEach(b => { b.style.background = '#2a2f3c'; });
  $('strengthText').textContent = '—';
  $('strengthText').style.color = 'var(--muted)';
}

/* ---------------- AES 加密 ---------------- */

const MASTER_MIN = 8;   // 新建密钥时的最短长度：1 位密钥的 60 万次 PBKDF2 没有实际防护力
const MASTER_MAX = 20;
const PBKDF2_ITERATIONS = 600000;
const enc = new TextEncoder();
const dec = new TextDecoder();

// 同一密钥+盐只派生一次：批量解密时 600k 次 PBKDF2 只跑一遍
const keyCache = new Map();

function rememberKey(id, key) {
  if (keyCache.size >= 32) keyCache.delete(keyCache.keys().next().value);
  keyCache.set(id, key);
}

function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function unb64(str) {
  const s = atob(str);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

// 新密文使用 PBKDF2-SHA-256；v1 仅用于兼容历史密文。
async function deriveAesKey(pass, salt, iterations, usage) {
  const material = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iterations },
    material, { name: 'AES-GCM', length: 256 }, false, [usage]
  );
}

// 同一批次共用一个随机盐和一把派生好的密钥，整批加密只算一次 PBKDF2
async function makeEncryptor(pass) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto，无法加密');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = b64(salt);
  const key = await deriveAesKey(pass, salt, PBKDF2_ITERATIONS, 'encrypt');
  return async text => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(text));
    return 'v2:' + saltB64 + ':' + b64(iv) + ':' + b64(ct);
  };
}

async function aesEncrypt(text, pass) {
  return (await makeEncryptor(pass))(text);
}

// 中转（Excel / 聊天软件 / JSON 序列化）常给密文套上引号或空格。
// 两端都必须去掉：只剥开头会留下尾部引号，密文仍然通过 v1:/v2: 判断，却一定解不开。
function repairCipherText(value) {
  const raw = String(value);
  const trimmed = raw.replace(/^[\s"'`]+/, '').replace(/[\s"'`]+$/, '');
  return /^v[12]:/.test(trimmed) ? trimmed : raw;
}

// 导入时的长度收敛：密文不能按明文上限截断，否则会切坏密文且毫无提示
function clampPassword(value, cipherLike) {
  const s = String(value == null ? '' : value);
  const limit = cipherLike ? CIPHER_MAX : PWD_MAX;
  return s.length > limit ? s.slice(0, limit) : s;
}

// 取密文里的盐（v2 的第 2 段）；v1 用 pass 的 SHA-256，所有条目共用一把密钥
function cipherSalt(payload) {
  if (typeof payload !== 'string') return '';
  const parts = payload.split(':');
  if (parts[0] === 'v2' && parts.length === 4) return parts[1];
  return 'v1';
}

async function aesDecrypt(payload, pass) {
  if (!window.crypto || !crypto.subtle) throw new Error('当前环境不支持 Web Crypto，无法解密');
  if (typeof payload !== 'string') throw new Error('密文格式不正确');
  const parts = payload.split(':');
  if (parts[0] === 'v1' && parts.length === 3) {
    const digest = await crypto.subtle.digest('SHA-256', enc.encode(pass));
    const key = await crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, ['decrypt']);
    return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(parts[1]) }, key, unb64(parts[2])));
  }
  if (parts[0] === 'v2' && parts.length === 4) {
    const cacheId = pass + '|' + parts[1];
    let key = keyCache.get(cacheId);
    if (!key) {
      key = await deriveAesKey(pass, unb64(parts[1]), PBKDF2_ITERATIONS, 'decrypt');
      rememberKey(cacheId, key);
    }
    return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(parts[2]) }, key, unb64(parts[3])));
  }
  throw new Error('密文格式不正确');
}

/* ---------------- 存储 ---------------- */

function normalizeEntry(e) {
  // 历史数据里的密文可能被引号或空格污染（CSV/聊天软件中转时常见），先修复再判断
  const password = typeof e.password === 'string' ? repairCipherText(e.password) : '';
  const encrypted = e.enc === true || e.enc === 'true' || /^v[12]:/.test(password);
  return {
    id: e.id || uid(),
    // 历史数据里的名称可能是旧版本写入的（多空格/超长），读入时一并整理
    name: normalizeName(e.name),
    password: password,
    enc: encrypted,
    // 同一批次加密的条目标记相同 batchId，导出时只需输入一次密钥
    batchId: encrypted && typeof e.batchId === 'string' ? e.batchId : '',
    createdAt: Number(e.createdAt) || Date.now(),
    poolSize: Number(e.poolSize) || 0,
    source: e.source === 'manual' || e.source === 'imported' ? e.source : 'generated'
  };
}

// 兜底修复：enc 标记丢失时，只要密码字段本身就是 v1:/v2: 密文，就按加密条目处理，
// 避免把密文当成明文密钥复制出去
function healEnc(entry) {
  if (!entry || entry.enc) return false;
  const raw = typeof entry.password === 'string' ? entry.password : '';
  if (!/^v[12]:/.test(raw.replace(/^[\s"'`]+/, ''))) return false;
  entry.password = repairCipherText(raw);
  entry.enc = true;
  if (typeof entry.batchId !== 'string') entry.batchId = '';
  return true;
}

let legacyPlainFound = false;

// 存储里有读不出来的旧数据时，先原样备份一份，避免随后的 persist 把它彻底覆盖
function backupBrokenRaw(raw) {
  storageBroken = true;
  if (!raw) return;
  try {
    localStorage.setItem(STORAGE_KEY + '-broken-' + Date.now(), raw);
  } catch (err) {
    // 配额/权限问题：备份失败时绝不能再写，否则原始数据会被空列表直接覆盖
    backupFailed = true;
  }
}

function loadEntries() {
  let raw = null;
  try {
    raw = localStorage.getItem(STORAGE_KEY);
  } catch (err) {
    storageOk = false;
    return [];
  }
  if (!raw) return [];
  try {
    const data = JSON.parse(raw);
    if (!Array.isArray(data)) throw new Error('存储内容不是数组');
    // 旧版本会把内存里的明文（_plain）一起写进本地存储，读入时标记一次，随后重写干净
    if (data.some(e => e && Object.prototype.hasOwnProperty.call(e, '_plain'))) legacyPlainFound = true;
    return data.filter(e => e && typeof e.name === 'string' && typeof e.password === 'string')
      .map(normalizeEntry);
  } catch (err) {
    backupBrokenRaw(raw);
    return [];
  }
}

// 只持久化需要长期保存的字段：内存中的明文（_plain）绝不能落盘
const STORED_FIELDS = ['id', 'name', 'password', 'enc', 'batchId', 'createdAt', 'poolSize', 'source'];

function toStored(entry) {
  const out = {};
  for (const key of STORED_FIELDS) {
    if (entry[key] !== undefined) out[key] = entry[key];
  }
  return out;
}

// 存储状态常驻提示：写失败/旧数据损坏时不再只靠一闪而过的 toast
function updateStorageWarn() {
  const el = $('storageWarn');
  if (!el) return;
  const msgs = [];
  if (!storageOk) msgs.push('本地保存失败：本次改动只在当前页面有效，关闭后会丢失。');
  if (backupFailed) msgs.push('发现无法解析的旧数据，且自动备份失败（存储空间可能已满）。为避免覆盖原始内容，保存已暂停，请清理存储空间后重新打开。');
  else if (storageBroken) msgs.push('发现无法解析的旧数据，已原样备份到 ' + STORAGE_KEY + '-broken-… 里，当前列表从空开始。');
  el.textContent = msgs.join(' ');
  el.hidden = msgs.length === 0;
}

// 明文存储提示：还有未加密的条目时常驻显示（可手动关闭，记在本地）
function updateSecHint() {
  const el = $('secHint');
  if (!el) return;
  const plain = entries.filter(e => !e.enc).length;
  el.hidden = secHintClosed || !plain;
}

function persist() {
  // 原始数据没能备份成功时，任何写入都会把它彻底覆盖掉，这里直接拒绝
  if (backupFailed) {
    storageOk = false;
    updateStorageWarn();
    return;
  }
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries.map(toStored)));
    storageOk = true;
  } catch (err) {
    storageOk = false;
    const now = Date.now();
    if (now - storageToastAt > 8000) {
      storageToastAt = now;
      showToast('本地保存失败：数据仅在当前页面有效');
    }
  }
  updateStorageWarn();
}

// 名称统一整理：折叠空白、去首尾空格、限长；比较重名时忽略大小写与多余空格
function normalizeName(name) {
  return String(name || '').replace(/\s+/g, ' ').trim().slice(0, NAME_MAX);
}

function nameKey(name) {
  return normalizeName(name).toLowerCase();
}

function findByName(name) {
  const key = nameKey(name);
  if (!key) return null;
  return entries.find(e => nameKey(e.name) === key) || null;
}

function nextAutoName() {
  const used = new Set(entries.map(e => nameKey(e.name)));
  let n = 1;
  while (used.has(nameKey('密钥 ' + n))) n++;
  return '密钥 ' + n;
}

function addEntry(name, password, meta) {
  meta = meta || {};
  entries.unshift({
    id: uid(),
    name: normalizeName(name) || nextAutoName(),
    password: password,
    enc: false,
    batchId: '',
    createdAt: meta.createdAt || Date.now(),
    poolSize: meta.poolSize || 0,
    source: meta.source || 'generated'
  });
  persist();
  renderList();
  return entries[0];
}

/* ---------------- 渲染列表 ---------------- */

function fmtTime(ts) {
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  const md = p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  // 跨年的记录补上年份，免得历史数据看起来像今年的
  return d.getFullYear() === new Date().getFullYear() ? md : d.getFullYear() + '-' + md;
}

function fmtTimeFull(ts) {
  const d = new Date(ts);
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' +
    p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds());
}

function maskPwd(pwd) {
  return '•'.repeat(pwd.length);
}

// 搜索覆盖名称、来源、时间与加密状态；只看元信息，不碰密文内容
function matchesQuery(entry, q) {
  if (!q) return true;
  const hay = [
    entry.name,
    SOURCE_LABEL[entry.source] || '',
    fmtTime(entry.createdAt),
    fmtTimeFull(entry.createdAt),
    entry.enc ? '加密 密文 aes 需要密钥' : '明文 未加密'
  ].join(' ').toLowerCase();
  return q.split(/\s+/).filter(Boolean).every(token => hay.includes(token));
}

// 整表重绘会把节点全部换掉，键盘焦点会掉回 body：先记下焦点落在哪条记录的哪个控件上
function focusKeyOf(el) {
  if (!el || !el.dataset || !listEl.contains(el)) return null;
  const id = el.dataset.id || '';
  if (!id) return null;
  if (el.classList.contains('item-check')) return 'check|' + id;
  if (el.classList.contains('item-pwd')) return 'pwd|' + id;
  if (el.classList.contains('item-name')) return 'name|' + id;
  if (el.classList.contains('mini')) return 'mini|' + el.dataset.act + '|' + id;
  return null;
}

function findFocusTarget(key) {
  const parts = key.split('|');
  const kind = parts[0];
  const id = parts[parts.length - 1];
  const safe = (window.CSS && CSS.escape) ? CSS.escape(id) : id.replace(/"/g, '\\"');
  if (kind === 'check') return listEl.querySelector('.item-check[data-id="' + safe + '"]');
  if (kind === 'pwd') return listEl.querySelector('.item-pwd[data-id="' + safe + '"]');
  if (kind === 'name') return listEl.querySelector('.item-name[data-id="' + safe + '"]');
  if (kind === 'mini') {
    return listEl.querySelector('button.mini[data-act="' + parts[1] + '"][data-id="' + safe + '"]');
  }
  return null;
}

// 勾选状态变化只改这一小块界面，不整表重绘：2000 条时重绘一次要 300ms 以上
function updateSelectionUI() {
  listEl.querySelectorAll('.item-check').forEach(check => {
    const on = selectedIds.has(check.dataset.id);
    check.checked = on;
    const item = check.closest('.item');
    if (item) item.classList.toggle('selected', on);
  });
  const q = searchInput.value.trim().toLowerCase();
  const visible = q ? entries.filter(e => matchesQuery(e, q)) : entries;
  const encCount = entries.filter(e => e.enc).length;
  $('encStat').textContent = encCount ? '已加密 ' + encCount + '/' + entries.length : '';
  $('selCount').textContent = selectedIds.size ? '已选 ' + selectedIds.size + ' 项' : '未选择';
  const selAll = $('selAll');
  selAll.checked = visible.length > 0 && visible.every(e => selectedIds.has(e.id));
  // 搜索时「全选」只覆盖筛选结果，标题里说清楚，免得以为把整库都选中了
  selAll.title = q
    ? '全选当前搜索到的 ' + visible.length + ' 条（不含被筛掉的 ' + (entries.length - visible.length) + ' 条）'
    : '全选全部 ' + entries.length + ' 条';
  $('btnEncryptSel').disabled = selectedIds.size === 0;
  $('btnDecryptSel').disabled = !entries.some(e => e.enc && selectedIds.has(e.id));
  $('btnExportSel').disabled = selectedIds.size === 0;
  $('btnClearSel').disabled = selectedIds.size === 0;
}

function renderList() {
  // 记住滚动位置：勾选 / 加解密 / 重命名都会整表重绘，长列表不能每次跳回顶部
  const keepScroll = listEl.scrollTop;
  const keepFocus = focusKeyOf(document.activeElement);
  listEl.textContent = '';
  // 渲染前修复历史条目里丢失的加密标记，避免把密文当明文展示/复制
  let healed = false;
  entries.forEach(e => { if (healEnc(e)) healed = true; });
  if (healed) persist();
  updateStorageWarn();
  updateSecHint();
  const q = searchInput.value.trim().toLowerCase();
  const visible = q ? entries.filter(e => matchesQuery(e, q)) : entries;

  // 搜索时同时给出「命中 / 总数」，避免把筛选结果误当成全部
  countEl.textContent = visible.length === entries.length
    ? String(entries.length)
    : visible.length + '/' + entries.length;
  emptyEl.style.display = visible.length ? 'none' : 'block';
  emptyEl.textContent = entries.length
    ? '没有匹配「' + searchInput.value.trim() + '」的密钥。'
    : '还没有保存的密钥。生成时填写名称、手动记录或批量导入，都会出现在这里。';
  $('clearAll').disabled = entries.length === 0;

  // 清理已不存在的选中项
  const allIds = new Set(entries.map(e => e.id));
  [...selectedIds].forEach(id => { if (!allIds.has(id)) selectedIds.delete(id); });

  // 选中态与统计统一由 updateSelectionUI 负责（此时列表已清空，它只更新计数与按钮）
  updateSelectionUI();

  visible.forEach(entry => {
    const item = document.createElement('div');
    item.className = 'item' + (selectedIds.has(entry.id) ? ' selected' : '');

    const check = document.createElement('input');
    check.type = 'checkbox';
    check.className = 'item-check';
    check.checked = selectedIds.has(entry.id);
    check.dataset.id = entry.id;
    check.title = '选择这条密钥';

    const main = document.createElement('div');
    main.className = 'item-main';

    const row = document.createElement('div');
    row.className = 'item-row';

    const name = document.createElement('span');
    name.className = 'item-name';
    name.textContent = entry.name;
    name.title = '点击可重命名（键盘：Enter / F2）';
    name.dataset.id = entry.id;
    // 键盘可达：Tab 能聚焦，Enter / F2 进入重命名
    name.tabIndex = 0;
    name.setAttribute('role', 'button');
    name.setAttribute('aria-label', '重命名「' + entry.name + '」');

    const badges = document.createElement('span');
    badges.className = 'item-badges';
    const time = document.createElement('span');
    time.className = 'item-time' + (entry.source === 'generated' ? '' : ' custom');
    time.textContent = fmtTime(entry.createdAt);
    time.title = (entry.source === 'generated' ? '由本程序生成' : (entry.source === 'imported' ? '导入的记录' : '手动记录')) +
      ' · ' + fmtTimeFull(entry.createdAt);
    badges.appendChild(time);
    if (entry.enc) {
      const lock = document.createElement('span');
      lock.className = 'item-lock';
      lock.textContent = 'AES 加密';
      lock.title = '查看明文需要输入加密密钥';
      badges.appendChild(lock);
    }

    row.appendChild(name);
    row.appendChild(badges);

    const pwd = document.createElement('div');
    pwd.className = 'item-pwd';
    pwd.dataset.id = entry.id;
    pwd.title = entry.enc ? '点击输入加密密钥查看明文（键盘：Enter）' : '点击复制（键盘：Enter）';
    pwd.textContent = shownIds.has(entry.id)
      ? (entry._plain || entry.password)
      : (entry.enc ? '🔒 ' + '•'.repeat(12) : maskPwd(entry.password));
    // 与名称一致：能点就能用键盘触发，否则键盘用户完全够不到密码区
    pwd.tabIndex = 0;
    pwd.setAttribute('role', 'button');
    pwd.setAttribute('aria-label', entry.enc ? '显示或复制「' + entry.name + '」' : '复制「' + entry.name + '」');

    main.appendChild(row);
    main.appendChild(pwd);

    const btns = document.createElement('div');
    btns.className = 'item-btns';
    btns.appendChild(miniBtn(shownIds.has(entry.id) ? '隐藏' : '显示', 'toggle', entry));
    btns.appendChild(miniBtn('复制', 'copy', entry));
    // 明文未锁 → 显示「加密」；已加密（锁定）→ 显示「解密」
    btns.appendChild(miniBtn(entry.enc ? '解密' : '加密', 'enc', entry));
    const delBtn = miniBtn('删除', 'del', entry);
    delBtn.classList.add('del');
    btns.appendChild(delBtn);

    item.appendChild(check);
    item.appendChild(main);
    item.appendChild(btns);
    listEl.appendChild(item);
  });
  // 内容恢复后再写回，否则空列表会把 scrollTop 夹成 0
  listEl.scrollTop = keepScroll;
  // 焦点归还原处：否则用键盘点一次「显示」，焦点就跳回页面顶部了
  if (keepFocus) {
    const again = findFocusTarget(keepFocus);
    if (again) again.focus();
  }
}

// 直接收条目对象：早先按 id 回查 entries，每行 4 个按钮就是 4 次全表扫描，
// 2000 条时单次重绘要多花几百毫秒
function miniBtn(text, act, entry) {
  const b = document.createElement('button');
  b.className = 'mini';
  b.textContent = text;
  b.dataset.act = act.startsWith('del') ? 'del' : act;
  b.dataset.id = entry.id;
  // 一排按钮都叫「显示/复制/删除」，屏幕阅读器读出来分不清是哪一条
  b.setAttribute('aria-label', text + '「' + entry.name + '」');
  return b;
}

/* ---------------- 交互 ---------------- */

// 复制到剪贴板：只有真的成功才提示；成功后安排一次自动清空
// keep = true 时不清空（导出结果就是给用户去粘贴的，清掉反而添乱）
async function copyText(text, tip, keep) {
  if (!text) return false;
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (err) {
    ok = legacyCopy(text);
  }
  if (!ok) {
    showToast('复制失败，请手动选中文本复制');
    return false;
  }
  showToast(tip || '已复制到剪贴板');
  if (!keep) scheduleClipboardClear(text);
  return true;
}

function legacyCopy(text) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch (err) {
    return false;
  }
}

// 45 秒后清空剪贴板；只清「还是本次复制的那段内容」的情况，避免误清用户后来的复制
function scheduleClipboardClear(text) {
  clearTimeout(clipTimer);
  // 又复制了新内容：之前挂着的「回前台补清」已经过时，留着会误清刚复制的这段
  pendingClipClear = null;
  clipTimer = setTimeout(() => tryClearClipboard(text), CLIP_CLEAR_MS);
}

// 页面不在前台时 readText 基本会被拒绝，先记下来，等回到前台再清
async function tryClearClipboard(target) {
  clipTimer = null;
  if (document.visibilityState !== 'visible' || !document.hasFocus()) {
    pendingClipClear = target;
    return;
  }
  let current = null;
  let readable = false;
  try {
    current = await navigator.clipboard.readText();
    readable = true;
  } catch (err) {
    readable = false;
  }
  if (readable && current !== target) return; // 用户后来复制了别的内容，绝不能误清
  if (!readable) {
    // 没有读取权限：此时页面仍在最前，说明用户没去别处复制，直接覆盖即可
    if (document.visibilityState !== 'visible' || !document.hasFocus()) {
      pendingClipClear = target;
      return;
    }
  }
  try {
    await navigator.clipboard.writeText('');
    pendingClipClear = null;
    showToast('剪贴板已自动清空');
  } catch (err) {
    pendingClipClear = null;
  }
}

// 提示按队列依次播放：启动时可能同时有「存储不可用 / 旧数据损坏 / 已加密 N 条」多条，
// 直接覆盖会让前面的关键警告根本看不到
const TOAST_MS = 1600;
let toastQueue = [];
let toastTimer = null;

function showToast(msg) {
  if (!msg) return;
  // 连续触发同一条（比如连点复制）不重复排队
  if (toastQueue[toastQueue.length - 1] !== msg) toastQueue.push(msg);
  if (toastQueue.length > 3) toastQueue.splice(0, toastQueue.length - 3);
  if (!toastTimer) playToast();
}

function playToast() {
  const toast = $('toast');
  const msg = toastQueue.shift();
  if (!msg) {
    toastTimer = null;
    toast.classList.remove('show');
    return;
  }
  toast.textContent = msg;
  toast.classList.add('show');
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
    // 留一点间隔，避免两条消息连成一片
    toastTimer = setTimeout(playToast, 180);
  }, TOAST_MS);
}

// 弹窗输入加密密钥，并用它解开指定密文；成功返回 {pass, plain}，取消/错误返回 null
async function askPlain(cipher, opts) {
  let plain = null;
  const res = await askPassword({
    title: opts.title,
    tip: opts.tip || '每次查看都需要输入加密密钥，密钥不会保存在任何地方。',
    check: async pass => {
      try {
        // 校验时顺手把明文留下，避免确认后再跑一次 PBKDF2
        plain = await aesDecrypt(cipher, pass);
        return '';
      } catch (err) {
        plain = null;
        return '加密密钥不正确';
      }
    }
  });
  if (!res) return null;
  if (plain === null) {
    try {
      plain = await aesDecrypt(cipher, res.pass);
    } catch (err) {
      showToast('解密失败：加密密钥不正确');
      return null;
    }
  }
  return { pass: res.pass, plain: plain };
}

// 明文展示 60 秒后自动收起；切走窗口时立即收起
function scheduleHide() {
  clearTimeout(hideTimer);
  hideTimer = setTimeout(() => hideAllPlain(), PLAIN_HIDE_MS);
}

function hideAllPlain() {
  clearTimeout(hideTimer);
  hideTimer = null;
  // 正在重命名就先提交（blur 会走 finish），否则随后的 renderList 会把刚输入的内容抹掉
  const active = document.activeElement;
  if (active && active.classList && active.classList.contains('item-name')) active.blur();
  if (!shownIds.size && !keyCache.size) return;
  shownIds.forEach(id => {
    const e = entries.find(x => x.id === id);
    if (e) delete e._plain;
  });
  shownIds.clear();
  keyCache.clear();
  renderList();
}

// 显示明文：明文条目直接展示；加密条目才要求输入加密密钥
async function showPlain(entry) {
  if (healEnc(entry)) persist();
  if (!entry.enc) {
    entry._plain = entry.password;
    shownIds.add(entry.id);
    scheduleHide();
    renderList();
    return true;
  }
  const res = await askPlain(entry.password, {
    title: '查看「' + entry.name + '」',
    tip: '输入这条密钥的加密密钥，验证通过后临时显示明文；点「隐藏」、切换窗口或 ' + Math.round(PLAIN_HIDE_MS / 1000) + ' 秒后自动清除。'
  });
  if (!res) return false;
  entry._plain = res.plain;
  shownIds.add(entry.id);
  scheduleHide();
  renderList();
  return true;
}

// 切换显示/隐藏明文
async function toggleShow(entry) {
  if (shownIds.has(entry.id)) {
    shownIds.delete(entry.id);
    delete entry._plain;
    renderList();
    return;
  }
  await showPlain(entry);
}

// 点密码区（鼠标或键盘）：明文条目直接复制，加密条目先展开
async function activatePwd(entry) {
  if (entry.enc) await toggleShow(entry);
  else await copyText(entry.password, '已复制「' + entry.name + '」');
}

// 复制密码：加密条目每次都要求输入密钥
async function copyEntryPassword(entry) {
  if (healEnc(entry)) persist();
  if (!entry.enc) {
    await copyText(entry.password, '已复制「' + entry.name + '」');
    return;
  }
  if (entry._plain && shownIds.has(entry.id)) {
    await copyText(entry._plain, '已复制「' + entry.name + '」');
    return;
  }
  const res = await askPlain(entry.password, {
    title: '复制「' + entry.name + '」',
    tip: '输入加密密钥验证后复制到剪贴板；密钥不会被记住。'
  });
  if (!res) return;
  await copyText(res.plain, '已复制「' + entry.name + '」');
}

listEl.addEventListener('click', async e => {
  const btn = e.target.closest('button.mini');
  if (btn) {
    const entry = entries.find(x => x.id === btn.dataset.id);
    if (!entry) return;
    const act = btn.dataset.act;
    if (act === 'toggle') {
      await toggleShow(entry);
    } else if (act === 'copy') {
      await copyEntryPassword(entry);
    } else if (act === 'enc') {
      if (entry.enc) await decryptOne(entry);
      else await encryptOne(entry);
    } else if (act === 'del') {
      if (!confirm('删除密钥「' + entry.name + '」？')) return;
      entries = entries.filter(x => x.id !== entry.id);
      shownIds.delete(entry.id);
      selectedIds.delete(entry.id);
      persist();
      renderList();
      showToast('已删除');
    }
    return;
  }

  const check = e.target.closest('.item-check');
  if (check) {
    if (check.checked) selectedIds.add(check.dataset.id);
    else selectedIds.delete(check.dataset.id);
    updateSelectionUI();
    return;
  }

  const pwd = e.target.closest('.item-pwd');
  if (pwd) {
    const entry = entries.find(x => x.id === pwd.dataset.id);
    if (entry) await activatePwd(entry);
    return;
  }

  const nameEl = e.target.closest('.item-name');
  if (nameEl && nameEl.getAttribute('contenteditable') !== 'true') startRename(nameEl);
});

listEl.addEventListener('keydown', async e => {
  if (e.key !== 'Enter' && e.key !== 'F2' && e.key !== ' ') return;

  // 密码区：Enter / 空格等同于点击（复制或展开）
  const pwdEl = e.target.closest('.item-pwd');
  if (pwdEl) {
    e.preventDefault();
    const entry = entries.find(x => x.id === pwdEl.dataset.id);
    if (entry) await activatePwd(entry);
    return;
  }

  // 名称：Enter / F2 / 空格进入重命名
  const nameEl = e.target.closest('.item-name');
  if (!nameEl || nameEl.getAttribute('contenteditable') === 'true') return;
  e.preventDefault();
  startRename(nameEl);
});

function startRename(nameEl) {
  const id = nameEl.dataset.id;
  const entry = entries.find(x => x.id === id);
  if (!entry) return;
  const old = entry.name;

  nameEl.setAttribute('contenteditable', 'true');
  nameEl.focus();
  const range = document.createRange();
  range.selectNodeContents(nameEl);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);

  const finish = commit => {
    nameEl.removeAttribute('contenteditable');
    nameEl.removeEventListener('blur', onBlur);
    nameEl.removeEventListener('keydown', onKey);
    if (!commit) { nameEl.textContent = old; return; }
    const val = normalizeName(nameEl.textContent);
    if (!val) { nameEl.textContent = old; return; }
    const dup = entries.find(e => e.id !== id && nameKey(e.name) === nameKey(val));
    if (dup) {
      nameEl.textContent = old;
      showToast('已存在同名密钥「' + dup.name + '」');
      return;
    }
    entry.name = val;
    nameEl.textContent = val;
    nameEl.setAttribute('aria-label', '重命名「' + val + '」');
    persist();
  };
  const onBlur = () => finish(true);
  const onKey = ev => {
    // 必须阻止冒泡：提交后 contenteditable 已移除，事件继续上传会触发列表的
    // 「Enter 进入重命名」，刚改完的名字会立刻又进入编辑态
    if (ev.key === 'Enter') { ev.preventDefault(); ev.stopPropagation(); finish(true); }
    else if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); finish(false); }
  };

  nameEl.addEventListener('blur', onBlur);
  nameEl.addEventListener('keydown', onKey);
}

/* ---------------- 加密操作 ---------------- */

// 弹窗焦点管理：打开前记录、关闭后按栈归还，键盘用户不会掉回页面顶部
function rememberFocus() {
  focusStack.push(document.activeElement);
}

function restoreFocus() {
  const el = focusStack.pop();
  if (el && typeof el.focus === 'function' && document.contains(el)) el.focus();
}

// 当前最上层的可见弹窗（密钥弹窗层级最高，排在最前）
function topModal() {
  return ['unlockModal', 'textModal', 'importModal', 'exportModal']
    .map(id => $(id))
    .find(el => el && !el.hidden) || null;
}

// 安卓实体返回键：由 MainActivity 调用。
// 返回 true 表示「这次返回被页面消费掉了」，false 才让系统退出应用。
// 没有这个钩子时，导入框里粘了一半的内容会随进程一起消失。
window.__handleBack = () => {
  if (!$('unlockModal').hidden) { $('unlockCancel').click(); return true; }
  if (!$('textModal').hidden) { closeTextExport(); return true; }
  if (!$('importModal').hidden) {
    // 关闭确认里选「取消」时弹窗仍在，也算消费掉这次返回，不能顺手退出应用
    closeImport();
    return true;
  }
  if (!$('exportModal').hidden) { closeExport(); return true; }
  return false;
};

function askPassword(opts) {
  const modal = $('unlockModal');
  rememberFocus();
  modal.hidden = false;
  $('unlockTitle').textContent = opts.title || '输入加密密钥';
  $('unlockTip').textContent = opts.tip || '用于 AES 加密 / 解密，关闭页面后需重新输入。';
  const input = $('unlockInput');
  const input2 = $('unlockInput2');
  const confirmRow = $('unlockConfirmRow');
  input.value = '';
  input.maxLength = MASTER_MAX;
  input2.value = '';
  input2.maxLength = MASTER_MAX;
  confirmRow.hidden = !opts.confirm;
  $('unlockError').textContent = '';
  // 延迟聚焦是为了等 hidden 生效；期间弹窗可能已经关掉，那就不能再抢焦点
  let focusTimer = setTimeout(() => {
    focusTimer = null;
    if (!modal.hidden) input.focus();
  }, 30);

  return new Promise(resolve => {
    let closed = false;
    let busy = false;
    const setBusy = on => {
      busy = on;
      const okBtn = $('unlockOk');
      okBtn.disabled = on;
      okBtn.textContent = on ? '校验中…' : '确定';
      $('unlockCancel').disabled = on;
      $('unlockClose').disabled = on;
    };
    const cleanup = () => {
      if (focusTimer) { clearTimeout(focusTimer); focusTimer = null; }
      $('unlockOk').removeEventListener('click', ok);
      $('unlockCancel').removeEventListener('click', cancel);
      $('unlockClose').removeEventListener('click', cancel);
      modal.removeEventListener('keydown', onKey);
      modal.removeEventListener('click', onBackdrop);
      modal.hidden = true;
      input.value = '';
      input2.value = '';
      setBusy(false);
      restoreFocus();
    };
    const close = val => {
      if (closed) return;
      closed = true;
      cleanup();
      resolve(val);
    };
    const submit = () => {
      const val = input.value;
      if (!val) { $('unlockError').textContent = '请输入加密密钥'; input.focus(); return; }
      if (val.length > MASTER_MAX) { $('unlockError').textContent = '最多 ' + MASTER_MAX + ' 个字符'; input.focus(); return; }
      // 只对「新建密钥」强制下限：老数据可能用的更短密钥，解锁时不能拦
      if (opts.confirm && val.length < MASTER_MIN) {
        $('unlockError').textContent = '加密密钥至少 ' + MASTER_MIN + ' 个字符';
        input.focus();
        return;
      }
      if (opts.confirm && input2.value !== val) {
        $('unlockError').textContent = '两次输入的密钥不一致';
        input2.focus();
        return;
      }
      close({ pass: val });
    };
    const ok = () => {
      if (closed || busy) return;
      if (opts.check && input.value) {
        // PBKDF2 要几百毫秒，期间锁住按钮避免重复提交
        setBusy(true);
        $('unlockError').textContent = '';
        Promise.resolve()
          .then(() => opts.check(input.value))
          .then(err => {
            setBusy(false);
            if (closed) return;
            if (err) { $('unlockError').textContent = err; input.focus(); return; }
            submit();
          })
          .catch(() => {
            setBusy(false);
            if (!closed) $('unlockError').textContent = '校验失败，请重试';
          });
        return;
      }
      submit();
    };
    const cancel = () => close(null);
    // 挂在弹窗而不是两个输入框上：焦点落到别处（点到标题、按过空白）时 Esc 也要能关，
    // 否则这个弹窗只能靠鼠标点「取消」退出
    const onKey = ev => {
      if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); cancel(); return; }
      if (ev.key !== 'Enter') return;
      // 焦点在按钮上时让按钮自己响应，不然「取消」按钮按回车会变成「确定」
      if (ev.target && ev.target.tagName === 'BUTTON') return;
      ev.preventDefault();
      ev.stopPropagation();
      ok();
    };
    const onBackdrop = ev => {
      ev.stopPropagation();
      if (ev.target === modal) cancel();
    };

    $('unlockOk').addEventListener('click', ok);
    $('unlockCancel').addEventListener('click', cancel);
    $('unlockClose').addEventListener('click', cancel);
    modal.addEventListener('keydown', onKey);
    modal.addEventListener('click', onBackdrop);
  });
}

// 加密时询问加密密钥（不保存，仅用于本次操作）
async function askNewKey(tip) {
  const res = await askPassword({
    title: '设置加密密钥',
    tip: tip + '密钥至少 ' + MASTER_MIN + ' 位，不会保存；之后每次查看或解密都要重新输入，请自行牢记。',
    confirm: true
  });
  return res ? res.pass : null;
}

async function encryptOne(input) {
  const entry = input && (entries.find(e => e.id === input.id) || input);
  if (!entry) return;
  // 密文被当成明文再加密一层就再也解不开了：先按 v1:/v2: 前缀把丢失的标记修正回来
  if (healEnc(entry)) {
    persist();
    renderList();
    showToast('「' + entry.name + '」已是密文，无需再次加密');
    return;
  }
  if (entry.enc) return;
  const pass = await askNewKey('将用 AES-256-GCM 加密这条密钥并保存在本地。');
  if (!pass) return;
  try {
    const plain = entry._plain || entry.password;
    entry.password = await aesEncrypt(plain, pass);
    entry.enc = true;
    entry.batchId = uid();
    delete entry._plain;
    shownIds.delete(entry.id);
    persist();
    renderList();
    showToast('已加密「' + entry.name + '」，需输入密钥才能查看');
  } catch (err) {
    showToast('加密失败：' + err.message);
  }
}

async function decryptOne(input) {
  if (!input || !input.enc) return;
  const entry = entries.find(e => e.id === input.id) || input;
  const cipher = entry.password;
  const plain = await askPlain(cipher, {
    title: '解密「' + entry.name + '」',
    tip: '验证通过后这条密钥将以明文保存，不再需要密钥。'
  });
  if (!plain) return;
  entry.password = plain.plain;
  entry.enc = false;
  entry.batchId = '';
  shownIds.delete(entry.id);
  delete entry._plain;
  keyCache.clear();
  persist();
  renderList();
  showToast('已解密「' + entry.name + '」');
}

async function encryptSelected() {
  // 同上：先把「其实是密文但丢了标记」的条目挑出来，别把密文再加密一层
  let healed = 0;
  entries.forEach(e => { if (selectedIds.has(e.id) && !e.enc && healEnc(e)) healed++; });
  const targets = entries.filter(e => selectedIds.has(e.id) && !e.enc);
  if (healed) {
    persist();
    renderList();
    showToast(healed + ' 条记录已是密文，已跳过');
  }
  if (!targets.length) {
    if (!healed) showToast('所选条目都已加密');
    return;
  }
  const pass = await askNewKey('将用同一个密钥加密所选 ' + targets.length + ' 条记录。');
  if (!pass) return;
  // 本批次共用同一个 batchId、同一个随机盐和同一把派生密钥，整批只算一次 PBKDF2
  const batchId = uid();
  try {
    const encrypt = await makeEncryptor(pass);
    let done = 0;
    for (const e of targets) {
      const plain = e._plain || e.password;
      e.password = await encrypt(plain);
      e.enc = true;
      e.batchId = batchId;
      delete e._plain;
      shownIds.delete(e.id);
      done++;
    }
    persist();
    renderList();
    showToast('已加密 ' + done + ' 条密钥（同批次，导出时输入一次密钥即可）');
  } catch (err) {
    showToast('加密失败：' + err.message);
  }
}

async function decryptSelected() {
  const targets = entries.filter(e => selectedIds.has(e.id) && e.enc);
  if (!targets.length) {
    showToast('所选条目没有加密内容');
    return;
  }
  const res = await askPassword({
    title: '解密所选 ' + targets.length + ' 条',
    tip: '输入加密密钥；只有能成功解密的条目会被还原为明文，其余保持不变。'
  });
  if (!res) return;

  const btn = $('btnDecryptSel');
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = '解密中…';
  let okCount = 0;
  let failCount = 0;
  // 每条密文各自带盐时，PBKDF2 只按「密钥+盐」缓存一次。
  // 打乱顺序会让 32 条缓存被反复挤出、同一条盐重复算几十次，按盐聚在一起就只算一次。
  const sorted = targets.map(e => ({ e: e, salt: cipherSalt(e.password) }))
    .sort((a, b) => (a.salt === b.salt ? 0 : a.salt < b.salt ? -1 : 1))
    .map(o => o.e);
  try {
    for (const e of sorted) {
      try {
        e.password = await aesDecrypt(e.password, res.pass);
        e.enc = false;
        e.batchId = '';
        shownIds.delete(e.id);
        delete e._plain;
        okCount++;
      } catch (err) {
        failCount++;
      }
    }
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
  keyCache.clear();
  persist();
  renderList();
  showToast('已解密 ' + okCount + ' 条' + (failCount ? '，' + failCount + ' 条因密钥不符跳过' : ''));
}

/* ---------------- 导出 ---------------- */

function stamp() {
  const d = new Date();
  const p = n => String(n).padStart(2, '0');
  return d.getFullYear() + p(d.getMonth() + 1) + p(d.getDate()) + '-' + p(d.getHours()) + p(d.getMinutes());
}

// 安卓 / iOS 的 WebView 没有注册 DownloadListener，<a download> 的 blob 下载会被静默丢弃，
// 所以原生端改成「把内容放进可复制的文本框」，由用户自己粘贴保存
const IS_NATIVE_APP = /Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
// Electron 里保存对话框由主进程弹，用户可能取消，成败要等主进程回报
const IS_ELECTRON = /Electron/i.test(navigator.userAgent);
let pendingExportNotice = null;
let textFocusTimer = null;   // 原生端导出弹窗的延迟聚焦，关闭时要能取消

// 主进程在下载结束时通过 preload 转发 DOM 事件（见 electron/preload.js）
document.addEventListener('export-result', e => {
  if (!pendingExportNotice) return;
  const notice = pendingExportNotice;
  pendingExportNotice = null;
  const state = e.detail;
  if (state === 'completed') showToast(notice);
  else if (state === 'cancelled') showToast('已取消保存，文件没有写入');
  else showToast('保存失败，请换个目录后重试');
});

function download(filename, text, mime) {
  const blob = new Blob([text], { type: mime + ';charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // 桌面端会先弹保存对话框，用户选路径可能耗掉几十秒，而数据要等对话框返回后才开始读。
  // 1 秒就 revoke 会让这种情况下存出 0 字节文件，所以留足时间（几百 KB 不心疼）
  setTimeout(() => URL.revokeObjectURL(url), 120000);
}

// 导出批量解密：同 batchId 的条目共用一个密钥，每组只弹一次窗
async function decryptForExport(source) {
  const out = [];
  // 解不开的条目名，收尾时一次性提示，不让记录悄悄缺一条
  out.failed = [];
  // 明文条目直接取
  for (const e of source) {
    if (!e.enc) out.push({ entry: e, plain: e.password });
  }

  // 已在本页展开过的加密条目，直接复用内存里的明文
  const locked = [];
  for (const e of source) {
    if (!e.enc) continue;
    if (e._plain && shownIds.has(e.id)) out.push({ entry: e, plain: e._plain });
    else locked.push(e);
  }

  // 按批次分组：有 batchId 的归一组，没有的各自独立成组
  const groups = new Map();
  for (const e of locked) {
    const key = e.batchId || 'single:' + e.id;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(e);
  }

  for (const list of groups.values()) {
    const first = list[0];
    const res = await askPlain(first.password, {
      title: list.length > 1
        ? '导出：解密「' + first.name + '」等 ' + list.length + ' 条'
        : '导出「' + first.name + '」',
      tip: list.length > 1
        ? '这 ' + list.length + ' 条是同一批次加密的，输入一次密钥即可全部解密导出。'
        : '这条密钥已加密，输入密钥验证后才能导出明文。'
    });
    if (!res) return null;
    out.push({ entry: first, plain: res.plain });
    for (let i = 1; i < list.length; i++) {
      const e = list[i];
      try {
        out.push({ entry: e, plain: await aesDecrypt(e.password, res.pass) });
      } catch (err) {
        // 记下来在收尾时汇总提示，避免只闪一条 toast 就悄悄少了记录
        out.failed.push(e.name);
      }
    }
  }

  // 保持与列表一致的顺序
  const order = new Map(source.map((e, i) => [e.id, i]));
  out.sort((a, b) => order.get(a.entry.id) - order.get(b.entry.id));
  keyCache.clear();
  return out;
}

// 导出记录：mode = 'enc' 保持密文；mode = 'plain' 解密成明文
async function buildExportList(source, mode) {
  if (mode === 'plain') return decryptForExport(source);
  return source.map(e => ({
    entry: e,
    // 明文条目原样导出，加密条目导出密文
    plain: e.enc ? null : e.password,
    cipher: e.enc ? e.password : null
  }));
}

function csvCell(v, formulaSafe) {
  let value = String(v);
  // 只给真正以公式符号开头的值加前缀：带前导空格的值 Excel 不会当公式，
  // 而导入端只认 ^'+[=+@-]，加了前缀反而会在往返时多出一个引号。
  // 开头本来就有单引号的（如密码 '=x）也要补一个：导入端只去掉一个，
  // 否则用户自己那个引号会在往返中被吃掉。
  if (formulaSafe && /^'*[=+@-]/.test(value)) value = "'" + value;
  return '"' + value.replace(/"/g, '""') + '"';
}

function exportPayload(list) {
  const keys = list.map(o => {
    const e = o.entry;
    const item = {
      name: e.name,
      // 保持加密时写入密文，并标记 enc 与 batchId，重新导入后仍能整批解密
      password: o.cipher ? o.cipher : o.plain,
      length: o.cipher ? 0 : String(o.plain).length,
      createdAt: new Date(e.createdAt).toISOString(),
      source: SOURCE_LABEL[e.source] || SOURCE_LABEL.generated
    };
    if (o.cipher) {
      item.enc = true;
      if (e.batchId) item.batchId = e.batchId;
    }
    return item;
  });
  return { app: 'random-key-manager', version: 1, exportedAt: new Date().toISOString(), count: keys.length, keys };
}

async function doExport(source, fmt, mode, filename) {
  const list = await buildExportList(source, mode);
  if (!list || !list.length) return null;
  const encKept = list.filter(o => o.cipher).length;
  // 解密导出时可能有个别条目密钥不符被跳过，必须随结果一起上报
  const skipped = list.failed || [];
  const meta = {
    count: list.length,
    encKept: encKept,
    skipped: skipped,
    mime: fmt === 'csv' ? 'text/csv' : 'application/json'
  };
  if (fmt === 'csv') {
    const lines = ['名称,密码,长度,创建时间,来源,加密,批次号'];
    list.forEach(o => {
      const e = o.entry;
      lines.push([
        csvCell(e.name, true),
        // 密文用引号包裹，逗号分隔导入时可原样还原
        csvCell(o.cipher ? o.cipher : o.plain, true),
        o.cipher ? 0 : String(o.plain).length,
        csvCell(new Date(e.createdAt).toLocaleString('zh-CN', { hour12: false })),
        csvCell(SOURCE_LABEL[e.source] || SOURCE_LABEL.generated),
        o.cipher ? 'true' : 'false',
        csvCell(o.cipher ? (e.batchId || '') : '')
      ].join(','));
    });
    return Object.assign(meta, { filename: filename + '.csv', text: '\ufeff' + lines.join('\r\n') });
  }
  return Object.assign(meta, {
    filename: filename + '.json',
    text: JSON.stringify(exportPayload(list), null, 2)
  });
}

// 导出收尾：浏览器/桌面写文件，原生端弹可复制文本框
function finishExport(out, fmt, mode) {
  const skipped = out.skipped || [];
  const tail = skipped.length ? '，另有 ' + skipped.length + ' 条密钥不符未导出' : '';
  if (IS_NATIVE_APP) {
    openTextExport(out);
    return;
  }
  const notice = '已导出 ' + out.count + ' 条（' + fmt.toUpperCase() +
    (mode === 'plain' ? '，明文' : out.encKept ? '，' + out.encKept + ' 条保持密文' : '，明文') + '）' + tail;
  // 浏览器直接落盘，提示可以立即给；Electron 要等主进程回报「保存/取消/失败」
  if (IS_ELECTRON) {
    pendingExportNotice = notice;
    download(out.filename, out.text, out.mime);
    return;
  }
  download(out.filename, out.text, out.mime);
  showToast(notice);
}

function openTextExport(out) {
  const skipped = out.skipped || [];
  rememberFocus();
  $('textTitle').textContent = '导出 ' + out.count + ' 条（' + (out.mime === 'text/csv' ? 'CSV' : 'JSON') + '）' +
    (skipped.length ? ' · ' + skipped.length + ' 条密钥不符未导出' : '');
  $('textFileName').textContent = out.filename;
  const area = $('textOut');
  area.value = out.text;
  $('textModal').hidden = false;
  setTimeout(() => {
    area.focus();
    area.select();
  }, 30);
}

function closeTextExport() {
  if ($('textModal').hidden) return; // 已经关过就别再弹一次焦点栈
  $('textModal').hidden = true;
  // 明文不留在 DOM 里
  $('textOut').value = '';
  $('textFileName').textContent = '';
  restoreFocus();
}

/* ---------------- 导出弹窗 ---------------- */

let exportSource = null; // 当前要导出的条目；null 时取自「全部」
let exportScope = 'all'; // 'all' | 'sel'

// 打开导出弹窗；scope = 'all' 全量，'sel' 所选
function openExport(scope) {
  const source = scope === 'sel' ? entries.filter(e => selectedIds.has(e.id)) : entries;
  if (!source.length) {
    showToast(scope === 'sel' ? '请先勾选要导出的密钥' : '没有可导出的密钥');
    return;
  }
  exportSource = source;
  exportScope = scope;
  const encCount = source.filter(e => e.enc).length;
  $('exportTitle').textContent = (scope === 'sel' ? '导出所选 ' : '导出全部 ') + source.length + ' 条';
  $('exportError').textContent = '';
  // 没有任何加密条目时，「保持加密」与「解密后导出」等价，默认明文并禁用加密项
  const encOpt = document.querySelector('#exportModal input[name="exportMode"][value="enc"]');
  encOpt.disabled = encCount === 0;
  document.querySelector('#exportModal input[name="exportMode"][value="' + (encCount ? 'enc' : 'plain') + '"]').checked = true;
  updateCsvWarn();
  rememberFocus();
  $('exportModal').hidden = false;
  // 焦点必须进弹窗，否则键盘用户还停在下面的页面里，Tab 半天进不来
  const first = document.querySelector('#exportModal input[name="exportFmt"]:checked') ||
    document.querySelector('#exportModal input[name="exportFmt"]');
  if (first) first.focus();
}

// CSV 交给 Excel 会被当数字处理，选中 CSV 时给条明确警告
function updateCsvWarn() {
  const el = $('csvWarn');
  if (!el) return;
  const fmt = (document.querySelector('#exportModal input[name="exportFmt"]:checked') || {}).value;
  el.hidden = fmt !== 'csv';
}

function closeExport() {
  // 导出过程中按 Esc、或导出结束后再关一次都会走到这里；已关闭就别再弹一次焦点栈
  if ($('exportModal').hidden) return;
  $('exportModal').hidden = true;
  exportSource = null;
  restoreFocus();
}

async function runExport() {
  if (!exportSource || !exportSource.length) return;
  const fmt = (document.querySelector('#exportModal input[name="exportFmt"]:checked') || {}).value || 'json';
  const mode = (document.querySelector('#exportModal input[name="exportMode"]:checked') || {}).value || 'enc';
  const btn = $('exportRun');
  btn.disabled = true;
  try {
    const base = (exportScope === 'sel' ? 'keys-selected-' : 'keys-') + stamp();
    const out = await doExport(exportSource, fmt, mode, base);
    // 取消密钥输入时 doExport 返回 null：这里补一句反馈，别让弹窗看起来卡住
    if (!out) {
      showToast('已取消导出');
      return;
    }
    closeExport();
    finishExport(out, fmt, mode);
  } catch (err) {
    $('exportError').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
}

/* ---------------- 手动记录 ---------------- */

function addManual() {
  const name = normalizeName($('manualName').value);
  const pwd = $('manualPwd').value;
  if (!name) {
    showToast('请填写名称');
    $('manualName').focus();
    return;
  }
  if (!pwd) {
    showToast('请填写要记录的密码');
    $('manualPwd').focus();
    return;
  }
  const dup = findByName(name);
  if (dup && !confirm('已存在同名记录「' + dup.name + '」，仍要添加吗？')) return;
  addEntry(name, pwd, { source: 'manual' });
  $('manualName').value = '';
  $('manualPwd').value = '';
  $('manualName').focus();
  showToast('已添加：' + name);
}

/* ---------------- 批量导入 ---------------- */

const SOURCE_LABEL = { generated: '生成', manual: '手动', imported: '导入' };

// 删除 BOM 与零宽字符（手机/聊天软件复制常见）
function cleanText(s) {
  return String(s).replace(/^\uFEFF/, '').replace(/[\u200B-\u200D\uFEFF]/g, '');
}

// delim 是「分隔符集合」：收起的分隔符越多，越能容忍同一份文本里混用半角/全角逗号
function splitCsv(text, delim, quotedOut) {
  const rows = [];
  const flags = [];
  let row = [];
  let rowFlags = [];
  let cell = '';
  let quoted = false;
  let cellQuoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else if (c === '"' && !cell) { quoted = true; cellQuoted = true; }
    else if (delim.indexOf(c) > -1) { row.push(cell); rowFlags.push(cellQuoted); cell = ''; cellQuoted = false; }
    else if (c === '\r' || c === '\n') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rowFlags.push(cellQuoted);
      rows.push(row); flags.push(rowFlags);
      row = []; rowFlags = []; cell = ''; cellQuoted = false;
    } else cell += c;
  }
  if (quoted) throw new Error('CSV 格式错误：字段引号未闭合');
  if (cell || row.length) {
    row.push(cell); rowFlags.push(cellQuoted);
    rows.push(row); flags.push(rowFlags);
  }
  // 整行空白的丢弃，引号标记跟着一起丢，保证两个数组下标始终对齐
  const keep = [];
  rows.forEach((cells, i) => { if (cells.some(value => value.trim() !== '')) keep.push(i); });
  if (quotedOut) keep.forEach(i => quotedOut.push(flags[i]));
  return keep.map(i => rows[i]);
}

// Excel 防公式注入会给 = + @ - 开头的值加一个单引号，导入时还原
// 只去掉导出时补的那一个单引号：'=x 是用户原本的内容，去掉就丢字符了
function unquoteFormula(value) {
  return String(value || '').replace(/^'(?='*[=+@-])/, '');
}

// ISO / 本地时间字符串 → 毫秒时间戳；解析不出来返回 0
function parseTime(value) {
  if (typeof value === 'number' && isFinite(value)) return value;
  if (!value) return 0;
  const t = Date.parse(String(value).trim());
  return isFinite(t) ? t : 0;
}

function normalizeSource(value) {
  const v = String(value || '').trim();
  if (/手动|manual/i.test(v)) return 'manual';
  if (/导入|import/i.test(v)) return 'imported';
  return 'generated';
}

// 支持 JSON（本程序导出或 {name,password} 数组）、CSV、纯文本 "名称,密码"
// 每条记录统一返回 { name, password, enc, batchId, createdAt, source }
function parseImport(text) {
  const raw = cleanText(text).trim();
  if (!raw) return [];

  const isCipher = v => typeof v === 'string' && /^(v1|v2):/.test(v);
  const repairCipher = repairCipherText;

  // 截断时打标记，预览才能区分「正好 2000 条」和「被截掉了」
  const limitList = list => {
    const picked = list.slice(0, IMPORT_MAX);
    picked.truncated = list.length > IMPORT_MAX;
    return picked;
  };

  if (raw[0] === '{' || raw[0] === '[') {
    let data;
    try {
      data = JSON.parse(raw);
    } catch (err) {
      throw new Error('JSON 格式错误：' + err.message);
    }
    // entries 是常见写法（含其它密码管理器导出的文件），一并兼容
    let list = Array.isArray(data) ? data : (data.keys || data.entries || data.list || data.items || data.data || []);
    if (!Array.isArray(list)) throw new Error('JSON 中没有找到密钥数组');
    return limitList(list.map(item => {
      let password = String(item.password || item.pwd || item.secret || item.value || '');
      // 密文可能在 JSON 中转时被加上引号/空格，去掉后再判断
      password = repairCipher(password);
      // 导出的密文带 enc: true，也兼容只写了 v1:/v2: 前缀的记录，以及批次号
      const enc = (item.enc === true || item.enc === 'true' || isCipher(password)) && isCipher(password);
      return {
        // JSON 是无损格式：导出时不加 Excel 的公式前缀，这里也就不能剥，
        // 否则名字本身就是 '=xxx 的记录会在每次往返中少一个字符（CSV 那条链路才需要还原）
        name: normalizeName(item.name || item.title || item.site || ''),
        password: clampPassword(password, isCipher(password)),
        enc: enc,
        batchId: enc && typeof item.batchId === 'string' ? item.batchId : '',
        createdAt: parseTime(item.createdAt || item.time || item.date),
        source: normalizeSource(item.source)
      };
    }).filter(o => o.name || o.password));
  }

  // 只看首行会被「第一行没 Tab、后面全是 Tab」的表头骗过去，改成前几行投票
  const head = raw.split(/\r?\n/).slice(0, 5);
  const firstLine = head[0] || '';
  // 本程序导出的 CSV 一定以「名称,密码」开头：密码里若恰好含 Tab 或全角逗号，放宽分隔符
  // 会把密码切碎，这种表头把分隔符钉死成半角逗号（Tab 分隔的表头不含逗号，不受影响）
  const appHead = firstLine.indexOf('名称,') > -1 || firstLine.indexOf(',密码') > -1;
  // 半角与全角逗号都算「逗号族」：中文输入法下手打的「名称，密码」很常见，
  // 同一份粘贴内容里两种混用也要能切（密码里带全角逗号只在引号里才保得住）
  let tabVotes = 0;
  let commaVotes = 0;
  head.forEach(line => {
    const tabs = (line.match(/\t/g) || []).length;
    const commas = (line.match(/[,，]/g) || []).length;
    if (tabs > commas) tabVotes++;
    else if (commas > tabs) commaVotes++;
  });
  const delim = appHead ? ',' : (tabVotes > commaVotes ? '\t' : ',，');
  const rowQuoted = [];
  const rows = splitCsv(raw, delim, rowQuoted);
  if (!rows.length) return [];

  // 统一全角符号，便于从聊天/笔记里复制过来的内容也能解析
  const norm = s => s.replace(/，/g, ',').replace(/＝/g, '=').replace(/\u3000/g, ' ');

  const isHeader = l => {
    const h = norm(l).toLowerCase();
    const commaHeader = h.indexOf(',') > -1 && (h.indexOf('名称') > -1 || /\bname\b/.test(h)) && /password|密码|pwd/.test(h);
    const tabHeader = h.indexOf('\t') > -1 && (h.indexOf('名称') > -1 || /\bname\b/.test(h)) && /password|密码|pwd/.test(h);
    return commaHeader || tabHeader;
  };

  // 引号里的内容是「原样写入」的（本程序导出的 CSV、Excel 另存都是这样），再做全角替换
  // 会把密码里的「，」「＝」悄悄改成半角；只对不带引号的字段做归一化
  const cellAt = (row, flags) => row.map((c, i) => (flags && flags[i]) ? c : norm(c));
  const normalized = rows.map((row, ri) => cellAt(row, rowQuoted[ri]));
  const header = normalized[0].map(value => value.trim().toLowerCase());
  const hasBatchColumn = header[5] === '加密' && header[6] === '批次号';
  const appCsv = header[0] === '名称' && header[1] === '密码' &&
    (hasBatchColumn || (header[2] === '长度' && header[3] === '创建时间' && header[4] === '来源'));
  if (appCsv || isHeader(normalized[0].join(','))) {
    normalized.shift();
    rowQuoted.shift();
  }

  const out = [];
  normalized.forEach((cells, ri) => {
    cells = cellAt(cells, rowQuoted[ri]);
    let name = '';
    let password = '';
    let encrypted = false;
    let batchId = '';
    if (appCsv) {
      name = cells[0] || '';
      password = cells[1] || '';
      encrypted = isCipher(password) && (!hasBatchColumn || String(cells[5] || '').trim().toLowerCase() === 'true');
      batchId = encrypted ? (hasBatchColumn ? (cells[6] || '') : '') : '';
    } else if (cells.length > 1) {
      name = cells[0];
      password = cells[1];
    } else {
      const line = cells[0] || '';
      if (isCipher(line.trim())) password = line.trim();
      else if (line.indexOf('=') > -1 && !isCipher(line.slice(line.indexOf('=') + 1).trim())) {
        const i = line.indexOf('=');
        name = line.slice(0, i);
        password = line.slice(i + 1);
      } else {
        const match = line.match(/^(\S+)\s+(.+)$/);
        if (match) { name = match[1]; password = match[2]; }
        else name = line;
      }
    }
    name = name.trim();
    // 本程序导出的 CSV 每个字段都带引号：引号里的密码要原样保留（首尾可能有空格），
    // 只有手工粘贴的不带引号字段才需要 trim
    password = (rowQuoted[ri] && rowQuoted[ri][1]) ? password : password.trim();
    // 去掉中转时残留的引号/反引号，别让密文前缀失效
    const repaired = repairCipher(password);
    if (repaired !== password) password = repaired;
    // 本程序导出的 CSV 会给 = + @ - 开头的值加单引号，这里必须还原，否则密码会多一个 '
    else password = unquoteFormula(password);
    encrypted = encrypted || isCipher(password);
    // 时间与来源随文件一起回来，导入不再统一盖成「今天」
    const createdAt = appCsv ? parseTime(cells[3]) : 0;
    const source = appCsv ? normalizeSource(cells[4]) : 'imported';
    if (name || password) {
      out.push({
        name: normalizeName(unquoteFormula(name)),
        password: clampPassword(password, isCipher(password)),
        enc: encrypted,
        batchId: batchId,
        createdAt: createdAt,
        source: source
      });
    }
  });
  return limitList(out);
}

// 导入时统计加密记录，给出明确提示
function updateImportTip(list) {
  const tipEl = $('importTip');
  const encCount = list.filter(o => o.enc).length;
  const plainCount = list.filter(o => !o.enc).length;
  const keepEnc = $('importKeepEnc').checked;
  $('importKeepEnc').disabled = encCount === 0;
  if (!encCount) {
    tipEl.hidden = true;
    tipEl.textContent = '';
    // 之前取消勾选留下的风险底色要一起清掉，否则提示没了红底还在
    $('importKeepEnc').parentElement.classList.remove('warn');
    return;
  }
  tipEl.hidden = false;
  tipEl.textContent = '识别到 ' + encCount + ' 条加密记录' + (plainCount ? '、' + plainCount + ' 条明文记录' : '') +
    '，将' + (keepEnc ? '以密文形式原样导入，导入后仍需输入原密钥才能查看' : '先解密成明文再保存，需要输入加密密钥') + '。';
  if (!keepEnc) $('importKeepEnc').parentElement.classList.add('warn');
  else $('importKeepEnc').parentElement.classList.remove('warn');
}

function previewImport() {
  const area = $('importText');
  const btn = $('importRun');
  const errEl = $('importError');
  errEl.textContent = '';
  if (!area.value.trim()) {
    btn.disabled = true;
    $('importCount').textContent = '';
    updateImportTip([]);
    return [];
  }
  let list;
  try {
    list = parseImport(area.value);
  } catch (err) {
    errEl.textContent = err.message;
    btn.disabled = true;
    $('importCount').textContent = '';
    updateImportTip([]);
    return [];
  }
  btn.disabled = list.length === 0;
  if (list.truncated) errEl.textContent = '单次最多导入 ' + IMPORT_MAX + ' 条，超出部分已忽略';
  $('importCount').textContent = list.length
    ? '（' + list.length + ' 条' + (list.truncated ? '，已达上限' : '') + '）'
    : '';
  updateImportTip(list);
  return list;
}

// 把导入列表里的加密记录解密成明文；同批次只问一次，返回新的列表
async function decryptImportList(list) {
  // 保留 createdAt / source 等元信息，只把密码与加密标记改写
  const out = list.map(o => Object.assign({}, o, { enc: false, batchId: '' }));
  const idx = [];
  out.forEach((o, i) => { if (list[i].enc) idx.push(i); });
  // 同一批次的记录共用密钥，按批次聚合；没有批次号的逐条输入
  const groups = new Map();
  idx.forEach(i => {
    const key = list[i].batchId || 'single:' + i;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(i);
  });

  try {
    for (const ids of groups.values()) {
      const first = out[ids[0]];
      const res = await askPlain(list[ids[0]].password, {
        title: ids.length > 1 ? '导入：解密「' + first.name + '」等 ' + ids.length + ' 条' : '导入「' + first.name + '」',
        tip: ids.length > 1
          ? '这 ' + ids.length + ' 条属于同一批次，输入一次密钥即可全部解密导入。'
          : '这条记录是加密的，输入原加密密钥后以明文导入。'
      });
      // 用户中途取消：派生密钥必须一起清掉，不能留在内存里
      if (!res) return null;
      // 整组尝试用同一个密钥解，解不开的保留密文并计数
      let failed = 0;
      for (const i of ids) {
        try {
          out[i].password = await aesDecrypt(list[i].password, res.pass);
        } catch (err) {
          out[i].password = list[i].password;
          out[i].enc = true;
          out[i].batchId = list[i].batchId;
          failed++;
        }
      }
      if (failed) showToast('有 ' + failed + ' 条密钥不符，保留为密文');
    }
    return out;
  } finally {
    keyCache.clear();
  }
}

async function runImport() {
  let list = previewImport();
  if (!list.length) {
    $('importError').textContent = '没有可导入的有效记录';
    return;
  }
  const keepEnc = $('importKeepEnc').checked;
  const hasEnc = list.some(o => o.enc);

  if (hasEnc && !keepEnc) {
    const btn = $('importRun');
    btn.disabled = true;
    try {
      list = await decryptImportList(list);
    } finally {
      btn.disabled = false;
    }
    if (!list) return; // 用户取消了密钥输入
  }

  const overwrite = $('overwrite').checked;
  let added = 0;
  let updated = 0;
  let skipped = 0;
  let unnamed = 0;
  let encImported = 0;

  const batchNames = new Set();
  list.forEach(o => {
    let name = o.name;
    if (!name) {
      unnamed++;
      name = nextAutoName();
    } else if (batchNames.has(nameKey(name)) && !overwrite) {
      // 同一批内重名（entries 中已包含前一条导入结果，这里仅作保险）
      skipped++;
      return;
    }
    batchNames.add(nameKey(name));
    // 重名判断不看大小写、不看得多余空格，避免「GitHub」和「github 」并存
    const dup = findByName(name);
    const apply = target => {
      target.password = o.password;
      target.enc = !!o.enc;
      target.batchId = o.enc ? (o.batchId || uid()) : '';
      target.poolSize = 0;
      if (o.createdAt) target.createdAt = o.createdAt;
      if (o.source) target.source = o.source;
      // 兜底：导入内容本身就是密文时，绝不当成明文存下来
      healEnc(target);
      if (target.enc) encImported++;
      shownIds.delete(target.id);
      delete target._plain;
    };
    if (dup) {
      if (!overwrite) { skipped++; return; }
      if (!o.password) { skipped++; return; }
      apply(dup);
      updated++;
      return;
    }
    if (!o.password) { skipped++; return; }
    const created = {
      id: uid(),
      name: name,
      password: o.password,
      enc: false,
      batchId: '',
      // 文件里带了原始时间就用它，别把历史记录统一盖成导入当天
      createdAt: o.createdAt || Date.now(),
      poolSize: 0,
      source: o.source || 'imported'
    };
    entries.unshift(created);
    apply(created);
    added++;
  });

  persist();
  renderList();
  closeImport(true);
  const parts = [];
  if (added) parts.push('新增 ' + added);
  if (updated) parts.push('覆盖 ' + updated);
  if (skipped) parts.push('跳过 ' + skipped);
  if (unnamed) parts.push('自动命名 ' + unnamed);
  if (encImported) parts.push(encImported + ' 条保持加密');
  showToast('导入完成：' + (parts.join('，') || '无变化'));
}

function openImport() {
  rememberFocus();
  $('importModal').hidden = false;
  $('importError').textContent = '';
  $('importCount').textContent = '';
  $('importText').focus();
  previewImport();
}

// 清空导入表单：文本框、已选文件、两个勾选项、错误与提示
function resetImportForm() {
  importReadToken++;
  $('importText').value = '';
  $('fileInput').value = '';
  $('importKeepEnc').checked = true;
  $('overwrite').checked = false;
  $('importKeepEnc').parentElement.classList.remove('warn');
  previewImport();
}

// force = true 时跳过「已粘贴内容会丢失」的确认（导入成功后调用）
function closeImport(force) {
  if ($('importModal').hidden) return; // 重复关闭：不要再弹一次焦点栈
  if (!force && $('importText').value.trim() &&
      !confirm('关闭后会清空已粘贴的内容，确定关闭吗？')) return;
  $('importModal').hidden = true;
  resetImportForm();
  restoreFocus();
}

// 解码顺序：UTF-16 BOM → 零字节启发（无 BOM 的 UTF-16）→ UTF-8 严格 → GBK → 宽松 UTF-8
// 记事本「Unicode」与 Excel「Unicode 文本」都是 UTF-16LE，只认 UTF-8/GBK 会整份乱码
function decodeImportBuffer(buf) {
  if (buf.length >= 2) {
    if (buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder('utf-16le').decode(buf);
    if (buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder('utf-16be').decode(buf);
  }
  // UTF-16 文本里 ASCII 字符的高位是 0x00，GBK/UTF-8 几乎不会出现这种分布
  const probe = Math.min(buf.length, 256);
  if (probe >= 8) {
    let zeros = 0;
    for (let i = 0; i < probe; i++) if (buf[i] === 0) zeros++;
    if (zeros / probe > 0.1) {
      let evenZero = 0;
      let oddZero = 0;
      for (let i = 0; i < probe; i += 2) {
        if (buf[i] === 0) evenZero++;
        if (i + 1 < probe && buf[i + 1] === 0) oddZero++;
      }
      return new TextDecoder(oddZero >= evenZero ? 'utf-16le' : 'utf-16be').decode(buf);
    }
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch (err) {
    try {
      return new TextDecoder('gbk').decode(buf);
    } catch (err2) {
      return new TextDecoder().decode(buf);
    }
  }
}

function readImportFile(file) {
  const token = ++importReadToken;
  const errEl = $('importError');
  // 全量读进内存再逐字符解析，几百 MB 的文件会直接把 WebView 拖死
  if (file.size > IMPORT_FILE_MAX) {
    errEl.textContent = '文件过大（' + Math.round(file.size / 1048576) + 'MB），请拆分成小于 ' +
      Math.round(IMPORT_FILE_MAX / 1048576) + 'MB 的文件再导入';
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    if (token !== importReadToken || $('importModal').hidden) return;
    const text = decodeImportBuffer(new Uint8Array(reader.result || new ArrayBuffer(0)));
    // 2000 条 × 200 字符只要 0.4MB，超过 2MB 的文本基本可以肯定是选错了文件
    if (text.length > IMPORT_TEXT_MAX) {
      errEl.textContent = '文件内容过长，请确认选对了文件（单个密码库通常不到 1MB）';
      return;
    }
    errEl.textContent = '';
    $('importText').value = text;
    previewImport();
  };
  reader.onerror = () => {
    if (token === importReadToken && !$('importModal').hidden) errEl.textContent = '文件读取失败';
  };
  reader.readAsArrayBuffer(file);
}

/* ---------------- 事件绑定 ---------------- */

// 拖滑块时同步数字与已生成的密码：只改文本会让人以为密码已经跟着变了
lengthEl.addEventListener('input', () => {
  lenText.textContent = lengthEl.value;
  saveGenerateOptions();
  if (currentPwd) generate();
});
// 字符集/排除易混淆改动后，之前生成的密码已不符合新设置，直接重算
['optLower', 'optUpper', 'optDigit', 'optSymbol', 'optExclusive'].forEach(id => {
  $(id).addEventListener('change', () => {
    if (currentPwd) generate();
    saveGenerateOptions();
  });
});
$('genBtn').addEventListener('click', generate);
$('refreshBtn').addEventListener('click', generate);
$('copyBtn').addEventListener('click', () => {
  if (currentPwd) copyText(currentPwd);
});
passwordEl.addEventListener('click', () => {
  if (currentPwd) copyText(currentPwd);
});
nameInput.addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); generate(); }
});
$('saveBtn').addEventListener('click', saveCurrent);
$('manualAdd').addEventListener('click', addManual);
$('manualPwd').addEventListener('keydown', e => {
  if (e.key === 'Enter') { e.preventDefault(); addManual(); }
});
// 搜索与导入预览都加防抖：大列表/大文本时不再每敲一个字符就全量重算
searchInput.addEventListener('input', () => {
  // 换关键词等于换结果集，先回顶再重绘
  listEl.scrollTop = 0;
  clearTimeout(searchTimer);
  searchTimer = setTimeout(renderList, 120);
});
$('importBtn').addEventListener('click', openImport);
// 包里包一层：直接传 closeImport 会把事件对象当成 force 参数，跳过确认
$('modalClose').addEventListener('click', () => closeImport());
$('importRun').addEventListener('click', runImport);
$('importFileBtn').addEventListener('click', () => $('fileInput').click());
$('importText').addEventListener('input', () => {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(previewImport, 180);
});
$('importKeepEnc').addEventListener('change', previewImport);
$('fileInput').addEventListener('change', e => {
  const file = e.target.files && e.target.files[0];
  e.target.value = '';
  if (file) readImportFile(file);
});
$('importModal').addEventListener('click', e => {
  if (e.target === $('importModal')) closeImport();
});
document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  // 密钥弹窗叠在其它弹窗之上，它自己处理 Esc，这里不能跟着关下层弹窗
  if (!$('unlockModal').hidden) return;
  if (!$('textModal').hidden) closeTextExport();
  else if (!$('importModal').hidden) closeImport();
  else if (!$('exportModal').hidden) closeExport();
});
// 弹窗内 Tab 循环，避免焦点跑到后面的背景内容上
document.addEventListener('keydown', e => {
  if (e.key !== 'Tab') return;
  const modal = topModal();
  if (!modal) return;
  const items = [...modal.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )].filter(el => el.offsetParent !== null && el.type !== 'hidden');
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  const inside = modal.contains(document.activeElement);
  if (e.shiftKey && (document.activeElement === first || !inside)) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && (document.activeElement === last || !inside)) {
    e.preventDefault();
    first.focus();
  }
});
$('exportBtn').addEventListener('click', () => openExport('all'));
document.querySelectorAll('#exportModal input[name="exportFmt"]').forEach(el => {
  el.addEventListener('change', updateCsvWarn);
});
$('exportRun').addEventListener('click', runExport);
$('exportClose').addEventListener('click', closeExport);
$('exportCancel').addEventListener('click', closeExport);
$('exportModal').addEventListener('click', e => {
  if (e.target === $('exportModal')) closeExport();
});
$('textModal').addEventListener('click', e => {
  if (e.target === $('textModal')) closeTextExport();
});
$('textClose').addEventListener('click', closeTextExport);
$('textCancel').addEventListener('click', closeTextExport);
$('textCopy').addEventListener('click', () => {
  // 导出内容是要拿去粘贴的，这里不能自动清空剪贴板
  copyText($('textOut').value, '已复制全部导出内容，去粘贴保存吧', true);
});
$('clearAll').addEventListener('click', () => {
  if (!entries.length) return;
  if (!confirm('确定清空全部 ' + entries.length + ' 条密钥？此操作不可恢复。')) return;
  entries = [];
  shownIds.clear();
  selectedIds.clear();
  // 列表都清空了，派生密钥也没必要继续留在内存里
  keyCache.clear();
  persist();
  renderList();
  showToast('已清空密钥列表');
});

$('selAll').addEventListener('change', e => {
  const q = searchInput.value.trim().toLowerCase();
  const visible = q ? entries.filter(x => matchesQuery(x, q)) : entries;
  visible.forEach(x => {
    if (e.target.checked) selectedIds.add(x.id);
    else selectedIds.delete(x.id);
  });
  updateSelectionUI();
});
$('btnEncryptSel').addEventListener('click', encryptSelected);
$('btnDecryptSel').addEventListener('click', decryptSelected);
$('btnClearSel').addEventListener('click', () => {
  selectedIds.clear();
  updateSelectionUI();
});
$('btnExportSel').addEventListener('click', () => openExport('sel'));

/* ---------------- 启动 ---------------- */

try {
  secHintClosed = localStorage.getItem(SEC_HINT_KEY) === '1';
} catch (err) {
  secHintClosed = false;
}

entries = loadEntries();
// 旧版本曾把明文写进本地存储，读到残留就立刻用干净数据覆盖掉
if (legacyPlainFound) persist();
renderList();
$('appVersion').textContent = 'v' + APP_VERSION;
// 恢复上次的长度/字符集，再生成首条密码
loadGenerateOptions();

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState !== 'visible') {
    // 切到后台/最小化时立刻收起所有明文，回到桌面也不会被旁人看到
    hideAllPlain();
    return;
  }
  // 回到前台把之前因为没权限/不在前台而没清掉的剪贴板补清
  if (pendingClipClear) tryClearClipboard(pendingClipClear);
});

// 桌面端按 Alt-Tab 切到别的窗口时 visibilityState 仍是 visible，必须靠 blur 收起明文
window.addEventListener('blur', () => hideAllPlain());

$('secHintClose').addEventListener('click', () => {
  secHintClosed = true;
  try { localStorage.setItem(SEC_HINT_KEY, '1'); } catch (err) { /* 隐私模式忽略 */ }
  updateSecHint();
});

// 其它窗口/标签页改了数据时同步过来，避免后写的整份覆盖先写的
window.addEventListener('storage', e => {
  if (e.key !== STORAGE_KEY) return;
  entries = loadEntries();
  shownIds.clear();
  keyCache.clear();
  [...selectedIds].forEach(id => {
    if (!entries.some(x => x.id === id)) selectedIds.delete(id);
  });
  renderList();
  showToast('已同步其它窗口的修改（共 ' + entries.length + ' 条）');
});

if (!storageOk) showToast('无法访问本地存储，列表不会跨会话保留');
if (storageBroken) showToast('发现无法解析的旧数据，已备份原始内容并从空列表开始');
const encOnLoad = entries.filter(e => e.enc).length;
if (encOnLoad) showToast('有 ' + encOnLoad + ' 条密钥已加密，查看时需输入加密密钥');
generate();
