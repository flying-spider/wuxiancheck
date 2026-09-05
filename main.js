const { app, BrowserWindow, WebContentsView, ipcMain } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { fetch, ProxyAgent } = require('undici');

// ---------------- 常量 ----------------
const API_BASE = 'http://api.91http.com';
const CHECK_URL = 'https://userappeal.vivo.com.cn/';
const CHECK_MARKER = 'vivo账号申诉';

// 浏览器内容使用独立的持久化 session，方便单独设置代理
const PARTITION = 'persist:proxysession';

// 顶部工具栏高度（与 index.html 中 #toolbar 的高度保持一致）
const TOOLBAR_HEIGHT = 51;

// 日志面板高度（与 index.html 中 #logPanel 的高度保持一致）
const LOG_HEIGHT = 200;

// 启动后默认打开的主页
const DEFAULT_URL = 'https://userappeal.vivo.com.cn/#/index';

// 距离到期提前多少秒自动换 IP
const EXPIRE_SWITCH_SECONDS = 20;

// ---------------- 设置 ----------------
const DEFAULT_SETTINGS = {
  trade_no: '',
  secret: '',
  num: 10,      // 每次请求提取的 IP 数量
  N: 5,         // 优质 IP 池目标大小
  maxLatency: 2000, // 质量检测延迟阈值（毫秒），低于该值视为优质
  proxy_user: '',  // 代理账号（账密认证用）
  proxy_pass: '',  // 代理密码
};

let settings = { ...DEFAULT_SETTINGS };

function settingsPath() {
  return path.join(app.getPath('userData'), 'settings.json');
}

function clampInt(v, min, max) {
  const n = parseInt(v, 10);
  if (Number.isNaN(n)) return min;
  return Math.max(min, Math.min(max, n));
}

function loadSettings() {
  try {
    const parsed = JSON.parse(fs.readFileSync(settingsPath(), 'utf8'));
    settings = {
      ...DEFAULT_SETTINGS,
      ...parsed,
      trade_no: String(parsed.trade_no ?? DEFAULT_SETTINGS.trade_no).trim(),
      secret: String(parsed.secret ?? DEFAULT_SETTINGS.secret).trim(),
      num: clampInt(parsed.num, 1, 200),
      N: clampInt(parsed.N, 1, 200),
      maxLatency: clampInt(parsed.maxLatency, 100, 15000),
      proxy_user: String(parsed.proxy_user ?? DEFAULT_SETTINGS.proxy_user).trim(),
      proxy_pass: String(parsed.proxy_pass ?? DEFAULT_SETTINGS.proxy_pass).trim(),
    };
  } catch (e) {
    settings = { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(next) {
  settings = {
    ...settings,
    trade_no: String(next.trade_no ?? settings.trade_no).trim(),
    secret: String(next.secret ?? settings.secret).trim(),
    num: clampInt(next.num ?? settings.num, 1, 200),
    N: clampInt(next.N ?? settings.N, 1, 200),
    maxLatency: clampInt(next.maxLatency ?? settings.maxLatency, 100, 15000),
    proxy_user: String(next.proxy_user ?? settings.proxy_user).trim(),
    proxy_pass: String(next.proxy_pass ?? settings.proxy_pass).trim(),
  };
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2), 'utf8');
  } catch (e) { /* 忽略写入错误 */ }
  return settings;
}

// ---------------- 代理池 ----------------
const pool = [];          // { proxy: "ip:port", expireAt: 毫秒时间戳 }
let currentProxy = null;  // 当前应用到浏览器的 "ip:port"
let currentExpireAt = null;
let refilling = false;
let swapping = false;
let lastError = null;
let switchTimer = null;
let maintenanceTimer = null;

let mainWindow = null;
let browserView = null;
let logOpen = false;
let zoomFactor = 1.0; // 当前页面缩放比例（100% = 1.0）

// 日志环形缓冲 + 推送
const LOG_LIMIT = 300;
const logs = [];

function log(level, msg) {
  const time = new Date().toLocaleTimeString('zh-CN', { hour12: false });
  const line = `[${time}] [${level}] ${msg}`;
  logs.push(line);
  if (logs.length > LOG_LIMIT) logs.splice(0, logs.length - LOG_LIMIT);
  console.log(line);
  sendToRenderer('log', line);
}

// 安全地向渲染进程推送消息，避免窗口销毁后 send 抛异常
function sendToRenderer(channel, ...args) {
  try {
    if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents && !mainWindow.webContents.isDestroyed()) {
      mainWindow.webContents.send(channel, ...args);
    }
  } catch (e) { /* 忽略 */ }
}

// 安全获取浏览器视图的 webContents，销毁时返回 null
function getBrowserWC() {
  try {
    if (!browserView) return null;
    const wc = browserView.webContents;
    return wc && !wc.isDestroyed() ? wc : null;
  } catch (e) {
    return null;
  }
}

// 兜底：未捕获异常不退出进程，记录日志避免整机卡死
process.on('uncaughtException', (err) => {
  try {
    log('error', '未捕获异常：' + (err && err.stack ? err.stack : String(err)));
  } catch (e) { /* 忽略 */ }
});

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function buildApiUrl(count) {
  const q = new URLSearchParams({
    trade_no: settings.trade_no,
    secret: settings.secret,
    num: String(count),
    format: 'text',
    sep: '1',
    time: '1',
    protocol: '1',
    filter: '1',
  });
  return `${API_BASE}/v1/get-ip?${q.toString()}`;
}

// 从接口拉取一批代理，返回 [{ proxy, expireAt }]
async function fetchProxies(count) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch(buildApiUrl(count), { signal: controller.signal });
    if (!res.ok) throw new Error(`接口返回 HTTP ${res.status}`);
    const text = (await res.text()).trim();
    if (!text) return [];
    const list = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      // 返回格式：ip:port:YYYY-MM-DD HH:MM:SS
      const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+):(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/);
      if (!m) continue;
      const proxy = `${m[1]}:${m[2]}`;
      const expireAt = new Date(m[3].replace(' ', 'T')).getTime();
      if (!Number.isNaN(expireAt)) {
        list.push({ proxy, expireAt });
      }
    }
    return list;
  } finally {
    clearTimeout(timer);
  }
}

// 原始 TCP 连通性检测（不经过代理），判断代理 ip:port 是否可达
function rawTcpConnect(host, port, timeoutMs = 2500) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const started = Date.now();
    let settled = false;
    const finish = (ok, info) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ok, ms: Date.now() - started, info });
    };
    const timer = setTimeout(() => finish(false, 'timeout'), timeoutMs);
    socket.once('connect', () => { clearTimeout(timer); finish(true, 'connected'); });
    socket.once('error', (e) => { clearTimeout(timer); finish(false, e.code || e.message); });
  });
}

// 手动向代理发 CONNECT 请求，探测代理的隧道能力与返回码
function manualConnect(targetHost, targetPort, proxyHost, proxyPort, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: proxyHost, port: proxyPort });
    const started = Date.now();
    let buf = '';
    let settled = false;
    const finish = (obj) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ...obj, ms: Date.now() - started });
    };
    const timer = setTimeout(() => finish({ ok: false, info: 'timeout' }), timeoutMs);
    socket.once('connect', () => {
      let req = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\nProxy-Connection: keep-alive\r\n`;
      if (settings.proxy_user) {
        const token = Buffer.from(`${settings.proxy_user}:${settings.proxy_pass}`).toString('base64');
        req += `Proxy-Authorization: Basic ${token}\r\n`;
      }
      req += '\r\n';
      socket.write(req);
    });
    socket.on('data', (d) => {
      buf += d.toString('latin1');
      const m = buf.match(/^HTTP\/1\.[01] (\d{3})/);
      if (m) {
        clearTimeout(timer);
        finish({ ok: m[1] === '200', info: 'CONNECT ' + m[1] });
      }
    });
    socket.once('error', (e) => { clearTimeout(timer); finish({ ok: false, info: e.code || e.message }); });
  });
}

// 展开错误链（fetch -> DOMException -> 底层 socket 错误）
function errorChain(e) {
  const parts = [];
  let cur = e;
  let guard = 0;
  while (cur && guard++ < 5) {
    const code = cur.code ? `${cur.code}:` : '';
    const msg = cur.message || String(cur);
    parts.push(code + msg);
    if (cur.cause && cur.cause !== cur) cur = cur.cause;
    else break;
  }
  return parts.join(' <- ');
}

// 构造带认证的 ProxyAgent（账密认证时自动附带 Proxy-Authorization）
function buildProxyAgent(proxy) {
  const opts = { uri: `http://${proxy}` };
  if (settings.proxy_user) {
    const token = 'Basic ' + Buffer.from(`${settings.proxy_user}:${settings.proxy_pass}`).toString('base64');
    opts.token = token;
  }
  return new ProxyAgent(opts);
}

// 通过 vivo 页面检测单个代理是否可用，返回 { ok, latency, reason }
// 判定标准：HTTP 200 且页面含标记文字，且响应耗时低于设置的延迟阈值
async function checkProxyQuality(proxy) {
  const [host, portStr] = proxy.split(':');
  const port = Number(portStr);

  // 1) 先做原始 TCP 连通性检测，不通则直接判定失败（省去等待 undici 超时）
  const tcp = await rawTcpConnect(host, port);
  if (!tcp.ok) {
    return { ok: false, latency: tcp.ms, reason: `代理不可达 TCP(${tcp.info})` };
  }

  const dispatcher = buildProxyAgent(proxy);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  const started = Date.now();
  try {
    const res = await fetch(CHECK_URL, {
      dispatcher,
      signal: controller.signal,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
      },
    });
    const latency = Date.now() - started;
    if (!res.ok) return { ok: false, latency, reason: `HTTP ${res.status}` };
    const text = await res.text();
    if (latency > settings.maxLatency) {
      return { ok: false, latency, reason: `延迟 ${latency}ms 超过阈值 ${settings.maxLatency}ms` };
    }
    if (!text.includes(CHECK_MARKER)) {
      return { ok: false, latency, reason: '页面未含「vivo账号申诉」' };
    }
    return { ok: true, latency, reason: '通过' };
  } catch (e) {
    const latency = Date.now() - started;
    let reason;
    if (controller.signal.aborted) {
      reason = '超时(15s)';
    } else {
      reason = errorChain(e);
    }
    // 2) fetch 失败时，附带 CONNECT 隧道探测，区分「代理拒隧道」与「vivo 侧断连」
    const diag = await manualConnect('userappeal.vivo.com.cn', 443, host, port);
    reason += `；CONNECT=${diag.ok ? '200 OK' : ('失败:' + diag.info)}`;
    return { ok: false, latency, reason };
  } finally {
    clearTimeout(timer);
    await dispatcher.close().catch(() => {});
  }
}

// 限流并发执行
async function mapWithConcurrency(items, limit, fn) {
  const results = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  }
  const workers = [];
  for (let i = 0; i < Math.min(limit, items.length); i++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

function pruneExpired() {
  const now = Date.now();
  for (let i = pool.length - 1; i >= 0; i--) {
    if (pool[i].expireAt <= now) pool.splice(i, 1);
  }
}

function qualityPoolSize() {
  const now = Date.now();
  let n = 0;
  for (const p of pool) if (p.expireAt > now) n++;
  return n;
}

// 从池中取出最"新鲜"（过期时间最晚，即剩余寿命最长）的可用代理
function takeFreshest(excludeProxy = null) {
  const now = Date.now();
  let best = null;
  let bestIdx = -1;
  for (let i = 0; i < pool.length; i++) {
    const p = pool[i];
    if (p.expireAt <= now) continue;
    if (p.proxy === excludeProxy) continue;
    if (!best || p.expireAt > best.expireAt) {
      best = p;
      bestIdx = i;
    }
  }
  if (bestIdx >= 0) pool.splice(bestIdx, 1);
  return best;
}

// 补充优质 IP 直到池满 N
async function refill() {
  if (refilling) return;
  if (!settings.trade_no || !settings.secret) {
    const msg = '请先在「设置」中填写 trade_no 与 secret';
    lastError = msg;
    log('warn', msg);
    pushStatus();
    return;
  }
  refilling = true;
  pushStatus();
  try {
    // 最多尝试若干轮，避免接口持续无货时死循环
    for (let round = 0; round < 5; round++) {
      await pruneExpired();
      const need = settings.N - qualityPoolSize();
      if (need <= 0) break;

      let batch;
      try {
        batch = await fetchProxies(settings.num);
      } catch (e) {
        const msg = '拉取代理失败：' + e.message;
        lastError = msg;
        log('error', msg);
        break;
      }
      if (!batch || batch.length === 0) {
        const msg = '接口没有返回可用代理（返回为空或格式不符）';
        lastError = msg;
        log('warn', msg);
        break;
      }

      const now = Date.now();
      const candidates = batch.filter((p) => p.expireAt > now);
      if (candidates.length === 0) {
        const msg = '本批代理已全部过期，稍后自动重试';
        lastError = msg;
        log('warn', msg);
        break;
      }

      log('info', `第 ${round + 1} 轮：拉取 ${batch.length} 个代理，${candidates.length} 个未过期，开始并发检测（阈值 ${settings.maxLatency}ms）`);

      let added = 0;
      // 并发检测：通过一个立即入池一个，池满即跳过剩余检测
      await mapWithConcurrency(candidates, 6, async (c) => {
        if (qualityPoolSize() >= settings.N) return; // 池已满，跳过未开始的检测
        const r = await checkProxyQuality(c.proxy);
        if (!r.ok) {
          log('warn', `检测 ${c.proxy} → 未通过（${r.reason}，耗时 ${r.latency}ms）`);
          return;
        }
        if (qualityPoolSize() >= settings.N) return; // 检测期间池已被填满
        if (c.expireAt <= Date.now() || pool.some((x) => x.proxy === c.proxy)) return;
        pool.push(c);
        added++;
        log('ok', `检测 ${c.proxy} → 通过（耗时 ${r.latency}ms），已立即入池 ${qualityPoolSize()}/${settings.N}`);
        pushStatus();
      });

      if (added === 0) {
        const msg = `本批 ${candidates.length} 个代理均未通过质量检测，稍后自动重试`;
        lastError = msg;
        log('warn', msg);
        break;
      }
      log('info', `本批完成，当前池 ${qualityPoolSize()}/${settings.N}`);
    }
  } finally {
    refilling = false;
    pushStatus();
  }
}

// 立即拉取并检测，返回一个可用代理（用于池空时应急）
async function acquireOne() {
  try {
    const batch = await fetchProxies(Math.max(1, settings.num));
    const now = Date.now();
    const candidates = batch.filter((p) => p.expireAt > now);
    if (candidates.length === 0) return null;
    // 并发检测，返回第一个通过的
    let found = null;
    await mapWithConcurrency(candidates, 6, async (c) => {
      if (found) return; // 已找到，跳过未开始的检测
      const r = await checkProxyQuality(c.proxy);
      log(r.ok ? 'ok' : 'warn', `检测 ${c.proxy} → ${r.ok ? '通过' : '未通过'}（${r.reason}，耗时 ${r.latency}ms）`);
      if (r.ok && !found) found = c;
    });
    return found;
  } catch (e) {
    const msg = '拉取代理失败：' + e.message;
    lastError = msg;
    log('error', msg);
    return null;
  }
}

function reloadBrowser() {
  const wc = getBrowserWC();
  if (!wc) return;
  try {
    const url = wc.getURL();
    if (url && url !== '' && url !== 'about:blank') {
      wc.reload();
    }
  } catch (e) { /* 忽略 */ }
}

async function applyProxy(proxy, expireAt) {
  const wc = getBrowserWC();
  if (!wc) return;
  try {
    const ses = wc.session;
    await ses.setProxy({
      proxyRules: `http=${proxy};https=${proxy}`,
      proxyBypassRules: '<local>',
    });
    await ses.closeAllConnections();
  } catch (e) {
    log('warn', '设置代理失败：' + (e.message || e));
  }
  currentProxy = proxy;
  currentExpireAt = expireAt;
  log('info', `已应用代理 ${proxy}，到期 ${new Date(expireAt).toLocaleTimeString('zh-CN', { hour12: false })}`);
  scheduleAutoSwitch();
  pushStatus();
}

function clearAutoSwitch() {
  if (switchTimer) {
    clearTimeout(switchTimer);
    switchTimer = null;
  }
}

// 清除代理、回退直连（拿不到新 IP 时保证页面仍能访问）
async function clearProxy() {
  const wc = getBrowserWC();
  if (wc) {
    try {
      const ses = wc.session;
      await ses.setProxy({ mode: 'direct' });
      await ses.closeAllConnections();
    } catch (e) { /* 忽略 */ }
  }
  currentProxy = null;
  currentExpireAt = null;
  clearAutoSwitch();
  log('warn', '已清除代理，回退直连');
  pushStatus();
}

function scheduleAutoSwitch() {
  clearAutoSwitch();
  if (!currentExpireAt) return;
  const delay = currentExpireAt - Date.now() - EXPIRE_SWITCH_SECONDS * 1000;
  if (delay > 0) {
    switchTimer = setTimeout(autoSwitch, delay);
  } else {
    autoSwitch();
  }
}

async function autoSwitch() {
  switchTimer = null;
  await swapProxy({ reload: false });
}

// 从池中取一个新 IP 应用（reload 决定是否刷新页面）
async function swapProxy({ reload = false } = {}) {
  if (swapping) return;
  swapping = true;
  pushStatus();
  try {
    await pruneExpired();
    let pick = takeFreshest(currentProxy);
    if (!pick) {
      pick = await acquireOne();
    }

    if (!pick) {
      // 拿不到新 IP：若当前代理已失效则回退直连，保证页面始终能打开
      const curExpired = !currentProxy || !currentExpireAt || Date.now() >= currentExpireAt;
      if (curExpired) {
        await clearProxy();
        reloadBrowser();
      }
      const msg = '暂无可用代理' + (curExpired ? '，已回退直连' : '');
      lastError = msg;
      log('warn', msg);
      pushStatus();
      setTimeout(() => { refill(); swapProxy({ reload }); }, 5000);
      return;
    }

    await applyProxy(pick.proxy, pick.expireAt);
    refill(); // 后台补满池
    if (reload) reloadBrowser();
  } finally {
    swapping = false;
    pushStatus();
  }
}

// ---------------- 状态推送 ----------------
function buildStatus() {
  return {
    currentProxy,
    currentExpireAt,
    poolSize: qualityPoolSize(),
    targetN: settings.N,
    refilling,
    swapping,
    lastError,
    configured: !!(settings.trade_no && settings.secret),
  };
}

function pushStatus() {
  sendToRenderer('pool-status', buildStatus());
}

// ---------------- 维护循环 ----------------
function startMaintenance() {
  stopMaintenance();
  maintenanceTimer = setInterval(() => {
    pruneExpired();
    // 当前代理已到期，立即切换
    if (currentProxy && currentExpireAt && Date.now() >= currentExpireAt) {
      swapProxy();
      return;
    }
    // 池低于 N 时补充
    if (qualityPoolSize() < settings.N) {
      refill();
    }
    pushStatus();
  }, 500);
}

function stopMaintenance() {
  if (maintenanceTimer) {
    clearInterval(maintenanceTimer);
    maintenanceTimer = null;
  }
}

// 启动时：读设置、开维护、等待第一个优质 IP 后应用并打开首页
async function initProxyPool() {
  loadSettings();
  log('info', `启动：trade_no=${settings.trade_no ? '已填' : '未填'}，secret=${settings.secret ? '已填' : '未填'}，num=${settings.num}，N=${settings.N}，延迟阈值=${settings.maxLatency}ms，代理账密=${settings.proxy_user ? '已填' : '未填'}`);
  pushStatus();
  startMaintenance();
  refill();

  // 最多等约 20 秒拿到第一个优质 IP
  for (let i = 0; i < 40; i++) {
    await pruneExpired();
    const pick = takeFreshest();
    if (pick) {
      await applyProxy(pick.proxy, pick.expireAt);
      refill();
      break;
    }
    await sleep(500);
  }

  const wc0 = getBrowserWC();
  if (wc0) wc0.loadURL(DEFAULT_URL).catch(() => {});
}

// ---------------- 窗口 ----------------
function layoutBrowserView() {
  if (!mainWindow || mainWindow.isDestroyed() || !browserView) return;
  const [width, height] = mainWindow.getContentSize();
  const bottomInset = logOpen ? LOG_HEIGHT : 0;
  browserView.setBounds({
    x: 0,
    y: TOOLBAR_HEIGHT,
    width,
    height: Math.max(0, height - TOOLBAR_HEIGHT - bottomInset),
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    title: 'vivo无限查询',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  browserView = new WebContentsView({
    webPreferences: { partition: PARTITION },
  });

  mainWindow.contentView.addChildView(browserView);
  layoutBrowserView();
  mainWindow.on('resize', layoutBrowserView);

  const wc = browserView.webContents;

  // 使用桌面 Chrome UA，避免站点按移动端/Electron 识别导致页面异常放大或布局错乱
  wc.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  // 锁定手势（捏合）缩放，页面缩放统一走 zoomFactor
  wc.setVisualZoomLevelLimits(0, 0);

  // 每次导航都强制应用当前缩放比例，忽略持久会话记忆的旧缩放（清理自动缩放）
  const applyZoom = () => {
    const cur = getBrowserWC();
    if (!cur) return;
    try { cur.setZoomFactor(zoomFactor); } catch (e) { /* 忽略 */ }
  };
  wc.on('did-navigate', applyZoom);
  wc.on('did-navigate-in-page', applyZoom);
  wc.on('did-finish-load', applyZoom);

  // 代理账密认证：当浏览器通过代理收到 407 时，自动用设置的账号密码应答
  wc.session.on('login', (event, webContents, details, authInfo, callback) => {
    if (authInfo.isProxy && settings.proxy_user) {
      callback(settings.proxy_user, settings.proxy_pass);
    } else {
      callback();
    }
  });

  wc.on('did-navigate', (_e, url) => sendToRenderer('url-changed', url));
  wc.on('did-navigate-in-page', (_e, url) => sendToRenderer('url-changed', url));
  wc.on('did-start-loading', () => sendToRenderer('loading', true));
  wc.on('did-stop-loading', () => sendToRenderer('loading', false));
  wc.on('did-fail-load', (_e, errorCode, errorDescription, validatedURL, isMainFrame) => {
    if (isMainFrame && errorCode !== -3) {
      sendToRenderer('load-error', { errorCode, errorDescription, validatedURL });
    }
  });

  wc.setWindowOpenHandler(({ url }) => {
    const cur = getBrowserWC();
    if (cur) cur.loadURL(url).catch(() => {});
    return { action: 'deny' };
  });

  mainWindow.loadFile('index.html');
}

app.whenReady().then(() => {
  createWindow();
  initProxyPool();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// ---------------- IPC ----------------
ipcMain.handle('navigate', async (_e, url) => {
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const cur = getBrowserWC();
  if (cur) cur.loadURL(url).catch(() => {});
  return { ok: true };
});

// 手动刷新：后台换一个 IP 并刷新页面，立即返回，避免按钮长时间置灰
ipcMain.handle('refresh-proxy', () => {
  swapProxy({ reload: true }).catch((e) => log('error', '刷新失败：' + (e && e.message ? e.message : e)));
  return { ok: true };
});

ipcMain.handle('get-settings', () => settings);

ipcMain.handle('save-settings', async (_e, next) => {
  const saved = saveSettings(next);
  // 设置变化后重建池（清空旧 IP），保留当前代理直到下一次切换
  pool.length = 0;
  lastError = null;
  startMaintenance();
  refill();
  pushStatus();
  return saved;
});

ipcMain.handle('get-current-url', () => {
  const cur = getBrowserWC();
  return cur ? cur.getURL() : '';
});

ipcMain.handle('get-status', () => buildStatus());

// 设置面板打开时隐藏浏览器视图，避免遮挡设置弹窗
ipcMain.handle('set-settings-open', (_e, open) => {
  if (browserView) {
    try { browserView.setVisible(!open); } catch (e) { /* 忽略 */ }
  }
  return { ok: true };
});

// 日志面板开关：调整浏览器视图高度，给底部日志面板留出空间
ipcMain.handle('set-log-open', (_e, open) => {
  logOpen = !!open;
  layoutBrowserView();
  return { ok: true };
});

// 返回已有日志，供渲染进程启动时回填
ipcMain.handle('get-logs', () => logs);

// ---------------- 缩放 ----------------
ipcMain.handle('get-zoom', () => zoomFactor);

ipcMain.handle('zoom-by', (_e, delta) => {
  const d = Number(delta);
  if (!Number.isNaN(d)) zoomFactor = Math.min(3, Math.max(0.5, zoomFactor + d));
  const cur = getBrowserWC();
  if (cur) { try { cur.setZoomFactor(zoomFactor); } catch (e) { /* 忽略 */ } }
  return zoomFactor;
});

ipcMain.handle('zoom-reset', () => {
  zoomFactor = 1.0;
  const cur = getBrowserWC();
  if (cur) { try { cur.setZoomFactor(zoomFactor); } catch (e) { /* 忽略 */ } }
  return zoomFactor;
});
