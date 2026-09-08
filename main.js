const { app, BrowserWindow, WebContentsView, ipcMain, session } = require('electron');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { spawn } = require('child_process');
const { fetch, ProxyAgent } = require('undici');

// ---------------- 常量 ----------------
const CHECK_MARKER = 'vivo账号申诉';

// 验证码图片/JS 来自 captcha.vivo.com.cn（与 userappeal 不同源），
// 质量检测需单独探测该域名，避免留下「userappeal 快、验证码慢/被墙」的 IP
const CAPTCHA_CHECK_URL = 'https://captcha.vivo.com.cn/dx-captcha/sdk/dingxiang-sdk.js';
const CAPTCHA_HOST = 'captcha.vivo.com.cn'; // 验证码源站主机（用于直连旁路规则）
const RISK_PATH = '/userappeal/v1/getSliderUrl'; // 风控闸口请求路径（仅风控代理模式匹配）
const DEFAULT_IP_LIFETIME_MS = 5 * 60 * 1000; // 供应商未返回过期时间时（如 rox）默认 IP 寿命（5 分钟）

// 浏览器内容使用独立的持久化 session，方便单独设置代理
const PARTITION = 'persist:proxysession';

// 顶部工具栏高度（与 index.html 中 #toolbar 的高度保持一致）
const TOOLBAR_HEIGHT = 51;

// 日志面板高度（与 index.html 中 #logPanel 的高度保持一致）
const LOG_HEIGHT = 200;

// 启动后默认打开的主页
const DEFAULT_URL = 'https://userappeal.vivo.com.cn/#/index';

// 距离到期提前多少秒自动换 IP
const EXPIRE_SWITCH_SECONDS = 5;

// 本地 MITM 代理与控制服务端口（页面请求走 curl_cffi 随机指纹转发）
const LOCAL_PROXY_PORT = 8899;
const CONTROL_PORT = 8898;

// 忽略证书错误：让 Chromium 接受本地 MITM 代理签发的自签名证书
app.commandLine.appendSwitch('ignore-certificate-errors');

// 兜底：`ignore-certificate-errors` 开关对自定义 partition 的 WebContentsView
// 经常不生效（见 electron#31596），导致所有 HTTPS 页面都因证书校验失败而打不开。
// 这里用 certificate-error 事件显式放行，确保 MITM 自签名证书能被接受。
app.on('certificate-error', (event, _webContents, _url, _error, _certificate, callback) => {
  event.preventDefault();
  callback(true);
});

// ---------------- 本地指纹代理（Python curl_cffi） ----------------
let pythonProc = null;
let quitting = false; // 是否正在退出（退出时不自动重启 sidecar）

// 解析本地指纹代理的启动命令：打包后（Windows）优先用打包进来的 curlffi_proxy.exe，
// 无需本机 Python；开发环境走 .venv 的 python + 脚本。
function resolvePythonLauncher() {
  if (app.isPackaged) {
    const sidecar = path.join(process.resourcesPath, 'sidecar', 'curlffi_proxy.exe');
    if (process.platform === 'win32' && fs.existsSync(sidecar)) {
      return { exe: sidecar, script: null };
    }
  }
  const script = path.join(__dirname, 'curlffi_proxy.py');
  const venvPy = process.platform === 'win32'
    ? path.join(__dirname, '.venv', 'Scripts', 'python.exe')
    : path.join(__dirname, '.venv', 'bin', 'python');
  if (fs.existsSync(venvPy)) return { exe: venvPy, script };
  return { exe: process.platform === 'win32' ? 'python' : 'python3', script };
}

function startPythonProxy() {
  const { exe, script } = resolvePythonLauncher();
  if (script && !fs.existsSync(script)) {
    log('error', '找不到 curlffi_proxy.py，请确认该文件与 main.js 同级');
    return;
  }
  const args = ['--serve-only', '--port', String(LOCAL_PROXY_PORT), '--control-port', String(CONTROL_PORT)];
  if (script) args.unshift(script);
  log('info', `启动本地指纹代理：${exe} ${script || ''}`.trim());
  try {
    // Windows 上强制 sidecar 以 UTF-8 输出，避免 GBK/UTF-8 混用导致日志乱码
    const env = { ...process.env };
    if (process.platform === 'win32') {
      env.PYTHONIOENCODING = 'utf-8';
      env.PYTHONUTF8 = '1';
    }
    pythonProc = spawn(exe, args, {
      stdio: ['ignore', 'pipe', 'pipe'],
      cwd: app.getPath('userData'), // CA 证书生成到可写目录
      windowsHide: true,            // 隐藏打包后 sidecar 的控制台窗口
      env,
    });

    // 把 Python 代理的 stdout/stderr 转发到日志面板（去掉重复的 [proxy] 前缀）
    const forwardLines = (data, level) => {
      String(data).split(/\r?\n/).forEach((raw) => {
        const line = raw.replace(/^\[proxy\]\s*/, '').trim();
        if (line) log(level, line);
      });
    };
    pythonProc.stdout.on('data', (d) => forwardLines(d, 'proxy'));
    pythonProc.stderr.on('data', (d) => forwardLines(d, 'error'));

    pythonProc.on('exit', (code) => {
      const dead = pythonProc;
      pythonProc = null;
      if (dead) log('warn', `本地指纹代理已退出（code=${code}）`);
      // 崩溃/意外退出时自动重启，避免打包后的 Windows 版因 sidecar 挂掉而所有页面打不开
      if (!quitting) {
        log('info', '3 秒后自动重启本地指纹代理…');
        setTimeout(() => { if (!quitting && !pythonProc) startPythonProxy(); }, 3000);
      }
    });
    pythonProc.on('error', (e) => {
      log('error', '本地指纹代理启动失败：' + (e.message || e));
      pythonProc = null;
    });
  } catch (e) {
    log('error', '本地指纹代理启动失败：' + (e.message || e));
  }
}

function stopPythonProxy() {
  if (pythonProc) {
    try { pythonProc.kill(); } catch (e) { /* 忽略 */ }
    pythonProc = null;
  }
}

// 设置/清除本地代理的上游（即 91http/rox 代理）；页面请求由本地代理经 curl_cffi 转发
// upstream 形如 { proxy: "host:port", user, pass }，null 表示清除（直连）
async function setControlUpstream(upstream) {
  const payload = upstream
    ? { proxy: upstream.proxy, user: upstream.user || '', pass: upstream.pass || '' }
    : { proxy: null };
  try {
    const res = await fetch(`http://127.0.0.1:${CONTROL_PORT}/upstream`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      log('info', upstream ? `上游代理已切换：${upstream.proxy}` : '上游代理已清除（直连）');
    } else {
      log('warn', '设置上游代理失败：HTTP ' + res.status);
    }
  } catch (e) {
    log('warn', '设置上游代理失败：' + (e.message || e));
  }
}

// 等待本地指纹代理控制服务就绪：sidecar 从 spawn 到绑定端口需要约 1 秒，
// 若在此之前就 loadURL，页面会因连不上 127.0.0.1:8899 而直接失败且无自动重试。
async function waitForSidecarReady(timeoutMs = 8000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`http://127.0.0.1:${CONTROL_PORT}/ping`, { signal: AbortSignal.timeout(500) });
      if (res.ok) return true;
    } catch (e) { /* 尚未就绪，继续等待 */ }
    await sleep(200);
  }
  return false;
}

// ---------------- 设置 ----------------
const DEFAULT_SETTINGS = {
  provider: '91http', // 代理供应商：91http / rox
  extract_url: '',    // 91http 提取链接（完整 URL，参数由用户在链接内配置）
  rox_host: '',       // rox 代理主机
  rox_port: '',       // rox 代理端口
  rox_username: '',   // rox 账号（含 sessid，切换 IP 时随机化其后 8 位）
  rox_password: '',   // rox 密码
  N: 5,         // 优质 IP 池目标大小
  maxLatency: 2000, // 质量检测延迟阈值（毫秒），低于该值视为优质
  check_url: '', // 质量检测网址（留空则不检测域名，仅判定代理 TCP 可达）
  proxy_user: '',  // 代理账号（账密认证用）
  proxy_pass: '',  // 代理密码
  use_curlffi: true, // 是否使用 curl_cffi 做请求中转（TLS 指纹伪装）
  captcha_direct: false, // 验证码域名是否直连（绕过代理），用于加快验证码图片加载
  direct: false, // 直连模式：浏览器与 curl_cffi 转发都不走 91http 代理
  risk_proxy_only: false, // 仅风控代理：只有 getSliderUrl 走 curl_cffi 动态代理，其余直连
  auto_switch_ip: true, // 是否自动换 IP（到期 / 风控）
  max_auto_switch: 0,   // 最大自动切换数量，0 表示不限
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
      provider: parsed.provider === 'rox' ? 'rox' : '91http',
      extract_url: String(parsed.extract_url ?? DEFAULT_SETTINGS.extract_url).trim(),
      rox_host: String(parsed.rox_host ?? DEFAULT_SETTINGS.rox_host).trim(),
      rox_port: String(parsed.rox_port ?? DEFAULT_SETTINGS.rox_port).trim(),
      rox_username: String(parsed.rox_username ?? DEFAULT_SETTINGS.rox_username).trim(),
      rox_password: String(parsed.rox_password ?? DEFAULT_SETTINGS.rox_password).trim(),
      N: clampInt(parsed.N, 1, 200),
      maxLatency: clampInt(parsed.maxLatency, 100, 15000),
      check_url: String(parsed.check_url ?? DEFAULT_SETTINGS.check_url).trim(),
      proxy_user: String(parsed.proxy_user ?? DEFAULT_SETTINGS.proxy_user).trim(),
      proxy_pass: String(parsed.proxy_pass ?? DEFAULT_SETTINGS.proxy_pass).trim(),
      use_curlffi: parsed.use_curlffi !== false,
      captcha_direct: !!parsed.captcha_direct,
      direct: !!parsed.direct,
      risk_proxy_only: !!parsed.risk_proxy_only,
      auto_switch_ip: parsed.auto_switch_ip !== false,
      max_auto_switch: clampInt(parsed.max_auto_switch, 0, 100000),
    };
  } catch (e) {
    settings = { ...DEFAULT_SETTINGS };
  }
}

function saveSettings(next) {
  settings = {
    ...settings,
    provider: next.provider === undefined ? settings.provider : (next.provider === 'rox' ? 'rox' : '91http'),
    extract_url: String(next.extract_url ?? settings.extract_url).trim(),
    rox_host: String(next.rox_host ?? settings.rox_host).trim(),
    rox_port: String(next.rox_port ?? settings.rox_port).trim(),
    rox_username: String(next.rox_username ?? settings.rox_username).trim(),
    rox_password: String(next.rox_password ?? settings.rox_password).trim(),
    N: clampInt(next.N ?? settings.N, 1, 200),
    maxLatency: clampInt(next.maxLatency ?? settings.maxLatency, 100, 15000),
    check_url: String(next.check_url ?? settings.check_url).trim(),
    proxy_user: String(next.proxy_user ?? settings.proxy_user).trim(),
    proxy_pass: String(next.proxy_pass ?? settings.proxy_pass).trim(),
    use_curlffi: next.use_curlffi === undefined ? settings.use_curlffi : !!next.use_curlffi,
    captcha_direct: next.captcha_direct === undefined ? settings.captcha_direct : !!next.captcha_direct,
    direct: next.direct === undefined ? settings.direct : !!next.direct,
    risk_proxy_only: next.risk_proxy_only === undefined ? settings.risk_proxy_only : !!next.risk_proxy_only,
    auto_switch_ip: next.auto_switch_ip === undefined ? settings.auto_switch_ip : !!next.auto_switch_ip,
    max_auto_switch: clampInt(next.max_auto_switch ?? settings.max_auto_switch, 0, 100000),
  };
  try {
    fs.mkdirSync(app.getPath('userData'), { recursive: true });
    fs.writeFileSync(settingsPath(), JSON.stringify(settings, null, 2), 'utf8');
  } catch (e) { /* 忽略写入错误 */ }
  return settings;
}

// ---------------- 代理池 ----------------
const pool = [];          // { proxy: "ip:port", expireAt: 毫秒时间戳 }
let currentProxy = null;  // 当前应用到浏览器的 "host:port"
let currentAuth = null;   // 当前代理的账密 { user, pass }
let currentExpireAt = null;
let refilling = false;
let swapping = false;
let lastError = null;
let switchTimer = null;
let maintenanceTimer = null;
let autoSwitchCount = 0; // 本次会话已自动换 IP 次数

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

// rox 会话随机字符集：大小写 + 数字
const ROX_SESSID_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// 随机化账号中 sessid 字段的最后 8 位（用于 rox 切换 IP）
function rotateRoxSession(username) {
  // 账号形如 ...-sessid-<VALUE>-...，把 <VALUE> 的最后 8 位换成随机大小写+数字
  const m = username.match(/^(.*-sessid-)([A-Za-z0-9]+)(-.*)$/);
  if (!m) return username;
  const sessid = m[2];
  if (sessid.length < 8) return username;
  const keep = sessid.slice(0, sessid.length - 8);
  let tail = '';
  for (let i = 0; i < 8; i++) {
    tail += ROX_SESSID_CHARS[Math.floor(Math.random() * ROX_SESSID_CHARS.length)];
  }
  return m[1] + keep + tail + m[3];
}

// 91代理：兼容两种返回格式，账密共用 proxy_user/pass。
// 1) 文本格式，每行 ip:port:YYYY-MM-DD HH:MM:SS
// 2) JSON 格式：{ code, msg, data: { proxy_list: [{ ip, port, expire_time, ... }] } }
function parse91Proxies(text) {
  const list = [];
  const user = settings.proxy_user || '';
  const pass = settings.proxy_pass || '';

  const push = (ip, port, expireTime) => {
    if (!ip || port == null) return;
    const proxy = `${ip}:${port}`;
    const expireAt = expireTime
      ? new Date(String(expireTime).replace(' ', 'T')).getTime()
      : 0;
    if (!Number.isNaN(expireAt)) list.push({ proxy, user, pass, expireAt });
  };

  // 优先按 JSON 解析
  const trimmed = text.trim();
  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed);
      const items = obj && obj.data && Array.isArray(obj.data.proxy_list) ? obj.data.proxy_list : null;
      if (items) {
        for (const it of items) {
          push(it.ip, it.port, it.expire_time);
        }
        return list;
      }
    } catch (e) { /* 不是合法 JSON，回退到文本解析 */ }
  }

  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    // 返回格式：ip:port:YYYY-MM-DD HH:MM:SS
    const m = line.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+):(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$/);
    if (!m) continue;
    push(m[1], m[2], m[3]);
  }
  return list;
}

// rox代理：根据账号 sessid 随机化生成 count 个不同 IP 的代理
function generateRoxProxies(count) {
  const host = settings.rox_host.trim();
  const port = Number(settings.rox_port);
  const baseUser = settings.rox_username.trim();
  const pass = settings.rox_password;
  if (!host || !Number.isFinite(port) || port <= 0 || !baseUser) return [];
  const expireAt = Date.now() + DEFAULT_IP_LIFETIME_MS;
  const list = [];
  for (let i = 0; i < count; i++) {
    list.push({ proxy: `${host}:${port}`, user: rotateRoxSession(baseUser), pass, expireAt });
  }
  return list;
}

// 按供应商获取一批代理，返回 [{ proxy, user, pass, expireAt }]
async function fetchProxies(count = 1) {
  if (settings.provider === 'rox') {
    return generateRoxProxies(count);
  }
  // 91代理：抓取提取链接
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20000);
  try {
    const res = await fetch(settings.extract_url, { signal: controller.signal });
    if (!res.ok) throw new Error(`接口返回 HTTP ${res.status}`);
    const text = (await res.text()).trim();
    if (!text) return [];
    return parse91Proxies(text);
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
function manualConnect(targetHost, targetPort, proxyHost, proxyPort, user = '', pass = '', timeoutMs = 4000) {
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
      if (user) {
        const token = Buffer.from(`${user}:${pass}`).toString('base64');
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
function buildProxyAgent(item) {
  const opts = { uri: `http://${item.proxy}` };
  if (item.user) {
    const token = 'Basic ' + Buffer.from(`${item.user}:${item.pass}`).toString('base64');
    opts.token = token;
  }
  return new ProxyAgent(opts);
}

// 检测单个代理是否可用，返回 { ok, latency, reason }
// 判定标准：TCP 可达；若设置了检测网址（settings.check_url），还需 HTTP 2xx、
// 响应耗时低于延迟阈值；检测网址为 vivo 业务站时额外校验页面标记与验证码源站
async function checkProxyQuality(item) {
  const [host, portStr] = item.proxy.split(':');
  const port = Number(portStr);

  // 1) 先做原始 TCP 连通性检测，不通则直接判定失败（省去等待 undici 超时）
  const tcp = await rawTcpConnect(host, port);
  if (!tcp.ok) {
    return { ok: false, latency: tcp.ms, reason: `代理不可达 TCP(${tcp.info})` };
  }

  // 2) 未配置检测网址：不检测域名，仅判定代理 TCP 可达即合格
  const checkUrl = String(settings.check_url || '').trim();
  if (!checkUrl) {
    return { ok: true, latency: tcp.ms, reason: '通过（未配置检测网址，仅 TCP 可达）' };
  }
  // 仅当检测 vivo 业务站时，才做页面标记校验与验证码域名探测
  const isVivo = /userappeal\.vivo\.com\.cn/.test(checkUrl);

  const dispatcher = buildProxyAgent(item);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), settings.maxLatency);
  const started = Date.now();
  try {
    const res = await fetch(checkUrl, {
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
    if (isVivo && !text.includes(CHECK_MARKER)) {
      return { ok: false, latency, reason: '页面未含「vivo账号申诉」' };
    }

    // 验证码图片来自 captcha.vivo.com.cn，单独探测该域名可达性与延迟（仅 vivo 业务站）
    if (isVivo) {
      const capController = new AbortController();
      const capTimer = setTimeout(() => capController.abort(), settings.maxLatency);
      let capOk = false;
      let capLatency = 0;
      let capReason = '';
      try {
        const capRes = await fetch(CAPTCHA_CHECK_URL, {
          dispatcher,
          signal: capController.signal,
          headers: {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36',
          },
        });
        capLatency = Date.now() - started;
        if (!capRes.ok) {
          capReason = `验证码服务器 HTTP ${capRes.status}`;
        } else {
          await capRes.text();
          if (capLatency > settings.maxLatency) {
            capReason = `验证码服务器延迟 ${capLatency}ms 超过阈值`;
          } else {
            capOk = true;
          }
        }
      } catch (e) {
        capLatency = Date.now() - started;
        capReason = capController.signal.aborted
          ? `验证码服务器超时(${settings.maxLatency}ms)`
          : errorChain(e);
      } finally {
        clearTimeout(capTimer);
      }
      if (!capOk) return { ok: false, latency: capLatency, reason: capReason };
    }

    return { ok: true, latency, reason: '通过' };
  } catch (e) {
    const latency = Date.now() - started;
    let reason;
    if (controller.signal.aborted) {
      reason = `超时(${settings.maxLatency}ms)`;
    } else {
      reason = errorChain(e);
    }
    // 2) fetch 失败时，附带 CONNECT 隧道探测，区分「代理拒隧道」与「目标站点侧断连」
    let diagHost = 'userappeal.vivo.com.cn';
    try { diagHost = new URL(checkUrl).hostname; } catch (e) { /* 忽略 */ }
    const diag = await manualConnect(diagHost, 443, host, port, item.user, item.pass);
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

// 代理唯一身份：rox 的多个出口 IP 共享同一 host:port，靠账号中的 sessid 区分，
// 因此身份需包含 user；91http 的 user 可共用/为空，此时退化为 host:port。
function proxyId(item) {
  return `${item.proxy}|${item.user || ''}`;
}

// 从池中取出最"新鲜"（过期时间最晚，即剩余寿命最长）的可用代理
function takeFreshest(excludeId = null) {
  const now = Date.now();
  let best = null;
  let bestIdx = -1;
  for (let i = 0; i < pool.length; i++) {
    const p = pool[i];
    if (p.expireAt <= now) continue;
    if (excludeId && proxyId(p) === excludeId) continue;
    if (!best || p.expireAt > best.expireAt) {
      best = p;
      bestIdx = i;
    }
  }
  if (bestIdx >= 0) pool.splice(bestIdx, 1);
  return best;
}

function isConfigured() {
  if (settings.provider === 'rox') {
    return !!(settings.rox_host && settings.rox_port && settings.rox_username);
  }
  return !!settings.extract_url;
}

// 补充优质 IP 直到池满 N
async function refill() {
  if (refilling) return;
  if (settings.direct) return; // 直连模式不拉取代理
  if (!settings.auto_switch_ip) return; // 自动换 IP 关闭时不自动补池，仅手动刷新时获取
  if (!isConfigured()) {
    const msg = settings.provider === 'rox'
      ? '请先在「设置」中填写 rox 的主机、端口与账号'
      : '请先在「设置」中填写提取链接';
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
        batch = await fetchProxies(need);
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
      let failed = 0;
      let dupSkipped = 0;
      // 并发检测：通过一个立即入池一个，池满即跳过剩余检测
      await mapWithConcurrency(candidates, 6, async (c) => {
        if (qualityPoolSize() >= settings.N) return; // 池已满，跳过未开始的检测
        const r = await checkProxyQuality(c);
        if (!r.ok) {
          failed++;
          log('warn', `检测 ${c.proxy} → 未通过（${r.reason}，耗时 ${r.latency}ms）`);
          return;
        }
        if (qualityPoolSize() >= settings.N) return; // 检测期间池已被填满
        if (c.expireAt <= Date.now()) return; // 已过期
        if (pool.some((x) => proxyId(x) === proxyId(c))) {
          dupSkipped++;
          return;
        }
        pool.push(c);
        added++;
        log('ok', `检测 ${c.proxy} → 通过（耗时 ${r.latency}ms），已立即入池 ${qualityPoolSize()}/${settings.N}`);
        pushStatus();
      });

      if (added === 0) {
        const msg = failed > 0
          ? `本批 ${candidates.length} 个代理均未通过质量检测（${failed} 个检测失败），稍后自动重试`
          : (dupSkipped > 0
            ? `本批 ${candidates.length} 个代理均为重复 IP（${dupSkipped} 个去重跳过），稍后自动重试`
            : `本批 ${candidates.length} 个代理未能入池（池已满或已过期），稍后自动重试`);
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
    const batch = await fetchProxies(Math.max(1, settings.N));
    const now = Date.now();
    const candidates = batch.filter((p) => p.expireAt > now);
    if (candidates.length === 0) return null;
    // 并发检测，返回第一个通过的
    let found = null;
    await mapWithConcurrency(candidates, 6, async (c) => {
      if (found) return; // 已找到，跳过未开始的检测
      const r = await checkProxyQuality(c);
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
    } else {
      // 页面尚未成功导航（如启动时 sidecar 未就绪导致首屏失败），重新打开主页
      wc.loadURL(DEFAULT_URL).catch(() => {});
    }
  } catch (e) { /* 忽略 */ }
}

// 当前代理的上游信息（含账密），供本地 curl_cffi 代理设置上游
function currentUpstream() {
  if (!currentProxy) return null;
  return { proxy: currentProxy, user: currentAuth ? currentAuth.user : '', pass: currentAuth ? currentAuth.pass : '' };
}

// 当前代理的唯一身份（含 sessid），用于从池中排除「正在使用」的那个 IP
function currentProxyId() {
  if (!currentProxy) return '';
  return proxyId({ proxy: currentProxy, user: currentAuth ? currentAuth.user : '' });
}

// 生成 PAC 脚本：仅让风控闸口请求（getSliderUrl）走本地 curl_cffi 动态代理，其余直连
function buildRiskPacScript() {
  const pac = [
    'function FindProxyForURL(url, host) {',
    `  if (url.indexOf('${RISK_PATH}') !== -1) {`,
    `    return 'PROXY 127.0.0.1:${LOCAL_PROXY_PORT}';`,
    '  }',
    "  return 'DIRECT';",
    '}',
  ].join('\n');
  return 'data:application/x-ns-proxy-autoconfig;base64,' + Buffer.from(pac, 'utf8').toString('base64');
}

// 按开关决定浏览器请求走向：走 curl_cffi 本地中转，或直连 91http 上游代理；
// captcha_direct 开启时，验证码域名直连（绕过代理），加快验证码图片加载；
// direct 开启时，浏览器与 curl_cffi 转发都不走 91http 代理（纯直连）；
// risk_proxy_only 开启时，仅风控闸口请求走 curl_cffi 动态代理，其余直连
async function applyBrowserProxy() {
  const wc = getBrowserWC();
  if (!wc) return;
  const bypass = settings.captcha_direct
    ? `<local>;*.${CAPTCHA_HOST}`
    : '<local>';

  // 直连模式：不经过 91http 代理（最高优先级）
  if (settings.direct) {
    if (settings.use_curlffi) {
      // 仍经本地 curl_cffi 做 TLS 指纹伪装，但上游清空 → 直连源站
      await wc.session.setProxy({
        proxyRules: `http=127.0.0.1:${LOCAL_PROXY_PORT};https=127.0.0.1:${LOCAL_PROXY_PORT}`,
        proxyBypassRules: bypass,
      }).catch((e) => log('warn', '设置本地代理失败：' + (e.message || e)));
    } else {
      // 浏览器完全直连，不经 curl_cffi
      await wc.session.setProxy({ mode: 'direct' })
        .catch((e) => log('warn', '设置直连失败：' + (e.message || e)));
    }
    await setControlUpstream(null); // curl_cffi 上游清空 → 直连
    return;
  }

  // 仅风控代理模式：只有 getSliderUrl 走 curl_cffi 动态代理，其余请求直连
  if (settings.risk_proxy_only) {
    await wc.session.setProxy({
      mode: 'pac_script',
      pacScript: buildRiskPacScript(),
    }).catch((e) => log('warn', '设置 PAC 代理失败：' + (e.message || e)));
    await setControlUpstream(currentUpstream()); // curl_cffi 上游 = 动态代理
    return;
  }

  // 正常模式：走 91http 代理
  if (settings.use_curlffi) {
    // 走本地 MITM 代理，由 curl_cffi 随机指纹转发到上游 91http
    await wc.session.setProxy({
      proxyRules: `http=127.0.0.1:${LOCAL_PROXY_PORT};https=127.0.0.1:${LOCAL_PROXY_PORT}`,
      proxyBypassRules: bypass,
    }).catch((e) => log('warn', '设置本地代理失败：' + (e.message || e)));
    await setControlUpstream(currentUpstream());
  } else {
    // 不经 curl_cffi：浏览器直连 91http 上游代理（Chromium 自身 TLS）
    if (currentProxy) {
      await wc.session.setProxy({
        proxyRules: `http=${currentProxy};https=${currentProxy}`,
        proxyBypassRules: bypass,
      }).catch((e) => log('warn', '设置直连上游代理失败：' + (e.message || e)));
    } else {
      await wc.session.setProxy({ mode: 'direct' })
        .catch((e) => log('warn', '清除代理失败：' + (e.message || e)));
    }
  }
}

// 清空内嵌浏览器的所有缓存与站点数据（HTTP 缓存、认证缓存、DNS 缓存、Cookie、
// localStorage、IndexedDB、Service Worker、Cache Storage 等）。切换代理前调用，
// 让新 IP 以全新身份访问站点，避免残留旧 IP 的 Cookie/存储数据被站点关联或复用。
async function clearBrowserCache() {
  const ses = session.fromPartition(PARTITION);
  try {
    await ses.clearCache();
    await ses.clearAuthCache();
    await ses.clearHostResolverCache();
    await ses.clearStorageData({
      storages: ['cookies', 'indexdb', 'localstorage', 'shadercache', 'websql', 'serviceworkers', 'cachestorage', 'filesystem'],
    });
    log('info', '已清空浏览器缓存与站点数据');
    return true;
  } catch (e) {
    log('warn', '清空浏览器缓存失败：' + (e.message || e));
    return false;
  }
}

async function applyProxy(item) {
  // 切换代理前先清空浏览器缓存/站点数据，让新 IP 以全新身份访问
  await clearBrowserCache();
  currentProxy = item.proxy;
  currentAuth = { user: item.user || '', pass: item.pass || '' };
  currentExpireAt = item.expireAt;
  log('info', `已应用代理 ${item.proxy}，到期 ${new Date(item.expireAt).toLocaleTimeString('zh-CN', { hour12: false })}`);
  await applyBrowserProxy();
  scheduleAutoSwitch();
  pushStatus();
}

function clearAutoSwitch() {
  if (switchTimer) {
    clearTimeout(switchTimer);
    switchTimer = null;
  }
}

// 是否允许自动换 IP（开关 + 数量上限）
function canAutoSwitch() {
  if (!settings.auto_switch_ip) return false;
  if (settings.max_auto_switch > 0 && autoSwitchCount >= settings.max_auto_switch) return false;
  return true;
}

// 记录一次自动换 IP（计数 + 状态推送）
function markAutoSwitch() {
  autoSwitchCount++;
  const cap = settings.max_auto_switch > 0 ? `，上限 ${settings.max_auto_switch} 次` : '';
  log('info', `自动换 IP：本次会话第 ${autoSwitchCount} 次${cap}`);
  pushStatus();
}

// 清除代理、回退直连（拿不到新 IP 时保证页面仍能访问）
async function clearProxy() {
  currentProxy = null;
  currentAuth = null;
  currentExpireAt = null;
  clearAutoSwitch();
  log('warn', '已清除代理，回退直连');
  await applyBrowserProxy();
  pushStatus();
}

function scheduleAutoSwitch() {
  clearAutoSwitch();
  if (!currentExpireAt) return;
  if (!canAutoSwitch()) return; // 自动换 IP 关闭或已达上限：不排程，由维护循环兜底
  const delay = currentExpireAt - Date.now() - EXPIRE_SWITCH_SECONDS * 1000;
  if (delay > 0) {
    switchTimer = setTimeout(autoSwitch, delay);
  } else {
    autoSwitch();
  }
}

async function autoSwitch() {
  switchTimer = null;
  if (!canAutoSwitch()) return;
  markAutoSwitch();
  await swapProxy({ reload: false });
}

// 从池中取一个新 IP 应用（reload 决定是否刷新页面）
// source: 'auto' 自动换 IP（先池后拉取）；'pool' 仅从池中取；'fetch' 仅主动拉取
async function swapProxy({ reload = false, source = 'auto' } = {}) {
  if (swapping) return;
  if (settings.direct) { // 直连模式无代理可换，仅按需刷新页面
    if (reload) reloadBrowser();
    return;
  }
  swapping = true;
  pushStatus();
  try {
    await pruneExpired();
    let pick = null;
    if (source !== 'fetch') {
      pick = takeFreshest(currentProxyId());
    }
    if (!pick && source !== 'pool') {
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
      if (source === 'auto') {
        // 自动流程失败后稍后重试；手动刷新不自动重试
        setTimeout(() => { refill(); swapProxy({ reload, source }); }, 5000);
      }
      return;
    }

    await applyProxy(pick);
    refill(); // 后台补满池（关闭自动换 IP 时 refill 内部会跳过）
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
    configured: isConfigured(),
    useCurlffi: settings.use_curlffi,
    captchaDirect: settings.captcha_direct,
    direct: settings.direct,
    riskProxyOnly: settings.risk_proxy_only,
    autoSwitchIp: settings.auto_switch_ip,
    maxAutoSwitch: settings.max_auto_switch,
    autoSwitchCount,
  };
}

function pushStatus() {
  sendToRenderer('pool-status', buildStatus());
}

// ---------------- 维护循环 ----------------
function startMaintenance() {
  stopMaintenance();
  maintenanceTimer = setInterval(() => {
    if (settings.direct) { pushStatus(); return; } // 直连模式跳过代理池维护
    pruneExpired();
    // 当前代理已到期：允许自动换则切换，否则回退直连
    if (currentProxy && currentExpireAt && Date.now() >= currentExpireAt) {
      if (canAutoSwitch()) {
        if (!swapping) {
          markAutoSwitch();
          swapProxy();
        }
      } else {
        clearProxy();
      }
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

// ---------------- 风控自动检测与自动换 IP ----------------
// 本地代理（curlffi_proxy）会在 getSliderUrl 返回风控短响应时置位 risk 标记；
// 这里轮询控制服务，一旦发现风控，立即换 IP 并刷新页面，直到通过。
let riskWatchTimer = null;
let lastRiskSwitchAt = 0;

async function checkRiskAndSwitch() {
  if (swapping) return;
  if (settings.direct) return; // 直连模式无代理可换
  // 风控检测依赖 getSliderUrl 经过 curl_cffi；仅「curl_cffi 中转」或「仅风控代理」开启时有效
  if (!settings.use_curlffi && !settings.risk_proxy_only) return;
  if (!canAutoSwitch()) return; // 自动换 IP 关闭或已达数量上限
  let data;
  try {
    const res = await fetch(`http://127.0.0.1:${CONTROL_PORT}/risk-status`, {
      signal: AbortSignal.timeout(2000),
    });
    if (!res.ok) return;
    data = await res.json();
  } catch (e) {
    return; // 轮询失败静默忽略
  }
  if (!data || !data.risk || !data.risk.detected) return;

  // 先清除标记，避免新页面请求前残留旧风控状态
  fetch(`http://127.0.0.1:${CONTROL_PORT}/risk-reset`, {
    method: 'POST',
    signal: AbortSignal.timeout(2000),
  }).catch(() => {});

  const now = Date.now();
  if (now - lastRiskSwitchAt < 2000) return; // 2 秒去抖
  lastRiskSwitchAt = now;
  markAutoSwitch();
  log('warn', '检测到风控（getSliderUrl 返回风险响应），自动换 IP 并刷新页面…');
  swapProxy({ reload: true }).catch((e) =>
    log('error', '自动换 IP 失败：' + (e && e.message ? e.message : e)));
}

function startRiskWatch() {
  stopRiskWatch();
  riskWatchTimer = setInterval(checkRiskAndSwitch, 800);
}

function stopRiskWatch() {
  if (riskWatchTimer) {
    clearInterval(riskWatchTimer);
    riskWatchTimer = null;
  }
}

// 启动时：读设置、开维护、等待第一个优质 IP 后应用并打开首页
async function initProxyPool() {
  loadSettings();
  log('info', `启动：供应商=${settings.provider}，配置=${isConfigured() ? '已填' : '未填'}，N=${settings.N}，延迟阈值=${settings.maxLatency}ms，检测网址=${settings.check_url || '未设置(不检测域名)'}，curl_cffi中转=${settings.use_curlffi ? '开' : '关'}，验证码直连=${settings.captcha_direct ? '开' : '关'}，直连模式=${settings.direct ? '开' : '关'}，仅风控代理=${settings.risk_proxy_only ? '开' : '关'}`);
  await applyBrowserProxy();
  pushStatus();

  if (settings.direct || !settings.auto_switch_ip) {
    if (settings.direct) {
      log('info', '直连模式：不拉取代理池，浏览器与 curl_cffi 转发均直连源站');
    } else {
      log('info', '已关闭自动换 IP：不自动补池，仅手动点击「刷新」时获取并应用代理');
      startMaintenance(); // 仅用于代理到期时回退直连，不自动补池/换 IP
    }
    // 走本地 curl_cffi 中转时，等 sidecar 就绪再加载页面，避免启动竞态导致首屏连不上代理
    if (settings.use_curlffi) await waitForSidecarReady();
    const wc0 = getBrowserWC();
    if (wc0) wc0.loadURL(DEFAULT_URL).catch(() => {});
    return;
  }

  startMaintenance();
  refill();

  // 最多等约 20 秒拿到第一个优质 IP
  for (let i = 0; i < 40; i++) {
    await pruneExpired();
    const pick = takeFreshest();
    if (pick) {
      await applyProxy(pick);
      refill();
      break;
    }
    await sleep(500);
  }

  // 走本地 curl_cffi 中转时，等 sidecar 就绪再加载页面
  if (settings.use_curlffi) await waitForSidecarReady();
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

  // 关键修复：接受本地 MITM 代理签发的自签名证书。Electron 的
  // `ignore-certificate-errors` 开关对自定义 partition 的 WebContentsView
  // 经常不生效，必须对 session 显式放行，否则所有 HTTPS 页面（无论走代理
  // 还是"直连"回退）都会在 TLS 握手阶段被浏览器拒绝，sidecar 永远收不到
  // 可转发的请求（日志里也就看不到任何 [proxy] 转发记录）。
  try {
    wc.session.setCertificateVerifyProc((_request, callback) => {
      callback(0); // 0 = 校验通过，放行
    });
  } catch (e) {
    log('warn', '设置证书校验放行失败：' + (e.message || e));
  }

  // 页面请求走向由设置里的「curl_cffi 中转」开关决定
  applyBrowserProxy().catch((e) => log('warn', '应用浏览器代理模式失败：' + (e.message || e)));

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
    if (authInfo.isProxy && currentAuth && currentAuth.user) {
      callback(currentAuth.user, currentAuth.pass);
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
  startPythonProxy();
  createWindow();
  initProxyPool();
  startRiskWatch();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

// 退出时关闭本地指纹代理子进程
app.on('before-quit', () => {
  quitting = true;
  stopPythonProxy();
});

// ---------------- IPC ----------------
ipcMain.handle('navigate', async (_e, url) => {
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  const cur = getBrowserWC();
  if (cur) cur.loadURL(url).catch(() => {});
  return { ok: true };
});

// 手动刷新：后台换一个 IP 并刷新页面，立即返回，避免按钮长时间置灰
// 自动换 IP 开启时从池中取；关闭时主动获取并应用一个代理
ipcMain.handle('refresh-proxy', () => {
  const source = settings.auto_switch_ip ? 'pool' : 'fetch';
  swapProxy({ reload: true, source }).catch((e) => log('error', '刷新失败：' + (e && e.message ? e.message : e)));
  return { ok: true };
});

// 手动清空内嵌浏览器所有缓存与站点数据
ipcMain.handle('clear-browser-cache', async () => {
  const ok = await clearBrowserCache();
  return { ok };
});

ipcMain.handle('get-settings', () => settings);

ipcMain.handle('save-settings', async (_e, next) => {
  const prevUseCurlffi = settings.use_curlffi;
  const prevCaptchaDirect = settings.captcha_direct;
  const prevDirect = settings.direct;
  const prevRiskProxyOnly = settings.risk_proxy_only;
  const prevAutoSwitchIp = settings.auto_switch_ip;
  const saved = saveSettings(next);
  // 开启自动换 IP 时清空自动换 IP 计数
  if (settings.auto_switch_ip && !prevAutoSwitchIp) {
    autoSwitchCount = 0;
    log('info', '已开启自动换 IP，自动切换计数已清零');
  }
  // 重新排程/清除到期切换定时器
  if (settings.auto_switch_ip) {
    if (currentExpireAt) scheduleAutoSwitch();
  } else {
    clearAutoSwitch();
  }
  // 设置变化后重建池（清空旧 IP），保留当前代理直到下一次切换
  pool.length = 0;
  lastError = null;
  startMaintenance();
  if (settings.direct) {
    // 直连模式：清除当前代理（维护/风控轮询内部会自行跳过）
    currentProxy = null;
    currentAuth = null;
    currentExpireAt = null;
    clearAutoSwitch();
  } else if (settings.auto_switch_ip) {
    // 自动换 IP 开启：后台补池；从直连切回时立即拉取并应用一个代理
    if (prevDirect) {
      refill();
      swapProxy({ reload: true }).catch(() => {});
    } else {
      refill();
    }
  }
  // 自动换 IP 关闭时：不自动补池/应用，仅手动点击「刷新」时获取并应用代理
  // 请求走向开关变化时立即切换并刷新页面
  await applyBrowserProxy();
  const routingChanged = prevDirect !== settings.direct
    || prevRiskProxyOnly !== settings.risk_proxy_only
    || prevUseCurlffi !== settings.use_curlffi
    || prevCaptchaDirect !== settings.captcha_direct;
  if (routingChanged) {
    const parts = [];
    if (prevDirect !== settings.direct) {
      parts.push(settings.direct
        ? '已开启直连模式（浏览器与 curl_cffi 转发均不走 91http 代理）'
        : '已关闭直连模式，恢复走 91http 代理');
    }
    if (prevRiskProxyOnly !== settings.risk_proxy_only) {
      parts.push(settings.risk_proxy_only
        ? '已开启仅风控代理（只有 getSliderUrl 走动态代理，其余直连）'
        : '已关闭仅风控代理');
    }
    if (prevUseCurlffi !== settings.use_curlffi) {
      parts.push(settings.use_curlffi
        ? '已开启 curl_cffi 请求中转（TLS 指纹伪装）'
        : '已关闭 curl_cffi 请求中转，浏览器直连上游代理');
    }
    if (prevCaptchaDirect !== settings.captcha_direct) {
      parts.push(settings.captcha_direct
        ? '验证码域名已切换为直连（绕过代理）'
        : '验证码域名已恢复走代理');
    }
    log('info', parts.join('；'));
    // 从直连切回代理时，由上面的 swapProxy({reload:true}) 应用代理后统一刷新，避免竞态
    if (!(prevDirect && !settings.direct)) reloadBrowser();
  }
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
