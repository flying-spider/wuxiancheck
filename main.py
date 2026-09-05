#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vivo 无限查询（Python 版）
- 代理池：91http 拉取 + 质量检测 + 自动换 IP
- 质量检测走 curl_cffi，可切换 chrome/firefox/safari 多种 TLS 指纹（过 TLS 检测）
- 渲染走 Camoufox（Firefox 内核，C++ 层随机浏览器指纹）
"""

import json
import os
import queue
import re
import socket
import sys
import threading
import time
from datetime import datetime

import platformdirs
from curl_cffi import requests as cffi

import tkinter as tk
from tkinter import messagebox

# ---------------- 常量 ----------------
CONFIG_DIR = platformdirs.user_config_dir("vivo-wuxian")
SETTINGS_PATH = os.path.join(CONFIG_DIR, "settings.json")

API_BASE = "http://api.91http.com"
CHECK_URL = "https://userappeal.vivo.com.cn/"
CHECK_MARKER = "vivo账号申诉"
DEFAULT_URL = "https://userappeal.vivo.com.cn/#/index"

# 距离到期提前多少秒自动换 IP
EXPIRE_SWITCH_SECONDS = 20

DEFAULT_SETTINGS = {
    "trade_no": "",
    "secret": "",
    "num": 10,          # 每次请求提取的 IP 数量
    "N": 5,             # 优质 IP 池目标大小
    "maxLatency": 2000,  # 质量检测延迟阈值（毫秒）
    "proxy_user": "",    # 代理账号（账密认证用）
    "proxy_pass": "",
}


def clamp_int(v, lo, hi):
    try:
        n = int(v)
    except (TypeError, ValueError):
        return lo
    return max(lo, min(hi, n))


def load_settings():
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            parsed = json.load(f)
        s.update(parsed)
    except Exception:
        pass
    s["trade_no"] = str(s.get("trade_no") or "").strip()
    s["secret"] = str(s.get("secret") or "").strip()
    s["proxy_user"] = str(s.get("proxy_user") or "").strip()
    s["proxy_pass"] = str(s.get("proxy_pass") or "")
    s["num"] = clamp_int(s.get("num"), 1, 200)
    s["N"] = clamp_int(s.get("N"), 1, 200)
    s["maxLatency"] = clamp_int(s.get("maxLatency"), 100, 15000)
    return s


def save_settings(next_s):
    s = load_settings()
    s.update({
        "trade_no": str(next_s.get("trade_no") or "").strip(),
        "secret": str(next_s.get("secret") or "").strip(),
        "proxy_user": str(next_s.get("proxy_user") or "").strip(),
        "proxy_pass": str(next_s.get("proxy_pass") or ""),
        "num": clamp_int(next_s.get("num"), 1, 200),
        "N": clamp_int(next_s.get("N"), 1, 200),
        "maxLatency": clamp_int(next_s.get("maxLatency"), 100, 15000),
    })
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return s


def error_chain(e):
    """展开异常链（fetch -> 底层 socket 错误）"""
    parts = []
    cur = e
    guard = 0
    while cur is not None and guard < 6:
        code = getattr(cur, "code", None)
        msg = str(cur) or cur.__class__.__name__
        parts.append(f"{code}:{msg}" if code else msg)
        nxt = getattr(cur, "__cause__", None) or getattr(cur, "context", None)
        if nxt is cur:
            break
        cur = nxt
        guard += 1
    return " <- ".join(parts)


# ---------------- 代理池（纯逻辑，不依赖浏览器） ----------------

def build_api_url(count, s):
    q = "trade_no={}&secret={}&num={}&format=text&sep=1&time=1&protocol=1&filter=1".format(
        s["trade_no"], s["secret"], count
    )
    return f"{API_BASE}/v1/get-ip?{q}"


def fetch_proxies(count, s):
    """从接口拉取一批代理，返回 [{'proxy': 'ip:port', 'expireAt': 秒级时间戳}]"""
    r = cffi.get(build_api_url(count, s), impersonate="chrome", timeout=20)
    if r.status_code != 200:
        raise RuntimeError(f"接口返回 HTTP {r.status_code}")
    text = (r.text or "").strip()
    if not text:
        return []
    out = []
    pat = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+):(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$")
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = pat.match(line)
        if not m:
            continue
        proxy = f"{m.group(1)}:{m.group(2)}"
        try:
            expire_at = datetime.strptime(m.group(3), "%Y-%m-%d %H:%M:%S").timestamp()
        except ValueError:
            continue
        out.append({"proxy": proxy, "expireAt": expire_at})
    return out


def raw_tcp_connect(host, port, timeout=2.5):
    """原始 TCP 连通性检测（不经过代理）"""
    started = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return {"ok": True, "ms": int((time.time() - started) * 1000), "info": "connected"}
    except Exception as e:
        code = getattr(e, "errno", None) or e.__class__.__name__
        return {"ok": False, "ms": int((time.time() - started) * 1000), "info": str(code)}


def manual_connect(target_host, target_port, proxy_host, proxy_port, user, pw, timeout=4.0):
    """手动向代理发 CONNECT 请求，探测代理隧道能力与返回码"""
    started = time.time()
    try:
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    except Exception as e:
        code = getattr(e, "errno", None) or e.__class__.__name__
        return {"ok": False, "info": str(code), "ms": int((time.time() - started) * 1000)}
    sock.settimeout(timeout)
    try:
        req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\nProxy-Connection: keep-alive\r\n"
        if user:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req += f"Proxy-Authorization: Basic {token}\r\n"
        req += "\r\n"
        sock.sendall(req.encode("latin1"))
        buf = b""
        while b"\r\n" not in buf:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
        status = buf.decode("latin1", "ignore")
        m = re.search(r"^HTTP/1\.[01] (\d{3})", status)
        return {
            "ok": bool(m) and m.group(1) == "200",
            "info": ("CONNECT " + m.group(1)) if m else "no-status",
            "ms": int((time.time() - started) * 1000),
        }
    except Exception as e:
        code = getattr(e, "errno", None) or e.__class__.__name__
        return {"ok": False, "info": str(code), "ms": int((time.time() - started) * 1000)}
    finally:
        try:
            sock.close()
        except Exception:
            pass


def check_proxy_quality(proxy, s):
    """通过 vivo 页面检测单个代理是否可用，返回 {ok, latency, reason}"""
    host, port_str = proxy.split(":")
    port = int(port_str)

    tcp = raw_tcp_connect(host, port)
    if not tcp["ok"]:
        return {"ok": False, "latency": tcp["ms"], "reason": f"代理不可达 TCP({tcp['info']})"}

    auth = f"{s['proxy_user']}:{s['proxy_pass']}@" if s["proxy_user"] else ""
    proxies = {
        "http": f"http://{auth}{host}:{port}",
        "https": f"http://{auth}{host}:{port}",
    }
    started = time.time()
    try:
        r = cffi.get(CHECK_URL, impersonate="chrome", proxies=proxies, timeout=15)
        latency = int((time.time() - started) * 1000)
        if r.status_code != 200:
            return {"ok": False, "latency": latency, "reason": f"HTTP {r.status_code}"}
        text = r.text or ""
        if latency > s["maxLatency"]:
            return {"ok": False, "latency": latency, "reason": f"延迟 {latency}ms 超过阈值 {s['maxLatency']}ms"}
        if CHECK_MARKER not in text:
            return {"ok": False, "latency": latency, "reason": "页面未含「vivo账号申诉」"}
        return {"ok": True, "latency": latency, "reason": "通过"}
    except Exception as e:
        latency = int((time.time() - started) * 1000)
        diag = manual_connect("userappeal.vivo.com.cn", 443, host, port,
                              s["proxy_user"], s["proxy_pass"])
        reason = f"{error_chain(e)}；CONNECT={'200 OK' if diag['ok'] else ('失败:' + diag['info'])}"
        return {"ok": False, "latency": latency, "reason": reason}


def map_with_concurrency(items, limit, fn):
    """限流并发执行（线程池）"""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    results = [None] * len(items)
    with ThreadPoolExecutor(max_workers=limit) as ex:
        fut = {ex.submit(fn, it): i for i, it in enumerate(items)}
        for f in as_completed(fut):
            results[fut[f]] = f.result()
    return results


def find_bundled_camoufox():
    """打包（PyInstaller 冻结）后，从捆绑数据里找 Camoufox 内核可执行文件，找不到返回 None。"""
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        return None
    for cand in (
        os.path.join(base, "camoufox", "camoufox.exe"),                       # Windows
        os.path.join(base, "camoufox", "Camoufox.app", "Contents", "MacOS", "camoufox"),  # macOS
        os.path.join(base, "camoufox", "camoufox-bin"),                       # Linux
    ):
        if os.path.exists(cand):
            return cand
    return None


# ---------------- 引擎（后台线程：代理池 + Camoufox） ----------------

class Engine:
    def __init__(self, events: queue.Queue):
        self.events = events
        self.cmds = queue.Queue()
        self.settings = dict(DEFAULT_SETTINGS)
        self.pool = []           # [{'proxy': 'ip:port', 'expireAt': 秒}]
        self.current_proxy = None
        self.current_expire_at = None
        self.refilling = False
        self.swapping = False
        self.last_error = None
        self._ctx = None         # Camoufox 上下文管理器
        self.browser = None
        self.page = None
        self.zoom = 1.0
        self.current_url = DEFAULT_URL
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)

    # ---- 对外接口 ----
    def start(self):
        self._thread.start()

    def post(self, cmd):
        self.cmds.put(cmd)

    def stop(self):
        self.running = False
        self.post(("stop",))

    # ---- 日志 / 状态 ----
    def _log(self, level, msg):
        line = f"[{time.strftime('%H:%M:%S')}] [{level}] {msg}"
        try:
            print(line)
        except Exception:
            pass
        self.events.put(("log", line))

    def _push_status(self):
        self.events.put(("status", {
            "currentProxy": self.current_proxy,
            "currentExpireAt": self.current_expire_at,
            "poolSize": self._quality_pool_size(),
            "targetN": self.settings["N"],
            "refilling": self.refilling,
            "swapping": self.swapping,
            "lastError": self.last_error,
            "configured": bool(self.settings["trade_no"] and self.settings["secret"]),
        }))

    # ---- 池操作 ----
    def _prune(self):
        now = time.time()
        self.pool = [p for p in self.pool if p["expireAt"] > now]

    def _quality_pool_size(self):
        now = time.time()
        return sum(1 for p in self.pool if p["expireAt"] > now)

    def _take_freshest(self, exclude=None):
        now = time.time()
        best, best_idx = None, -1
        for i, p in enumerate(self.pool):
            if p["expireAt"] <= now or p["proxy"] == exclude:
                continue
            if best is None or p["expireAt"] > best["expireAt"]:
                best, best_idx = p, i
        if best_idx >= 0:
            self.pool.pop(best_idx)
        return best

    def _refill(self):
        if self.refilling:
            return
        if not (self.settings["trade_no"] and self.settings["secret"]):
            self.last_error = "请先在「设置」中填写 trade_no 与 secret"
            self._log("warn", self.last_error)
            self._push_status()
            return
        self.refilling = True
        self._push_status()
        try:
            for round_i in range(5):
                self._prune()
                need = self.settings["N"] - self._quality_pool_size()
                if need <= 0:
                    break
                try:
                    batch = fetch_proxies(self.settings["num"], self.settings)
                except Exception as e:
                    self.last_error = "拉取代理失败：" + str(e)
                    self._log("error", self.last_error)
                    break
                if not batch:
                    self.last_error = "接口没有返回可用代理（返回为空或格式不符）"
                    self._log("warn", self.last_error)
                    break
                now = time.time()
                candidates = [p for p in batch if p["expireAt"] > now]
                if not candidates:
                    self.last_error = "本批代理已全部过期，稍后自动重试"
                    self._log("warn", self.last_error)
                    break
                self._log("info", f"第 {round_i + 1} 轮：拉取 {len(batch)} 个代理，"
                                  f"{len(candidates)} 个未过期，开始并发检测（阈值 {self.settings['maxLatency']}ms）")
                added = 0

                def check_one(c):
                    if self._quality_pool_size() >= self.settings["N"]:
                        return None
                    r = check_proxy_quality(c["proxy"], self.settings)
                    if not r["ok"]:
                        self._log("warn", f"检测 {c['proxy']} → 未通过（{r['reason']}，耗时 {r['latency']}ms）")
                        return None
                    if self._quality_pool_size() >= self.settings["N"]:
                        return None
                    if c["expireAt"] <= time.time() or any(x["proxy"] == c["proxy"] for x in self.pool):
                        return None
                    self.pool.append(c)
                    self._log("ok", f"检测 {c['proxy']} → 通过（耗时 {r['latency']}ms），"
                                    f"已立即入池 {self._quality_pool_size()}/{self.settings['N']}")
                    self._push_status()
                    return c

                for r in map_with_concurrency(candidates, 6, check_one):
                    if r:
                        added += 1
                if added == 0:
                    self.last_error = f"本批 {len(candidates)} 个代理均未通过质量检测，稍后自动重试"
                    self._log("warn", self.last_error)
                    break
                self._log("info", f"本批完成，当前池 {self._quality_pool_size()}/{self.settings['N']}")
        finally:
            self.refilling = False
            self._push_status()

    def _acquire_one(self):
        """池空时应急：立即拉取并检测，返回第一个可用代理"""
        try:
            batch = fetch_proxies(max(1, self.settings["num"]), self.settings)
        except Exception as e:
            self.last_error = "拉取代理失败：" + str(e)
            self._log("error", self.last_error)
            return None
        now = time.time()
        candidates = [p for p in batch if p["expireAt"] > now]
        if not candidates:
            return None
        found = [None]

        def check_one(c):
            if found[0] is not None:
                return None
            r = check_proxy_quality(c["proxy"], self.settings)
            self._log("ok" if r["ok"] else "warn",
                      f"检测 {c['proxy']} → {'通过' if r['ok'] else '未通过'}（{r['reason']}，耗时 {r['latency']}ms）")
            if r["ok"] and found[0] is None:
                found[0] = c
            return None

        map_with_concurrency(candidates, 6, check_one)
        return found[0]

    # ---- 浏览器（Camoufox） ----
    def _close_browser(self):
        if self._ctx is not None:
            try:
                self._ctx.__exit__(None, None, None)
            except Exception:
                pass
        self._ctx = None
        self.browser = None
        self.page = None

    def _launch(self, proxy):
        self._close_browser()
        try:
            from camoufox.sync_api import Camoufox
        except Exception as e:
            self._log("error", f"无法导入 Camoufox：{e}")
            self._log("error", "请先运行 `python -m camoufox fetch` 下载浏览器内核。")
            return False
        opts = {"headless": False, "humanize": True, "geoip": True}
        bundled = find_bundled_camoufox()
        if bundled:
            opts["executable_path"] = bundled
        if proxy:
            host, port = proxy.split(":")
            p = {"server": f"http://{host}:{port}"}
            if self.settings["proxy_user"]:
                p["username"] = self.settings["proxy_user"]
                p["password"] = self.settings["proxy_pass"]
            opts["proxy"] = p
        try:
            ctx = Camoufox(**opts)
            browser = ctx.__enter__()
            page = browser.new_page()
        except Exception as e:
            self._log("error", f"启动浏览器失败：{error_chain(e)}")
            return False
        self._ctx = ctx
        self.browser = browser
        self.page = page
        self._apply_zoom()
        self._log("info", f"浏览器已启动，代理={'直连' if not proxy else proxy}")
        return True

    def _apply_zoom(self):
        if not self.page:
            return
        try:
            self.page.evaluate(f"document.body.style.zoom = {self.zoom}")
        except Exception:
            pass

    def _goto(self, url):
        if not self.page:
            return
        try:
            self.page.goto(url, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            self._log("warn", f"页面加载异常：{error_chain(e)}")
        finally:
            self._apply_zoom()
        self.current_url = url
        self.events.put(("url", url))

    def _apply_proxy(self, proxy, expire_at):
        self.current_proxy = proxy
        self.current_expire_at = expire_at
        self._log("info", f"已应用代理 {proxy}，到期 {time.strftime('%H:%M:%S', time.localtime(expire_at))}")
        self._launch(proxy)
        self._goto(self.current_url)

    def _clear_proxy(self):
        self.current_proxy = None
        self.current_expire_at = None
        self._log("warn", "已清除代理，回退直连")
        self._launch(None)
        self._goto(self.current_url)

    def _swap(self, reload_page=False):
        if self.swapping:
            return
        self.swapping = True
        self._push_status()
        try:
            self._prune()
            pick = self._take_freshest(self.current_proxy)
            if not pick:
                pick = self._acquire_one()
            if not pick:
                cur_expired = (not self.current_proxy or not self.current_expire_at
                               or time.time() >= self.current_expire_at)
                if cur_expired:
                    self._clear_proxy()
                self.last_error = "暂无可用代理" + ("，已回退直连" if cur_expired else "")
                self._log("warn", self.last_error)
                self._push_status()
                # 稍后自动重试
                def _retry():
                    time.sleep(5)
                    self.post(("swap",))
                threading.Thread(target=_retry, daemon=True).start()
                return
            self._apply_proxy(pick["proxy"], pick["expireAt"])
            self._refill()
        finally:
            self.swapping = False
            self._push_status()

    def _maintenance(self):
        self._prune()
        if self.current_proxy and self.current_expire_at and time.time() >= self.current_expire_at:
            self._swap()
            return
        if self._quality_pool_size() < self.settings["N"]:
            self._refill()
        self._push_status()

    # ---- 命令分发 ----
    def _handle_cmd(self, cmd):
        kind = cmd[0]
        if kind == "navigate":
            url = cmd[1]
            if not re.match(r"^https?://", url):
                url = "https://" + url
            self.current_url = url
            self._goto(url)
        elif kind == "refresh":
            self._swap(reload_page=True)
        elif kind == "swap":
            self._swap()
        elif kind == "zoom":
            self.zoom = min(3.0, max(0.5, self.zoom + float(cmd[1])))
            self._apply_zoom()
            self.events.put(("zoom", self.zoom))
        elif kind == "zoom_reset":
            self.zoom = 1.0
            self._apply_zoom()
            self.events.put(("zoom", self.zoom))
        elif kind == "settings":
            self.settings = save_settings(cmd[1])
            self.pool = []
            self.last_error = None
            self._log("info", "设置已更新，正在重建代理池…")
            self._refill()
            self._push_status()
        elif kind == "stop":
            self.running = False

    def _drain_cmds(self):
        while True:
            try:
                cmd = self.cmds.get_nowait()
            except queue.Empty:
                break
            self._handle_cmd(cmd)

    # ---- 主循环 ----
    def _run(self):
        self.settings = load_settings()
        self._log("info", f"启动：trade_no={'已填' if self.settings['trade_no'] else '未填'}，"
                          f"secret={'已填' if self.settings['secret'] else '未填'}，"
                          f"num={self.settings['num']}，N={self.settings['N']}，"
                          f"延迟阈值={self.settings['maxLatency']}ms，"
                          f"代理账密={'已填' if self.settings['proxy_user'] else '未填'}")
        self._push_status()

        # 先尽力拿到第一个优质 IP（最多约 20 秒）
        if self.settings["trade_no"] and self.settings["secret"]:
            deadline = time.time() + 20
            while time.time() < deadline and not self._quality_pool_size():
                self._refill()
                pick = self._take_freshest()
                if pick:
                    self.current_proxy = pick["proxy"]
                    self.current_expire_at = pick["expireAt"]
                    self._log("info", f"已取得首个代理 {pick['proxy']}")
                    break
                time.sleep(0.5)

        self._launch(self.current_proxy)
        self._goto(self.current_url)
        self._push_status()

        while self.running:
            self._drain_cmds()
            self._maintenance()
            time.sleep(0.3)

        self._close_browser()


# ---------------- UI（tkinter 控制面板） ----------------

class App:
    def __init__(self, root, engine, events):
        self.root = root
        self.engine = engine
        self.events = events
        self.zoom = 1.0
        self.log_open = False
        self._build_toolbar()
        self._build_log_panel()
        root.after(100, self._poll)

    def _build_toolbar(self):
        bar = tk.Frame(self.root, bd=0)
        bar.pack(side="top", fill="x")

        self.url_var = tk.StringVar()
        self.url_entry = tk.Entry(bar, textvariable=self.url_var)
        self.url_entry.pack(side="left", fill="x", expand=True, padx=(8, 4), pady=6)
        self.url_entry.bind("<Return>", lambda e: self._navigate())

        tk.Button(bar, text="刷新", command=self._refresh).pack(side="left", padx=2)
        tk.Button(bar, text="设置", command=self._open_settings).pack(side="left", padx=2)
        self.log_btn = tk.Button(bar, text="日志", command=self._toggle_log)
        self.log_btn.pack(side="left", padx=2)

        tk.Button(bar, text="−", width=2, command=lambda: self._zoom_by(-0.1)).pack(side="left", padx=1)
        self.zoom_label = tk.Label(bar, text="100%", width=5)
        self.zoom_label.pack(side="left")
        tk.Button(bar, text="+", width=2, command=lambda: self._zoom_by(0.1)).pack(side="left", padx=1)

        self.status_var = tk.StringVar(value="初始化中…")
        tk.Label(bar, textvariable=self.status_var, fg="#555").pack(side="left", padx=10)

    def _build_log_panel(self):
        self.log_frame = tk.Frame(self.root, height=180)
        self.log_text = tk.Text(self.log_frame, bg="#1e1e1e", fg="#d4d4d4",
                                font=("Monaco", 11), state="disabled", wrap="word")
        sb = tk.Scrollbar(self.log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        # 初始隐藏

    def _toggle_log(self):
        self.log_open = not self.log_open
        if self.log_open:
            self.log_frame.pack(side="bottom", fill="both")
            self.log_btn.configure(relief="sunken")
        else:
            self.log_frame.pack_forget()
            self.log_btn.configure(relief="raised")

    def _navigate(self):
        url = self.url_var.get().strip()
        if url:
            self.engine.post(("navigate", url))

    def _refresh(self):
        self.engine.post(("refresh",))

    def _zoom_by(self, delta):
        self.zoom = min(3.0, max(0.5, self.zoom + delta))
        self.engine.post(("zoom", delta))
        self.zoom_label.configure(text=f"{round(self.zoom * 100)}%")

    def _zoom_reset(self):
        self.zoom = 1.0
        self.engine.post(("zoom_reset",))
        self.zoom_label.configure(text="100%")

    def _open_settings(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("代理设置")
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()

        def row(label, i):
            tk.Label(dlg, text=label).grid(row=i, column=0, sticky="e", padx=6, pady=4)
            var = tk.StringVar()
            ent = tk.Entry(dlg, textvariable=var, width=30)
            ent.grid(row=i, column=1, sticky="w", padx=6, pady=4)
            return var

        v_trade = row("trade_no（业务编号）", 0)
        v_secret = row("secret（业务密钥）", 1)
        v_user = row("代理账号（选填）", 2)
        v_pass = row("代理密码（选填）", 3)
        v_num = row("每次提取 IP 数量", 4)
        v_N = row("优质 IP 池大小 N", 5)
        v_lat = row("延迟阈值（毫秒）", 6)

        s = self.engine.settings
        v_trade.set(s["trade_no"])
        v_secret.set(s["secret"])
        v_user.set(s["proxy_user"])
        v_pass.set(s["proxy_pass"])
        v_num.set(str(s["num"]))
        v_N.set(str(s["N"]))
        v_lat.set(str(s["maxLatency"]))

        def do_save():
            try:
                self.engine.post(("settings", {
                    "trade_no": v_trade.get().strip(),
                    "secret": v_secret.get().strip(),
                    "proxy_user": v_user.get().strip(),
                    "proxy_pass": v_pass.get(),
                    "num": int(v_num.get()),
                    "N": int(v_N.get()),
                    "maxLatency": int(v_lat.get()),
                }))
            except ValueError:
                messagebox.showerror("错误", "数字字段格式不正确", parent=dlg)
                return
            dlg.destroy()

        btns = tk.Frame(dlg)
        btns.grid(row=7, column=0, columnspan=2, pady=8)
        tk.Button(btns, text="保存", command=do_save).pack(side="left", padx=6)
        tk.Button(btns, text="取消", command=dlg.destroy).pack(side="left", padx=6)

    def _append_log(self, line):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", line + "\n")
        if float(self.log_text.index("end-1c").split(".")[0]) > 300:
            self.log_text.delete("1.0", "2.0")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll(self):
        while True:
            try:
                kind, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self._append_log(payload)
            elif kind == "status":
                s = payload
                self.status_var.set(f"池 {s['poolSize']}/{s['targetN']}")
                if s["lastError"]:
                    self.status_var.set(f"池 {s['poolSize']}/{s['targetN']}  ⚠ {s['lastError']}")
            elif kind == "url":
                self.url_var.set(payload)
            elif kind == "zoom":
                self.zoom = payload
                self.zoom_label.configure(text=f"{round(payload * 100)}%")
        self.root.after(100, self._poll)


def main():
    events = queue.Queue()
    engine = Engine(events)
    root = tk.Tk()
    root.title("vivo 无限查询")
    root.geometry("760x64")
    App(root, engine, events)

    def on_close():
        engine.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    engine.start()
    root.mainloop()


if __name__ == "__main__":
    main()
