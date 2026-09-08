#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
curl_cffi 随机指纹转发代理 + 普通浏览器渲染

思路：
- 本地起一个 MITM 代理（默认 127.0.0.1:8899）
- 浏览器（Playwright Chromium）把「所有请求」都交给这个代理
- 代理对每个请求用 curl_cffi 转发，并随机选择一套浏览器 TLS 指纹（impersonate）
- 浏览器只负责渲染返回的页面；前端 JS 可见指纹与 TLS 指纹不一致暂不考虑

用法：
    .venv/bin/python curlffi_proxy.py                     # 打开默认目标页
    .venv/bin/python curlffi_proxy.py --url https://...    # 指定页面
    .venv/bin/python curlffi_proxy.py --upstream http://user:pass@ip:port  # 上游代理（如 91http）
    .venv/bin/python curlffi_proxy.py --headless           # 无头模式

依赖：curl_cffi、cryptography、playwright（Chromium 内核需已下载）
"""

import argparse
import datetime
import http.client
import http.server
import json
import os
import random
import re
import socket
import ssl
import tempfile
import threading
import time

from curl_cffi import requests as cffi

# ---------------- 常量 ----------------
DEFAULT_PORT = 8899
DEFAULT_URL = "https://userappeal.vivo.com.cn/#/index"

# 可用的 TLS 指纹池（从 curl_cffi BrowserType 中挑选的常见浏览器版本）
IMPERSONATE_POOL = [
    "chrome136", "chrome142", "chrome145", "chrome146", "chrome150",
    "firefox133", "firefox135", "firefox144", "firefox147",
    "safari180", "safari184", "safari260", "safari2601",
    "edge101",
]

# 转发时需要剔除的逐跳头（hop-by-hop），不能原样透传
HOP_BY_HOP = {
    "connection", "proxy-connection", "keep-alive", "transfer-encoding",
    "upgrade", "te", "trailer", "proxy-authorization",
}


# ---------------- 证书（MITM 用） ----------------

def _load_or_create_ca(cert_dir):
    """加载或生成 CA，返回 (ca_key, ca_cert, ca_crt_path)。"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(cert_dir, exist_ok=True)
    key_path = os.path.join(cert_dir, "ca.key")
    crt_path = os.path.join(cert_dir, "ca.crt")

    if os.path.exists(key_path) and os.path.exists(crt_path):
        with open(key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(crt_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert, crt_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "wuxiancheck"),
        x509.NameAttribute(NameOID.COMMON_NAME, "wuxiancheck MITM CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_encipherment=True, key_cert_sign=True,
            crl_sign=True, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .sign(key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert, crt_path


def _make_leaf(host, ca_key, ca_cert):
    """为指定 host 生成叶子证书，返回 (cert_pem, key_pem)。"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    san = x509.SubjectAlternativeName([x509.DNSName(host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=825))
        .add_extension(san, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


# ---------------- HTTP 报文解析 ----------------

class RequestReader:
    """带缓冲的 HTTP 请求读取器，正确处理 keep-alive 与分块传输。"""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _recv_until(self, delim):
        while delim not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                return False
            self.buf += chunk
        return True

    def read(self):
        """读取一条完整请求，返回 dict 或 None（对端关闭）。"""
        if not self._recv_until(b"\r\n\r\n"):
            return None
        head, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        request_line = lines[0].decode("latin1", "ignore")
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None
        method, target = parts[0], parts[1]

        headers = []
        hmap = {}
        for line in lines[1:]:
            if not line:
                continue
            k, sep, v = line.decode("latin1", "ignore").partition(":")
            if not sep:
                continue
            k, v = k.strip(), v.strip()
            headers.append((k, v))
            hmap.setdefault(k.lower(), v)

        body = b""
        if "content-length" in hmap:
            cl = int(hmap["content-length"])
            while len(self.buf) < cl:
                chunk = self.sock.recv(65536)
                if not chunk:
                    break
                self.buf += chunk
            body = self.buf[:cl]
            self.buf = self.buf[cl:]
        elif hmap.get("transfer-encoding", "").lower() == "chunked":
            body = self._read_chunked()

        return {"method": method, "target": target, "headers": headers, "hmap": hmap, "body": body}

    def _read_chunked(self):
        out = bytearray()
        while True:
            if not self._recv_until(b"\r\n"):
                break
            size_line, self.buf = self.buf.split(b"\r\n", 1)
            size = int(size_line.split(b";")[0], 16)
            if size == 0:
                # 0 长度 chunk 后还有一段可选的 trailer 头，读到结束空行
                if self._recv_until(b"\r\n"):
                    self.buf = self.buf.split(b"\r\n", 1)[1]
                break
            while len(self.buf) < size:
                chunk = self.sock.recv(65536)
                if not chunk:
                    return bytes(out)
                self.buf += chunk
            out += self.buf[:size]
            self.buf = self.buf[size:]
            if not self._recv_until(b"\r\n"):
                break
            self.buf = self.buf.split(b"\r\n", 1)[1]
        return bytes(out)


# ---------------- curl_cffi 转发 ----------------

class Forwarder:
    def __init__(self, impersonates=None, upstream=None, timeout=30, verbose=True):
        self.impersonates = list(impersonates or IMPERSONATE_POOL)
        self.timeout = timeout
        self.verbose = verbose
        self._lock = threading.Lock()
        self.proxies = None
        self._imp = None            # 当前会话固定 TLS 指纹
        self._risk = {"detected": False, "count": 0, "last": None}
        if upstream:
            self.proxies = {"http": upstream, "https": upstream}
        self._refresh_imp()

    def _refresh_imp(self):
        """抽取当前会话的固定指纹。每次换上游（换 IP/身份）重新抽一次，
        使同一会话内所有请求（含验证码 /api/a、/api/p1、/api/p2）指纹保持一致，
        模拟真实浏览器，避免「逐请求指纹漂移」被顶象风控识别。"""
        self._imp = random.choice(self.impersonates)

    def set_upstream(self, upstream):
        """运行时切换上游代理（线程安全）。upstream: http://user:pass@ip:port 或 None。
        换上游意味着换身份，因此同时更换 TLS 指纹。"""
        with self._lock:
            self.proxies = {"http": upstream, "https": upstream} if upstream else None
            self._refresh_imp()

    # ---- 风控检测 ----
    def _maybe_detect_risk(self, method, url, content):
        # getSliderUrl 是风控闸口：通过时返回长密文（约 1284 字节），
        # 风控/失败时返回短密文（约 164 字节）。据此用 body 长度识别风控。
        if method.upper() != "GET" or "getSliderUrl" not in url:
            return
        if content.startswith(b"enc:") and len(content) < 500:
            with self._lock:
                self._risk["detected"] = True
                self._risk["count"] += 1
                self._risk["last"] = time.time()
            if self.verbose:
                print(f"[proxy] ⚠ 风控：getSliderUrl 返回短响应（{len(content)}字节），建议换 IP 重试", flush=True)

    def risk_status(self):
        with self._lock:
            return dict(self._risk)

    def reset_risk(self):
        with self._lock:
            self._risk["detected"] = False

    def forward(self, method, url, headers, body):
        with self._lock:
            imp = self._imp or random.choice(self.impersonates)
            proxies = self.proxies

        fwd = []
        for k, v in headers:
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in ("host", "content-length", "accept-encoding"):
                continue
            fwd.append((k, v))
        # 用 identity 规避双重压缩；curl_cffi 仍按 impersonate 设置 TLS 指纹
        fwd.append(("Accept-Encoding", "identity"))

        t0 = time.time()
        try:
            r = cffi.request(
                method, url,
                headers=dict(fwd),
                data=body if body else None,
                impersonate=imp,
                proxies=proxies,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )
        except Exception as e:
            if self.verbose:
                print(f"[proxy] 转发失败 {method} {url} 指纹={imp} 错误={e}", flush=True)
            return self._error_response(502, f"curl_cffi error: {e}")
        ms = int((time.time() - t0) * 1000)

        content = r.content or b""
        self._maybe_detect_risk(method, url, content)
        reason = getattr(r, "reason", None) or http.client.responses.get(r.status_code, "")
        head = f"HTTP/1.1 {r.status_code} {reason}\r\n"
        out_headers = []
        for k, v in r.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in ("content-length", "content-encoding"):
                continue
            out_headers.append(f"{k}: {v}")
        out_headers.append(f"Content-Length: {len(content)}")
        out_headers.append("Connection: keep-alive")
        raw = (head + "\r\n".join(out_headers) + "\r\n\r\n").encode("latin1", "ignore") + content

        if self.verbose:
            short = url if len(url) <= 80 else url[:77] + "..."
            print(f"[proxy] {method} {short}  指纹={imp}  状态={r.status_code}  字节={len(content)}  耗时={ms}ms", flush=True)
        return raw

    @staticmethod
    def _error_response(code, msg):
        body = msg.encode("utf-8")
        head = (f"HTTP/1.1 {code} {http.client.responses.get(code, '')}\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: keep-alive\r\n\r\n")
        return head.encode("latin1") + body


# ---------------- MITM 代理服务 ----------------

class MITMProxy:
    def __init__(self, host="127.0.0.1", port=DEFAULT_PORT, forwarder=None, cert_dir="./certs"):
        self.host = host
        self.port = port
        self.forwarder = forwarder or Forwarder()
        self.cert_dir = cert_dir
        self.ca_key, self.ca_cert, self.ca_crt_path = _load_or_create_ca(cert_dir)
        self._leaf_cache = {}
        self._lock = threading.Lock()
        self._running = True
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def _leaf_files(self, host):
        with self._lock:
            if host in self._leaf_cache:
                return self._leaf_cache[host]
            cert_pem, key_pem = _make_leaf(host, self.ca_key, self.ca_cert)
            cf = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
            kf = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
            cf.write(cert_pem)
            cf.close()
            kf.write(key_pem)
            kf.close()
            self._leaf_cache[host] = (cf.name, kf.name)
            return self._leaf_cache[host]

    def _wrap_mitm(self, raw_sock, host):
        certfile, keyfile = self._leaf_files(host)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        ctx.set_alpn_protocols(["http/1.1"])
        return ctx.wrap_socket(raw_sock, server_side=True)

    def start(self):
        self._server.bind((self.host, self.port))
        self._server.listen(128)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        print(f"[proxy] MITM 代理已启动：http://{self.host}:{self.port}  （CA 证书：{self.ca_crt_path}）", flush=True)

    def _accept_loop(self):
        self._server.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()

    def stop(self):
        self._running = False
        try:
            self._server.close()
        except Exception:
            pass

    def _handle_conn(self, conn, addr):
        conn.settimeout(60)
        try:
            reader = RequestReader(conn)
            first = reader.read()
            if first is None:
                return

            method = first["method"].upper()
            target = first["target"]

            if method == "CONNECT":
                m = re.match(r"^([^:]+):(\d+)$", target)
                if not m:
                    return
                host, port = m.group(1), int(m.group(2))
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                tls = self._wrap_mitm(conn, host)
                tls.settimeout(60)
                self._serve(RequestReader(tls), host, port, is_https=True, first=None)
                return

            if target.startswith(("http://", "https://")):
                # 标准代理请求：绝对 URI
                m = re.match(r"^https?://([^/:]+)(?::(\d+))?", target)
                host = m.group(1)
                port = int(m.group(2) or 80)
                self._serve(reader, host, port, is_https=False, first=first)
                return

            # origin-form（如 GET /）：要么是对代理本身的直接探测，要么是非标准代理请求
            host_hdr = first["hmap"].get("host", "")
            host_bare = host_hdr.rsplit(":", 1)[0].strip("[]") if host_hdr else ""
            if host_hdr and host_bare not in ("127.0.0.1", "localhost", "::1"):
                url = f"http://{host_hdr}{target}"
                resp = self.forwarder.forward(method, url, first["headers"], first["body"])
                conn.sendall(resp)
            else:
                conn.sendall(self._direct_response(404, "this is a proxy"))
        except (ssl.SSLError, socket.timeout, ConnectionError, OSError):
            pass
        except Exception as e:
            print(f"[proxy] 连接处理异常（{addr}）：{e}", flush=True)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _direct_response(code, msg):
        body = msg.encode("utf-8")
        head = (f"HTTP/1.1 {code} {http.client.responses.get(code, '')}\r\n"
                f"Content-Type: text/plain; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Connection: close\r\n\r\n")
        return head.encode("latin1") + body

    def _serve(self, reader, host, port, is_https, first=None):
        req = first
        while True:
            if req is None:
                req = reader.read()
                if req is None:
                    break

            method = req["method"].upper()
            target = req["target"]
            hmap = req["hmap"]

            if is_https:
                url = f"https://{hmap.get('host', host)}{target}"
            else:
                url = target  # 绝对 URI

            resp = self.forwarder.forward(method, url, req["headers"], req["body"])
            try:
                reader.sock.sendall(resp)
            except OSError:
                break

            close = hmap.get("connection", "").lower() == "close"
            req = None
            if close:
                break


# ---------------- 控制服务（供 Electron 等外部客户端调用） ----------------

class ControlServer:
    """本地控制服务：外部进程（如 Electron 主进程）用它动态切换上游代理。"""

    def __init__(self, forwarder, host="127.0.0.1", port=8898):
        self.forwarder = forwarder
        self.host = host
        self.port = port
        self._httpd = None

    def start(self):
        fwd = self.forwarder

        class Handler(http.server.BaseHTTPRequestHandler):
            def _send_json(self, obj, code=200):
                body = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/ping":
                    self._send_json({"ok": True, "proxies": fwd.proxies})
                elif self.path == "/risk-status":
                    self._send_json({"ok": True, "risk": fwd.risk_status()})
                else:
                    self._send_json({"ok": False}, 404)

            def do_POST(self):
                if self.path == "/upstream":
                    try:
                        n = int(self.headers.get("Content-Length", 0) or 0)
                        data = json.loads(self.rfile.read(n) or b"{}")
                        proxy = data.get("proxy") or None
                        user = data.get("user") or ""
                        pwd = data.get("pass") or ""
                        if proxy:
                            auth = f"{user}:{pwd}@" if user else ""
                            fwd.set_upstream(f"http://{auth}{proxy}")
                        else:
                            fwd.set_upstream(None)
                        self._send_json({"ok": True, "proxies": fwd.proxies})
                    except Exception as e:
                        self._send_json({"ok": False, "error": str(e)}, 400)
                elif self.path == "/risk-reset":
                    fwd.reset_risk()
                    self._send_json({"ok": True})
                else:
                    self._send_json({"ok": False}, 404)

            def log_message(self, *args):
                pass

        self._httpd = http.server.ThreadingHTTPServer((self.host, self.port), Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        print(f"[proxy] 控制服务已启动：http://{self.host}:{self.port}", flush=True)

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None


def serve_only(port=DEFAULT_PORT, control_port=8898, upstream=None, verbose=True):
    """仅运行 MITM 代理 + 控制服务（不启动浏览器），供外部客户端使用。"""
    fwd = Forwarder(upstream=upstream, verbose=verbose)
    mitm = MITMProxy(port=port, forwarder=fwd)
    try:
        mitm.start()
    except OSError as e:
        print(f"[proxy] 代理端口 {port} 绑定失败（可能已有实例在运行）：{e}", flush=True)
        return
    ctrl = ControlServer(fwd, port=control_port)
    try:
        ctrl.start()
    except OSError as e:
        print(f"[proxy] 控制端口 {control_port} 绑定失败（可能已有实例在运行）：{e}", flush=True)
        mitm.stop()
        return
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        mitm.stop()
        ctrl.stop()


# ---------------- 浏览器（Playwright Chromium） ----------------

def launch_browser(proxy_port, url, headless=False):
    from playwright.sync_api import sync_playwright

    p = sync_playwright().start()
    browser = p.chromium.launch(
        headless=headless,
        args=[
            f"--proxy-server=127.0.0.1:{proxy_port}",
            "--ignore-certificate-errors",
            "--disable-quic",
        ],
    )
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    print(f"[browser] 正在打开 {url} ...", flush=True)
    page.goto(url, wait_until="domcontentloaded", timeout=60000)
    print(f"[browser] 页面标题：{page.title()}", flush=True)
    return p, browser, ctx, page


# ---------------- 入口 ----------------

def main():
    ap = argparse.ArgumentParser(description="curl_cffi 随机指纹代理 + 浏览器渲染")
    ap.add_argument("--url", default=DEFAULT_URL, help="要打开的页面 URL")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="本地代理端口")
    ap.add_argument("--upstream", default=None, help="上游代理，如 http://user:pass@ip:port")
    ap.add_argument("--headless", action="store_true", help="无头模式")
    ap.add_argument("--quiet", action="store_true", help="关闭逐请求日志")
    ap.add_argument("--serve-only", action="store_true", help="仅运行代理+控制服务（供 Electron 等外部客户端使用）")
    ap.add_argument("--control-port", type=int, default=8898, help="控制服务端口")
    args = ap.parse_args()

    if args.serve_only:
        serve_only(port=args.port, control_port=args.control_port,
                   upstream=args.upstream, verbose=not args.quiet)
        return

    fwd = Forwarder(upstream=args.upstream, verbose=not args.quiet)
    proxy = MITMProxy(port=args.port, forwarder=fwd)
    proxy.start()

    p = browser = ctx = page = None
    try:
        p, browser, ctx, page = launch_browser(args.port, args.url, headless=args.headless)
        print("\n浏览器已就绪，按 Ctrl+C 退出。", flush=True)
        while True:
            try:
                page.wait_for_timeout(1000)
            except KeyboardInterrupt:
                break
    except KeyboardInterrupt:
        pass
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        if p:
            try:
                p.stop()
            except Exception:
                pass
        proxy.stop()
        print("\n已退出。", flush=True)


if __name__ == "__main__":
    main()
