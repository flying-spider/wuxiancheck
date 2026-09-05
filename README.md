# vivo 无限查询（Python 版）

代理池浏览器：后台从 91http 拉取代理、通过 curl_cffi 多 TLS 指纹检测质量、自动换 IP，
渲染层用 Camoufox（Firefox 内核，C++ 层随机浏览器指纹）。

## 环境要求

- Python 3.10+（本机可用 uv 自动装 3.12）

## 安装

```bash
# 1. 建虚拟环境（用 uv，自动下载 Python 3.12）
uv venv --python 3.12 .venv

# 2. 装依赖
uv pip install -r requirements.txt

# 3. 下载 Camoufox 浏览器内核（约 300MB，需联网）
.venv/bin/python -m camoufox fetch
```

## 运行

```bash
.venv/bin/python main.py
```

首次启动：在「设置」里填 trade_no 与 secret，保存后自动开始拉取并检测优质 IP，
拿到第一个代理后自动用 Camoufox 打开 https://userappeal.vivo.com.cn/#/index，
每次换 IP 会重启浏览器上下文并带上新的随机指纹。

## 说明

- 质量检测请求走 curl_cffi（`impersonate="chrome"`），可在 `check_proxy_quality`
  里改成 `firefox` / `safari` 切换不同 TLS 指纹（JA3）。
- 渲染层 Camoufox 默认 `humanize=True`，每次启动自动生成一套自洽的随机浏览器指纹。

## 打包 Windows exe

PyInstaller 不能跨平台交叉编译，用 GitHub Actions 的 `windows-latest` 运行器出 exe：

1. 把代码推到本仓库，到 Actions 页面点 `Run workflow`（或 push 到 main 自动触发）。
2. 构建脚本见 [.github/workflows/build-windows.yml](.github/workflows/build-windows.yml)：
   自动 `camoufox fetch` 下载 Windows 版 Firefox 内核，再用 PyInstaller 打成单个 exe。
3. 构建完成后在 Artifacts 里下载 `vivo-wuxian-windows`。

注意：首次打包会下载 Camoufox 内核（约 300MB，CI 网络快）。exe 未签名，
Windows 双击会弹 SmartScreen「未知发布者」，点「更多信息 → 仍要运行」即可。
产物务必在 Windows 真机上跑一遍验证。

