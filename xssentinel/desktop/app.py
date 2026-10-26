# -*- coding: utf-8 -*-
"""XSSentinel desktop console -- one process, one window, zero extra services.

The console is the project's own REST API (``xssentinel.api.server``) plus a
single HTML page, started in-process and bound to loopback only:

  * the API server runs in a daemon thread on ``127.0.0.1`` (ephemeral port
    by default, so it cannot collide with a ``--serve`` deployment);
  * the HTML page is served from the SAME origin, which is what the API's
    same-origin gate (Phase 70) requires -- a ``file://`` page would be
    blocked from every mutating call;
  * a native window (pywebview/WebView2) frames that origin; when no GUI
    toolkit is available the URL is handed to the OS browser instead.

Nothing in the API module is edited: the UI route is appended to the shared
route table by :func:`install_ui_route`, which is idempotent and only ever
adds ``GET /``.
"""
from __future__ import annotations

import argparse
import re
import sys
import threading

from . import shell
from .assets import load_ui_html

_UI_ROUTE_PATTERN = r"^/$"


def install_ui_route() -> bool:
    """Serve the console page at ``GET /`` on the shared route table.

    Idempotent.  The table is described in ``api/server.py`` as "canonical,
    shared by both backends", so appending one GET route is the supported
    way to extend it; the alternative (forking the handler class) would
    silently diverge the two front-ends.
    """
    from xssentinel.api import server as api

    for _method, regex, _handler in api._ROUTES:
        if regex.pattern == _UI_ROUTE_PATTERN:
            return False

    def _serve_ui(ctx, match, body, query):
        # The console renders scanner output (URLs, payloads, snippets) and
        # can hold an API key in the tab.  Keep it same-origin, un-framable
        # and un-sniffable.  The page is a single self-contained file, so the
        # only inline allowances are its own <style>/<script> blocks.
        headers = {
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'unsafe-inline'; "
                "style-src 'unsafe-inline'; img-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'none'"
            ),
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        }
        return api.Response(200, load_ui_html().encode("utf-8"),
                            headers=headers,
                            content_type="text/html; charset=utf-8")

    api._ROUTES.append(("GET", re.compile(_UI_ROUTE_PATTERN), _serve_ui))
    return True


def build_server(host: str = "127.0.0.1", port: int = 0,
                 api_key: str | None = None, db_path: str | None = None):
    """Create (but do not start) the in-process API server."""
    from xssentinel.api.server import StdlibServer

    install_ui_route()
    return StdlibServer(host=host, port=port, api_key=api_key,
                        db_path=db_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="xssentinel-desktop",
        description="XSSentinel 桌面控制台（本地 API + 原生窗口）")
    parser.add_argument("--host", default="127.0.0.1",
                        help="绑定地址（默认 127.0.0.1，仅本机可达）")
    parser.add_argument("--port", type=int, default=0,
                        help="端口，0 = 自动分配（默认）")
    parser.add_argument("--api-key", default=None,
                        help="API 密钥；设置后需在控制台右上角的 X-API-Key "
                             "输入框填入同一密钥")
    parser.add_argument("--db", default=None,
                        help="扫描持久化数据库路径（默认用 API 模块自身位置）")
    parser.add_argument("--backend", default=None,
                        choices=[shell.BACKEND_PYWEBVIEW, shell.BACKEND_TKINTER,
                                 shell.BACKEND_BROWSER],
                        help="强制窗口后端（默认自动选择）")
    parser.add_argument("--no-window", action="store_true",
                        help="只启动 API 并打印地址，不开窗口（供脚本/排查用）")
    parser.add_argument("--print-url-only", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    # Loopback-only by construction: a desktop console that binds 0.0.0.0
    # would expose the scanner (and its credentials) to the network, which
    # is the exact thing --serve warns about.
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("[!] 桌面控制台只允许绑定回环地址；如需对外服务请用 "
              "`xssentinel --serve`。", file=sys.stderr)
        return 2

    try:
        server = build_server(host=args.host, port=args.port,
                              api_key=args.api_key, db_path=args.db)
    except Exception as e:
        print(f"[!] 启动失败: {e}", file=sys.stderr)
        return 1

    server.start_in_thread()
    url = server.base_url.rstrip("/") + "/"
    print(f"[+] XSSentinel 桌面控制台: {url}")
    if args.api_key:
        # Phase 263: the console can carry the key now -- it is entered in
        # the page (top-right) and attached as X-API-Key by the page's own
        # fetch wrapper, because embedding it in the HTML would hand it to
        # anything able to GET / and a cookie would mean editing the API's
        # auth gate.
        print("[*] 已启用 API 密钥：打开窗口后点右上角「密钥」，把同一个 "
              "X-API-Key 填进去（只存在该标签页，不写回服务器）")

    if args.print_url_only:
        print(url)
        return 0
    if args.no_window:
        print("[*] --no-window: API 已启动，按 Ctrl-C 停止。")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        return 0

    def _on_close():
        # The window is gone; stop accepting scans and let the process exit.
        try:
            server._httpd.shutdown()
        except Exception:
            pass

    used = shell.run_blocking(url, title="XSSentinel 桌面控制台",
                              on_close=_on_close, prefer=args.backend)
    if used:
        print(f"[*] 窗口后端: {used}")
    else:
        print("[!] 没有可用的窗口后端", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
