# -*- coding: utf-8 -*-
"""Window backends for the XSSentinel desktop console.

Three backends, tried in order.  The console itself is a single HTML page
served by the in-process REST API, so a "window" is all this module owes the
rest of the app:

  1. ``pywebview``  -- a real native window backed by the OS webview
     (Edge WebView2 on Windows, already present on any supported box).
     Optional dependency: ``pip install pywebview``.
  2. ``tkinter``    -- a small native window that hosts the URL plus a
     "reopen in browser" action.  Always available (ships with CPython),
     but it cannot embed a browser engine, so it is a control surface
     rather than the console itself.
  3. ``browser``    -- hand the URL to the OS default browser.  Zero
     dependencies, works everywhere.

Nothing here is allowed to import a GUI library at module scope: importing
this module on a headless box (CI) must not fail.
"""
from __future__ import annotations

import threading
import webbrowser

BACKEND_PYWEBVIEW = "pywebview"
BACKEND_TKINTER = "tkinter"
BACKEND_BROWSER = "browser"


def pywebview_available() -> bool:
    """Whether the optional native-window dependency is importable."""
    try:
        import webview  # noqa: F401  (probe only)
        return True
    except Exception:
        return False


def tkinter_available() -> bool:
    """Whether tkinter can actually create a window (import + display)."""
    try:
        import tkinter  # noqa: F401
    except Exception:
        return False
    # A headless box imports tkinter fine but cannot open a display; probing
    # it without a real Tk() call would report a backend that then dies.
    try:
        root = __import__("tkinter").Tk()
        root.destroy()
        return True
    except Exception:
        return False


def _open_with_pywebview(url: str, title: str,
                         on_close=None) -> bool:
    """Open the console in a native webview window.  Blocks until closed."""
    try:
        import webview
    except Exception:
        return False
    windows = webview.create_window(title, url, width=1280, height=860,
                                    min_size=(960, 600))
    # on_closed fires when the user dismisses the window; that is our cue to
    # stop the API thread too, or the process would linger headless.
    if on_close is not None:
        try:
            windows.events.closed += on_close
        except Exception:
            pass
    try:
        webview.start()
    except Exception:
        return False
    return True


def _open_with_tkinter(url: str, title: str, on_close=None) -> bool:
    """Open a small native window that frames the console URL.

    tkinter cannot host a browser engine, so this backend is a launcher:
    it shows the address, keeps the API process alive while it is open, and
    offers a one-click "open in browser" plus copy-to-clipboard.
    """
    try:
        import tkinter as tk
    except Exception:
        return False
    try:
        root = tk.Tk()
    except Exception:
        return False
    root.title(title)
    root.geometry("520x180")
    root.minsize(420, 150)
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass

    tk.Label(root, text="XSSentinel 控制台地址", anchor="w").pack(
        fill="x", padx=12, pady=(12, 2))
    entry = tk.Entry(root, justify="left")
    entry.insert(0, url)
    entry.configure(state="readonly")
    entry.pack(fill="x", padx=12)

    hint = tk.Label(root, anchor="w", fg="#666666",
                    text="未安装 pywebview，无法内嵌浏览器窗口。\n"
                         "点「在浏览器中打开」使用完整控制台；"
                         "pip install pywebview 后可获得原生窗口。")
    hint.pack(fill="x", padx=12, pady=(6, 0))

    def _copy():
        root.clipboard_clear()
        root.clipboard_append(url)

    bar = tk.Frame(root)
    bar.pack(fill="x", padx=12, pady=10)
    tk.Button(bar, text="在浏览器中打开",
              command=lambda: webbrowser.open(url)).pack(side="left")
    tk.Button(bar, text="复制地址", command=_copy).pack(side="left", padx=8)
    tk.Button(bar, text="退出", command=root.destroy).pack(side="right")

    if on_close is not None:
        root.protocol("WM_DELETE_WINDOW", lambda: (root.destroy(), on_close()))
    root.mainloop()
    return True


def _open_with_browser(url: str, title: str, on_close=None) -> bool:
    """Last resort: hand the URL to the OS browser (non-blocking)."""
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def open_console(url: str, title: str = "XSSentinel 桌面控制台",
                 on_close=None, prefer: str | None = None) -> str:
    """Open the console window, returning the backend that was used.

    ``prefer`` forces a backend (mainly for tests); otherwise the order is
    pywebview -> tkinter -> browser.  When no GUI backend can be opened the
    browser is used, and its return is immediate -- the caller keeps running
    until the user interrupts it.
    """
    order = [BACKEND_PYWEBVIEW, BACKEND_TKINTER, BACKEND_BROWSER]
    if prefer is not None:
        if prefer not in order:
            raise ValueError(f"unknown backend {prefer!r}")
        order = [prefer]

    for backend in order:
        if backend == BACKEND_PYWEBVIEW and not pywebview_available():
            continue
        if backend == BACKEND_TKINTER and not tkinter_available():
            continue
        opener = {
            BACKEND_PYWEBVIEW: _open_with_pywebview,
            BACKEND_TKINTER: _open_with_tkinter,
            BACKEND_BROWSER: _open_with_browser,
        }[backend]
        try:
            if opener(url, title, on_close):
                return backend
        except Exception:
            continue
    return ""


def run_blocking(url: str, title: str = "XSSentinel 桌面控制台",
                 on_close=None, prefer: str | None = None) -> str:
    """Open the console and keep the process alive until it is dismissed.

    The browser backend returns immediately (it only spawns the OS
    browser), so this variant parks the calling thread until ``on_close``
    fires or the user hits Ctrl-C -- otherwise ``main()`` would exit and
    take the API server with it.
    """
    used = open_console(url, title=title, on_close=on_close, prefer=prefer)
    if used == BACKEND_BROWSER:
        # No window exists to close, so nothing will ever invoke on_close;
        # park until the user interrupts, then shut the API down explicitly.
        print("[*] 已在默认浏览器中打开控制台。按 Ctrl-C 停止 API 并退出。")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
        finally:
            if on_close is not None:
                on_close()
    return used
