# -*- coding: utf-8 -*-
"""Range #7 -- a legacy CMS built on the Python standard library only.

Why another range: ranges 3-6 and the 194-case benchmark were all written
inside this repository, and a scanner can quietly fit the harness it was
tuned on.  This one is deliberately different in every superficial way
that a scanner could over-fit to:

  * stdlib ``http.server`` + SQLite (no framework, no templating engine);
  * table-based layout, a ``<title>``-less page, a session cookie;
  * four sink shapes the benchmark expresses differently: a quoted
    attribute value, a ``<script>`` config line, a stored comment thread,
    and a hash-routed DOM sink that decodes the fragment first (the
    Phase 265 lesson: Chromium percent-encodes '<').

Each vulnerable route has a twin that is safe BY CONSTRUCTION (escaping or
``textContent``), so a scanner that reports the twin is a false positive
rather than a judgement call.

Construction validity is not assumed: ``tests/test_range7_construct.py``
injects a marker into every ``-safe`` route and asserts the served bytes
never carry it raw, and that every vulnerable route does.
"""
from __future__ import annotations

import html
import os
import sqlite3
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_DB = os.path.join(tempfile.gettempdir(), "range7.sqlite3")
_LOCK = threading.Lock()

PAGE = ("<html><body><table width=800><tr><td>"
        "<h2>{title}</h2>{body}</td></tr></table></body></html>")


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS comments "
                 "(id INTEGER PRIMARY KEY, kind TEXT, text TEXT)")
    return conn


def _reset_store() -> None:
    with _LOCK:
        conn = _db()
        conn.execute("DELETE FROM comments")
        conn.commit()
        conn.close()


def _add_comment(kind: str, text: str) -> None:
    with _LOCK:
        conn = _db()
        conn.execute("INSERT INTO comments(kind, text) VALUES (?,?)",
                     (kind, text))
        conn.commit()
        conn.close()


def _comments(kind: str) -> list[str]:
    with _LOCK:
        conn = _db()
        rows = [r[0] for r in conn.execute(
            "SELECT text FROM comments WHERE kind=? ORDER BY id", (kind,))]
        conn.close()
    return rows


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


# --- pages ---------------------------------------------------------------

def page_index() -> str:
    links = [
        ("Search", "/search?q=book"),
        ("Search (escaped)", "/search-safe?q=book"),
        ("Widget", "/widget?cfg=dark"),
        ("Widget (safe)", "/widget-safe?cfg=dark"),
        ("Thread", "/thread"),
        ("Thread (safe)", "/thread-safe"),
        ("Profile", "/profile#bio"),
        ("Profile (safe)", "/profile-safe#bio"),
        ("Preview", "/preview?name=ada"),
        ("Preview (safe)", "/preview-safe?name=ada"),
        ("Admin", "/admin"),
        ("Admin (safe)", "/admin-safe"),
    ]
    body = "<ul>" + "".join(
        f'<li><a href="{u}">{_esc(t)}</a></li>' for t, u in links) + "</ul>"
    return PAGE.format(title="Range7 CMS", body=body)


def page_search(q: str, safe: bool) -> str:
    val = _esc(q) if safe else (q or "")
    return PAGE.format(
        title="Search",
        body=(f'<form action="/search" method="get">'
              f'<input name="q" value="{val}"></form>'
              f'<p>Results for <b>{val}</b></p>'))


def page_widget(cfg: str, safe: bool) -> str:
    # Escape the JS string delimiters either way; the DIFFERENCE is whether
    # '<' survives, i.e. whether the payload can close the script element.
    s = (cfg or "").replace("\\", "\\\\").replace('"', '\\"')
    if safe:
        s = s.replace("<", "\\x3c")
    return ("<html><body><div id=w>x</div><script>var cfg = \""
            + s +
            "\";document.getElementById('w').textContent = cfg;</script>"
            "</body></html>")


def page_profile(safe: bool) -> str:
    sink = ("document.getElementById('out').textContent = h;"
            if safe else
            "document.getElementById('out').innerHTML = h;")
    return ("<html><body><h2>Profile</h2><div id=out>bio</div>"
            "<script>var h = decodeURIComponent("
            "(location.hash||'').slice(1));" + sink + "</script></body></html>")


def page_preview(name: str, safe: bool) -> str:
    """A <script type=application/json> config block the page then renders.

    Distinct from the /widget face: the payload sits inside a JSON string
    inside a script element, so BOTH the element close and the JSON string
    are in play.  The safe twin escapes '<' the way a JSON encoder does
    (\u003c), which is what a real app would emit.
    """
    if safe:
        # NOT \u003c: that is a JSON escape, and JSON.parse turns it back
        # into '<' right before the innerHTML assignment -- measured, the
        # "safe" twin still executed the breakout payload, so the scanner
        # reported a browser-confirmed high on it (a range bug, not a
        # scanner bug).  The sink is innerHTML, so escape for HTML.
        name = _esc(name or "")
    return ("<html><body><div id=p>x</div>"
            '<script type="application/json" id=cfg>{"name":"'
            + (name or "") +
            '"}</script><script>'
            "var o = JSON.parse(document.getElementById('cfg').textContent);"
            "document.getElementById('p').innerHTML = o.name;"
            "</script></body></html>")


def page_admin(kind: str, safe: bool) -> str:
    """Second-order view: the value was stored by a DIFFERENT endpoint."""
    items = "".join(
        f"<div class=nm>{_esc(t) if safe else t}</div>"
        for t in _comments(kind))
    return PAGE.format(title="Admin", body=items or "<p>no profile</p>")


def page_thread(kind: str, safe: bool) -> str:
    items = "".join(
        f"<div class=cm>{_esc(t) if safe else t}</div>"
        for t in _comments(kind))
    return PAGE.format(title="Thread", body=items or "<p>no comments</p>")


# --- handler -------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the runner output readable
        pass

    def _send(self, status: int, body: str, extra: dict | None = None):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to: str):
        self.send_response(302)
        self.send_header("Location", to)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802
        u = urlparse(self.path)
        q = parse_qs(u.query)
        val = (q.get("q") or [""])[0]
        cfg = (q.get("cfg") or [""])[0]
        name = (q.get("name") or [""])[0]
        routes = {
            "/": lambda: self._send(200, page_index()),
            "/search": lambda: self._send(200, page_search(val, False)),
            "/search-safe": lambda: self._send(200, page_search(val, True)),
            "/widget": lambda: self._send(200, page_widget(cfg, False)),
            "/widget-safe": lambda: self._send(200, page_widget(cfg, True)),
            "/thread": lambda: self._send(200, page_thread("raw", False)),
            "/thread-safe": lambda: self._send(200, page_thread("safe", True)),
            "/preview": lambda: self._send(200, page_preview(name, False)),
            "/preview-safe": lambda: self._send(200, page_preview(name, True)),
            "/admin": lambda: self._send(200, page_admin("profile", False)),
            "/admin-safe": lambda: self._send(200, page_admin("profile_safe", True)),
            "/profile": lambda: self._send(200, page_profile(False)),
            "/profile-safe": lambda: self._send(200, page_profile(True)),
        }
        fn = routes.get(u.path)
        if fn is None:
            self._send(404, PAGE.format(title="404", body="not found"))
            return
        fn()

    def do_POST(self):  # noqa: N802
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        form = parse_qs(raw)
        text = (form.get("text") or form.get("comment")
                or form.get("name") or [""])[0]
        if u.path == "/comment":
            _add_comment("raw", text)
            self._redirect("/thread")
            return
        if u.path == "/comment-safe":
            _add_comment("safe", text)
            self._redirect("/thread-safe")
            return
        if u.path == "/settings":
            _add_comment("profile", text)
            self._redirect("/admin")
            return
        if u.path == "/settings-safe":
            _add_comment("profile_safe", text)
            self._redirect("/admin-safe")
            return
        self._send(404, PAGE.format(title="404", body="not found"))


def run_server(port: int = 19707, ready_callback=None):
    _reset_store()
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if ready_callback:
        ready_callback(srv)
    srv.serve_forever()
    return srv


if __name__ == "__main__":
    import sys
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 19707
    print(f"[*] Range7 on http://127.0.0.1:{p}")
    run_server(p)
