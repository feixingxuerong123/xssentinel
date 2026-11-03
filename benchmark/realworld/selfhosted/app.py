#!/usr/bin/env python3
"""Self-hosted third-party-style XSS target for benchmark/realworld.

Deliberately independent of xssentinel's own 194-case fixture.  Four faces:

  * reflected  -- /reflect?q=... (raw) and /reflect-safe (escaped control)
  * stored     -- /guestbook (SQLite-backed; another session sees it)
  * login/roles-- admin/adminpass (admin) and alice/alicepass (user)
  * header     -- /header reflects User-Agent and X-Forwarded-For raw

Everything is localhost-only, stdlib-only.  Start:

    python benchmark/realworld/selfhosted/app.py --port 8090

Ground truth is by construction plus an independent Playwright dialog check;
this target is NOT part of the 194-case self-authored matrix.
"""
from __future__ import annotations

import argparse
import html
import json
import secrets
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERS = {"admin": ("adminpass", "admin"), "alice": ("alicepass", "user")}
SESSIONS: dict[str, str] = {}
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE comments (id INTEGER PRIMARY KEY, user TEXT, body TEXT)")
DB.commit()

LOGIN_FORM = """
<form method="post" action="/login">
  <p><label>User <input name="user" value="alice"></label></p>
  <p><label>Pass <input name="pass" type="password" value="alicepass"></label></p>
  <p><button name="go" value="1">Login</button></p>
</form>"""


def _page(title: str, body: str, user: str | None = None) -> str:
    who = f" <span class='who'>[{html.escape(user)}]</span>" if user else ""
    return (f"<!doctype html><html><head><meta charset='utf-8'>"
            f"<title>{html.escape(title)}</title></head><body>"
            f"<nav><a href='/'>home</a> | <a href='/reflect'>reflect</a> | "
            f"<a href='/guestbook'>guestbook</a> | <a href='/header'>header</a>"
            f"{who}</nav><h1>{html.escape(title)}</h1>{body}</body></html>")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: str, status: int = 200, ctype="text/html",
              headers=None):
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _user(self):
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v in SESSIONS:
                return SESSIONS[v]
        return None

    def _require(self, role=None):
        user = self._user()
        if not user:
            self._send(_page("login required", LOGIN_FORM), 401)
            return None
        if role and USERS[user][1] != role:
            self._send(_page("forbidden", "<p>403</p>", user), 403)
            return None
        return user

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        user = self._user()
        if path == "/":
            self._send(_page("self-hosted xss lab",
                             "<p>Login as admin/adminpass or alice/alicepass.</p>"
                             + LOGIN_FORM, user))
        elif path == "/health":
            self._send(json.dumps({"ok": True}), ctype="application/json")
        elif path == "/reflect":
            q = (query.get("q") or [""])[0]
            self._send(_page("reflect", f"<div class='result'>{q}</div>", user))
        elif path == "/reflect-safe":
            q = (query.get("q") or [""])[0]
            self._send(_page("reflect-safe",
                             f"<div class='result'>{html.escape(q)}</div>", user))
        elif path == "/guestbook":
            u = self._require()
            if not u:
                return
            rows = DB.execute("SELECT user, body FROM comments").fetchall()
            items = "".join(f"<li>{html.escape(n)}: {b}</li>" for n, b in rows)
            form = ("<form method='post' action='/guestbook'>"
                    "<input name='body'><button>Post</button></form>")
            self._send(_page("guestbook", form + f"<ul>{items}</ul>", u))
        elif path == "/header":
            u = self._require()
            if not u:
                return
            ua = self.headers.get("User-Agent", "")
            xff = self.headers.get("X-Forwarded-For", "")
            self._send(_page("header", f"<div>UA: {ua}</div>"
                             f"<div>XFF: {xff}</div>", u))
        elif path == "/header-safe":
            ua = html.escape(self.headers.get("User-Agent", ""))
            self._send(_page("header-safe", f"<div>UA: {ua}</div>", user))
        elif path == "/admin":
            u = self._require(role="admin")
            if not u:
                return
            rows = DB.execute("SELECT user, body FROM comments").fetchall()
            items = "".join(f"<li>{b}</li>" for _, b in rows)
            users = "".join(f"<li>{n} ({USERS[n][1]})</li>" for n in USERS)
            self._send(_page("admin", f"<h2>users</h2><ul>{users}</ul>"
                             f"<h2>comments</h2><ul>{items}</ul>", u))
        else:
            self._send(_page("not found", "<p>404</p>", user), 404)

    def do_POST(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/login":
            length = int(self.headers.get("Content-Length") or 0)
            data = urllib.parse.parse_qs(
                self.rfile.read(length).decode("utf-8", "replace"))
            name = (data.get("user") or [""])[0]
            password = (data.get("pass") or [""])[0]
            if name in USERS and USERS[name][0] == password:
                sid = secrets.token_hex(16)
                SESSIONS[sid] = name
                self._send("", status=302, headers={
                    "Location": "/",
                    "Set-Cookie": f"sid={sid}; Path=/; HttpOnly"})
            else:
                self._send(_page("login failed", LOGIN_FORM), 401)
            return
        if parsed.path == "/guestbook":
            u = self._require()
            if not u:
                return
            length = int(self.headers.get("Content-Length") or 0)
            data = urllib.parse.parse_qs(
                self.rfile.read(length).decode("utf-8", "replace"))
            body = (data.get("body") or [""])[0]
            DB.execute("INSERT INTO comments(user, body) VALUES (?, ?)",
                       (u, body))
            DB.commit()
            self._send("", status=302, headers={"Location": "/guestbook"})
            return
        self._send(_page("not found", "<p>404</p>"), 404)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"self-hosted xss target on http://{args.host}:{args.port}")
    srv.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
