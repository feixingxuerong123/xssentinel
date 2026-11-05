# -*- coding: utf-8 -*-
"""Phase 360 pre-change CLI compatibility probe (measurement, no fixes).

Runs the REAL ``python -m xssentinel`` entry point in a subprocess for every
case.  The point is to find out what a script/agent/CI wrapper actually sees,
not what the code looks like it should do.  Keep this file as the evidence
harness: after the fixes, re-run it and diff the verdicts.

Usage:  python dev/cli_compat_probe.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
COMMON = ["--max-payloads", "1", "--max-transforms", "1",
          "--dom-engine", "static"]
BASE_ENV = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost"}


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        body = ("<html><body><div id=out>\u4e2d\u6587" + q +
                "</div></body></html>").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def cli(args, stdin=None, env=None, timeout=60):
    e = {**BASE_ENV, **(env or {})}
    try:
        r = subprocess.run([PY, "-m", "xssentinel", *args], cwd=ROOT,
                           env=e, input=stdin, capture_output=True,
                           timeout=timeout)
        return {"rc": r.returncode, "out": r.stdout, "err": r.stderr}
    except subprocess.TimeoutExpired:
        return {"rc": "TIMEOUT", "out": b"", "err": b""}


def frame_count(raw):
    """How many valid JSON objects are on stdout, and what else is there."""
    good, junk = 0, []
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                good += 1
            else:
                junk.append(line[:120])
        except ValueError:
            junk.append(line[:120])
    return good, junk


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]
    tmp = os.path.join(ROOT, "dev", "_cli_compat_tmp")
    os.makedirs(tmp, exist_ok=True)

    results = []

    def add(group, name, r, detail=None):
        results.append({
            "group": group,
            "name": name,
            "rc": r["rc"],
            "stdout_bytes": len(r["out"]),
            "stderr_bytes": len(r["err"]),
            "stdout_head": r["out"][:200].decode("utf-8", "replace"),
            "stderr_head": r["err"][:200].decode("utf-8", "replace"),
            "detail": detail or {},
        })

    # --- A. self description / version -----------------------------------
    for flag in ("--version", "-V", "version"):
        add("A.version", flag, cli([flag]))
    add("A.version", "--help", cli(["--help"]))
    for sub in ("serve --help", "mcp --help", "selftest --help"):
        add("A.version", sub, cli(sub.split()))
    add("A.version", "unknown-first-arg", cli(["nonsense"]))
    add("A.version", "help-subcommand", cli(["help"]))

    # --- B. argument parsing ---------------------------------------------
    add("B.parse", "--url=equals",
        cli(["--url=" + target, "-o", "-", "-f", "json", *COMMON]))
    add("B.parse", "-o-attached",
        cli(["-u", target, "-o-", "-f", "json", *COMMON]))
    add("B.parse", "--separator",
        cli(["--", "-u", target]))
    add("B.parse", "abbrev--form",
        cli(["-u", target, "--form", "json", "-o", "-", *COMMON]))
    add("B.parse", "abbrev--max-p",
        cli(["-u", target, "--max-p", "1", "-o", "-", "-f", "json", *COMMON]))
    add("B.parse", "unknown-flag", cli(["--no-such-flag"]))
    add("B.parse", "bad-int", cli(["-u", target, "--max-payloads=abc"]))
    add("B.parse", "batch-stdin-plus-u",
        cli(["--batch-stdin", "-u", target, "-o", "-", "-f", "json", *COMMON],
            stdin=(target + "\n").encode()))

    # --- C. pipeline contract (real scan) --------------------------------
    base = ["-u", target, "-o", "-", "-f", "json", *COMMON]
    r = cli(base)
    good, junk = frame_count(r["out"])
    add("C.pipe", "baseline", r, {"json_frames": good, "junk": junk[:4]})

    variants = {
        "login-token": ["--login-token", "T"],
        "login-basic": ["--login-basic", "u:p"],
        "ai-report": ["--ai-report"],
        "fuzz": ["--fuzz"],
        "discover": ["--discover"],
        "async": ["--async"],
    }
    for name, extra in variants.items():
        r = cli([*base, *extra])
        good, junk = frame_count(r["out"])
        add("C.pipe", name, r, {"json_frames": good, "junk": junk[:6]})

    add("C.pipe", "nuclei-to-stdout",
        cli(["-u", target, "-o", "-", "-f", "nuclei", *COMMON]))
    add("C.pipe", "batch-nuclei-to-stdout",
        cli(["--batch-stdin", "-o", "-", "-f", "nuclei", *COMMON],
            stdin=(target + "\n").encode()))

    # Broken pipe: consumer closes after the first byte.
    p = subprocess.Popen([PY, "-m", "xssentinel", *base], cwd=ROOT,
                         env=BASE_ENV, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    try:
        first = p.stdout.read(1)
        p.stdout.close()
        _, err = p.communicate(timeout=60)
        add("C.pipe", "broken-pipe", {"rc": p.returncode, "out": first,
                                      "err": err}, {"closed_after": 1})
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        add("C.pipe", "broken-pipe", {"rc": "TIMEOUT", "out": b"",
                                      "err": b""})

    # --- D. encoding ------------------------------------------------------
    add("D.encoding", "cp936-stdout-json",
        cli(base, env={"PYTHONIOENCODING": "cp936"}))
    add("D.encoding", "cp936-error-path",
        cli(["--batch", os.path.join(tmp, "nope.txt"), "-o", "-",
             "-f", "json"], env={"PYTHONIOENCODING": "cp936"}))

    cfg_ascii = os.path.join(tmp, "cfg_bom.json")
    with open(cfg_ascii, "wb") as f:
        f.write(b"\xef\xbb\xbf" + json.dumps(
            {"url": target, "max_payloads": 1}).encode("utf-8"))
    cfg_gbk = os.path.join(tmp, "cfg_gbk.json")
    with open(cfg_gbk, "wb") as f:
        f.write(json.dumps({"url": target, "note": "\u4e2d\u6587"},
                           ensure_ascii=False).encode("gbk"))
    for name, path in (("config-utf8-bom", cfg_ascii),
                       ("config-gbk", cfg_gbk)):
        add("D.encoding", name, cli(["--config", path, "-o", "-",
                                     "-f", "json", *COMMON]))

    # --- E. exit codes ----------------------------------------------------
    for name, args in (("no-target", []), ("help", ["--help"]),
                       ("unknown-flag", ["--no-such-flag"]),
                       ("batch-missing-file",
                        ["--batch", os.path.join(tmp, "missing.txt")]),
                       ("batch-empty-stdin",
                        ["--batch-stdin", "-f", "json"])):
        add("E.exit", name, cli(args, stdin=b""))

    # --- F. environment ---------------------------------------------------
    add("F.env", "NO_COLOR", cli(["-u", target, *COMMON],
                                 env={"NO_COLOR": "1"}))
    add("F.env", "FORCE_COLOR", cli(["-u", target, *COMMON],
                                    env={"FORCE_COLOR": "1"}))

    srv.shutdown()
    srv.server_close()

    out = {"probe": "phase360-cli-compat", "python": sys.version,
           "cases": results}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
