# -*- coding: utf-8 -*-
"""Can the CLI actually reach every feature?  (Phase 360 follow-up, 2026-11-06)

Two independent measurements, both against the REAL entry point:

* ``surface``: every program mode, input surface and report format, checking
  that the expected artefact appears and that nothing dies with a traceback.
* ``flag_smoke``: enumerate the parser's actions automatically, give each
  flag a plausible placeholder value and invoke the CLI once.  This is NOT a
  functional test of each feature (the 194-case matrix and the per-feature
  suites do that); it catches the specific shape "the flag parses but the
  code path behind it raises an uncaught exception".

Long-running / externally-conditioned modes are listed with a reason rather
than silently dropped.  Output: dev/_cli_surface_probe.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
TMP = os.path.join(ROOT, "dev", "_cli_surface_tmp")
os.makedirs(TMP, exist_ok=True)
COMMON = ["--max-payloads", "1", "--max-transforms", "1",
          "--dom-engine", "static", "--timeout", "2"]
ENV = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
       "no_proxy": "127.0.0.1,localhost", "PYTHONIOENCODING": "utf-8",
       "PYTHONPATH": ROOT}

CRASH_MARKERS = (b"Traceback (most recent call last)", b"AttributeError",
                 b"NameError", b"UnboundLocalError", b"KeyError",
                 b"TypeError:", b"ImportError", b"ModuleNotFoundError")


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        self._reply()

    def do_POST(self):
        self._reply()

    def _reply(self):
        # Reflect q: without a real finding, --verify-fix and -f nuclei have
        # nothing to work on, and the probe would wrongly call those modes
        # broken.  (The first run used a static page -> 0 findings.)
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        body = ("<html><body><div id=out>" + q +
                "</div></body></html>").encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class QuietServer(ThreadingHTTPServer):
    """Clients closed early in a smoke run are not product tracebacks."""

    def handle_error(self, request, client_address):
        pass


def run(args, stdin=None, timeout=25, cwd=None):
    try:
        r = subprocess.run([PY, "-m", "xssentinel", *args], cwd=cwd or TMP,
                           env=ENV, input=stdin, capture_output=True,
                           timeout=timeout)
        return {"rc": r.returncode, "out": len(r.stdout),
                "err": len(r.stderr),
                "out_head": r.stdout[:200].decode("utf-8", "replace"),
                "err_head": r.stderr[:220].decode("utf-8", "replace"),
                "crash": any(m in r.stderr for m in CRASH_MARKERS)}
    except subprocess.TimeoutExpired:
        return {"rc": "TIMEOUT", "out": 0, "err": 0, "err_head": "",
                "crash": False}


def long_running(args, wait=2.5, stdin=None):
    """Start a server-style mode and check it stays up (then terminate)."""
    p = subprocess.Popen([PY, "-m", "xssentinel", *args], cwd=TMP,
                         env=ENV, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        if stdin is not None:
            p.stdin.write(stdin)
            p.stdin.flush()
        p.wait(timeout=wait)
        rc, alive = p.returncode, False
    except subprocess.TimeoutExpired:
        rc, alive = None, True
    finally:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        err = p.stderr.read() if p.stderr else b""
        out = p.stdout.read() if p.stdout else b""
    return {"rc": rc if rc is not None else "running", "alive": alive,
            "out": len(out), "err": len(err),
            "out_head": out[:160].decode("utf-8", "replace"),
            "err_head": err[:220].decode("utf-8", "replace"),
            "crash": any(m in err for m in CRASH_MARKERS)}


def fixture(name, data):
    p = os.path.join(TMP, name)
    mode = "wb" if isinstance(data, bytes) else "w"
    kw = {} if isinstance(data, bytes) else {"encoding": "utf-8"}
    with open(p, mode, **kw) as f:
        f.write(data)
    return p


def main():
    srv = QuietServer(("127.0.0.1", 0), Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = "http://127.0.0.1:%d" % srv.server_address[1]
    target = host + "/?q=probe"

    har = json.dumps({"log": {"version": "1.2", "entries": [
        {"request": {"method": "GET", "url": target, "headers": [],
                     "cookies": [], "postData": None},
         "response": {"status": 200, "statusText": "ok"}}]}})
    oas = json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                      "servers": [{"url": host}],
                      "paths": {"/x": {"get": {"responses": {
                          "200": {"description": "ok"}}}}}})
    smap = ('<?xml version="1.0"?><urlset><url><loc>' + target +
            '</loc></url></urlset>')
    # bytes fixture: text-mode writing on Windows turns CRLF into CRCRLF,
    # which is not a valid raw HTTP request (and used to make the probe
    # report a product crash for a broken test file).
    raw = ("GET /?q=probe HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" %
           srv.server_address[1]).encode("ascii")
    fuzz_body = '{"q": "FUZZ"}'
    f = {k: fixture(k, v) for k, v in {
        "har.json": har, "oas.json": oas, "sitemap.xml": smap,
        "raw.txt": raw, "fuzz.txt": fuzz_body,
        "urls.txt": target + "\n",
        "placeholder.txt": "1\n",
    }.items()}
    # A REAL report (the loopback target reflects q, so it has findings)
    # for --verify-fix / --diff, whose "no findings" branch is an honest
    # rc=2 rather than a reachable feature path.
    real_report = os.path.join(TMP, "scan_report.json")
    run(["-u", target, "-o", real_report, "-f", "json", *COMMON])

    surface = []

    def add(name, result, expect=None):
        surface.append({"name": name, **result, "expect": expect})

    # --- program modes ---------------------------------------------------
    for sub in ("scan", "serve", "mcp", "selftest"):
        add("mode:" + sub + ":help",
            run([sub, "--help"], timeout=20), "rc 0 + help on stdout")
    add("mode:sandbox", run(["--sandbox", "<script>alert(1)</script>"]))
    add("mode:sandbox-hosts", run(["--sandbox-hosts"]))
    # --ai-check probes every configured LLM provider; on an offline host
    # that is minutes, not seconds.  It is a real external dependency, so
    # give it a longer leash and report the timeout as such.
    add("mode:ai-check", run(["--ai-check", "--ai-timeout", "2"],
                             timeout=120),
        "bounded probe of every LLM provider (needs network)")
    add("mode:verify-fix", run(["--verify-fix", real_report,
                                "-o", os.path.join(TMP, "vf.html")]))
    add("mode:diff", run(["--diff", real_report, real_report,
                          "-o", os.path.join(TMP, "diff.html")]))
    add("mode:save-config", run(["--save-config",
                                 os.path.join(TMP, "saved.json"),
                                 "-u", target]))
    # --fuzz-body takes the body TEXT; a file needs the '@' prefix.
    add("mode:fuzz-body", run(["--fuzz-body", "@" + f["fuzz.txt"],
                               "-u", target, "--fuzz-max", "1", *COMMON]))
    # server-style: must stay up, not exit immediately
    add("mode:serve", long_running(["--serve", "--port", "0"]),
        "stays alive")
    add("mode:passive", long_running(["--passive", "--proxy-port", "0"]),
        "stays alive")
    mcp_frame = json.dumps({"jsonrpc": "2.0", "id": 1,
                            "method": "tools/list", "params": {}}) + "\n"
    add("mode:mcp-frame", long_running(["--mcp"], wait=3.0,
                                       stdin=mcp_frame.encode()),
        "answers tools/list on stdout")
    # Bound the suite on purpose: we are measuring whether the CLI can
    # REACH it (server starts on a free port), not re-running the whole
    # minutes-long self-test.
    selftest_env = {**ENV, "XSSentinel_SELFTEST_TIMEOUT": "8"}
    try:
        st = subprocess.run([PY, "-m", "xssentinel", "--self-test"],
                            cwd=TMP, env=selftest_env, capture_output=True,
                            timeout=90)
        add("mode:self-test-start",
            {"rc": st.returncode, "out": len(st.stdout), "err": len(st.stderr),
             "out_head": st.stdout[:200].decode("utf-8", "replace"),
             "err_head": st.stderr[:220].decode("utf-8", "replace"),
             "crash": any(m in st.stderr for m in CRASH_MARKERS),
             "ready": b"Vuln server ready" in st.stdout},
            "reaches 'Vuln server ready' (suite bounded to 8s)")
    except subprocess.TimeoutExpired:
        add("mode:self-test-start", {"rc": "TIMEOUT", "out": 0, "err": 0,
                                     "err_head": "", "crash": False})

    # --- input surfaces --------------------------------------------------
    inputs = {
        "batch": ["--batch", f["urls.txt"]],
        "batch-stdin": ["--batch-stdin"],
        "har": ["--har", f["har.json"]],
        "openapi": ["--openapi", f["oas.json"]],
        "sitemap": ["--sitemap", f["sitemap.xml"],
                    "--allow-host", "127.0.0.1"],
        "raw-request": ["--raw-request", f["raw.txt"]],
    }
    for name, args in inputs.items():
        stdin = (target + "\n").encode() if name == "batch-stdin" else None
        add("input:" + name,
            run([*args, "-o", os.path.join(TMP, name + ".json"),
                 "-f", "json", *COMMON], stdin=stdin, timeout=60),
            "rc 0 + report written")

    # --- report formats --------------------------------------------------
    for fmt in ("html", "json", "csv", "sarif", "junit", "markdown",
                "burp", "nuclei"):
        out = os.path.join(TMP, "fmt_" + fmt)
        r = run(["-u", target, "-o", out, "-f", fmt, *COMMON])
        import glob as _glob
        made = (os.path.isdir(out) and bool(os.listdir(out))) if fmt == "nuclei" \
            else any(os.path.isfile(p) and os.path.getsize(p) > 0
                     for p in _glob.glob(out + "*"))
        r["artefact"] = bool(made)
        add("format:" + fmt, r, "rc 0 + non-empty artefact")

    # --- every other flag: parses AND does not raise ----------------------
    from xssentinel.__main__ import build_parser
    ap = build_parser("scan")
    # Excluded with a reason; these are covered above or need an external
    # service that a placeholder cannot stand in for.
    excluded = {
        "--serve": "server mode, covered above",
        "--mcp": "stdio server, covered above",
        "--passive": "proxy server, covered above",
        "--self-test": "minutes-long suite, start checked above",
        "--ai-reset": "deletes operator state",
        "--ai-check": "LLM provider probe, measured above with a 120s leash",
        "--oob": "starts an OOB listener",
        "--oob-keep-listening": "starts an OOB listener",
        "--headless": "needs a real browser",
        "--wayback": "needs the Wayback Machine",
        "--gql": "needs a GraphQL endpoint",
        "--webhook": "would emit network traffic",
        "--verify-fix": "mode, covered above",
        "--diff": "mode, covered above",
        "--fuzz-body": "mode, covered above",
        "--sandbox": "mode, covered above",
        "--sandbox-response": "mode, covered above",
        "--sandbox-hosts": "mode, covered above",
        "--batch-stdin": "needs piped stdin, covered above",
        "--har": "input surface, covered above",
        "--openapi": "input surface, covered above",
        "--sitemap": "input surface, covered above",
        "--raw-request": "input surface, covered above",
        "--batch": "input surface, covered above",
        "--url": "the base target itself",
        "--config": "input contract, Phase 360 suite",
        "--save-config": "mode, covered above",
        "-h": "help", "--version": "version", "-V": "version",
        "--ver": "verbose alias",
    }

    def placeholder(action, ph):
        if action.nargs == 0:
            return []
        if action.choices:
            v = list(action.choices)[0]
        elif action.type is int:
            v = "1"
        elif action.type is float:
            v = "1"
        else:
            v = ph
        return [v, v] if action.nargs == 2 else [v, ] if action.nargs == "+" \
            else [v] * 2 if isinstance(action.nargs, int) else [v]

    flag_jobs = []
    for a in ap._actions:
        if not a.option_strings:
            continue
        flag = a.option_strings[0]
        if flag in excluded:
            continue
        # Independent placeholder AND output per flag: with 4 workers a
        # shared --checkpoint placeholder gets rewritten by one case while
        # --resume reads it in another.  That race produced a fake crash in
        # the first run; the harness must not manufacture product bugs.
        safe = "".join(c if c.isalnum() else "_" for c in flag)
        ph = fixture("ph_" + safe + ".txt", "1\n")
        if isinstance(a, (argparse._HelpAction, argparse._VersionAction,
                          argparse._StoreTrueAction,
                          argparse._StoreFalseAction)):
            vals = []
        else:
            vals = placeholder(a, ph)
        flag_jobs.append((flag, [flag, *vals],
                          os.path.join(TMP, "smoke_" + safe + ".json")))

    def smoke(job):
        flag, argv, out = job
        # Bound any LLM-backed path (--ai-report) so an offline host cannot
        # turn a flag smoke into a 30s timeout that says nothing about the
        # CLI's ability to reach the feature.
        r = run(["-u", target, "-o", out, "-f", "json", *COMMON,
                 "--ai-timeout", "2", *argv], timeout=30)
        return {"flag": flag, "argv": argv, **r}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        flags = list(ex.map(smoke, flag_jobs))

    srv.shutdown()
    srv.server_close()

    out = {
        "python": sys.version,
        "parser_actions": len([a for a in ap._actions if a.option_strings]),
        "surface": surface,
        "flag_smoke": flags,
        "excluded": excluded,
    }
    with open(os.path.join(ROOT, "dev", "_cli_surface_probe.json"), "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
    print("surface cases:", len(surface), "flags smoked:", len(flags),
          "excluded:", len(excluded))
    print("surface crashes:", [c["name"] for c in surface if c["crash"]])
    print("surface non-ok:", [(c["name"], c["rc"])
                              for c in surface if c["rc"] not in (0, None)])
    print("flag crashes:", [(c["flag"], c["err_head"][:100])
                            for c in flags if c["crash"]])
    print("flag TIMEOUTs:", [c["flag"] for c in flags
                             if c["rc"] == "TIMEOUT"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
