# -*- coding: utf-8 -*-
"""Mutation control for the Phase 360 CLI-surface fixes.

Unlike ``phase360_mutation_check.py`` this harness does NOT drive pytest:
the previous turn's 50-deletion/turn quota was consumed by pytest's
temporary-directory cleanup and aborted the control mid-way.  Each check
here runs the real CLI entry point (or reads the source for the one
source-level contract) and nothing deletes files.

Rule: assert the anchor exists, baseline green -> mutated RED -> restored
green.  A mutated pass that is green means the guard has no teeth.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = os.path.join(ROOT, "dev", "_cli_surface_tmp")
os.makedirs(TMP, exist_ok=True)
PY = sys.executable
ENV = {**os.environ, "NO_PROXY": "127.0.0.1,localhost",
       "no_proxy": "127.0.0.1,localhost", "PYTHONIOENCODING": "utf-8",
       "PYTHONPATH": ROOT}
COMMON = ["--max-payloads", "1", "--max-transforms", "1",
          "--dom-engine", "static", "--timeout", "2"]


class T(BaseHTTPRequestHandler):
    def do_GET(self):
        from urllib.parse import parse_qs, urlparse
        q = (parse_qs(urlparse(self.path).query).get("q") or [""])[-1]
        b = ("<html><body><div id=out>" + q +
             "</div></body></html>").encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


class Quiet(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass


def cli(args, timeout=60, env=None):
    e = {**ENV, **(env or {})}
    return subprocess.run([PY, "-m", "xssentinel", *args], cwd=TMP,
                          env=e, capture_output=True, timeout=timeout)


def check_raw():
    p = os.path.join(TMP, "mut_bad.raw")
    open(p, "wb").write(b"NOT A REQUEST\r\n\r\n")
    r = cli(["--raw-request", p])
    return r.returncode == 2 and b"Traceback" not in r.stderr


def check_resume():
    p = os.path.join(TMP, "mut_bad.ckpt.json")
    open(p, "w", encoding="utf-8").write("1")
    r = cli(["-u", "http://127.0.0.1:1/", "--resume", p, *COMMON])
    return (r.returncode == 2 and b"Traceback" not in r.stderr
            and b"not a valid XSSentinel checkpoint" in r.stderr)


def check_selftest():
    r = cli(["--self-test"], timeout=90,
            env={"XSSentinel_SELFTEST_TIMEOUT": "8"})
    return (b"Vuln server ready" in r.stdout
            and b"did not start" not in r.stderr)


def check_poc(target):
    blocker = os.path.join(TMP, "mut_not_a_dir.txt")
    open(blocker, "w", encoding="utf-8").write("x")
    out = os.path.join(TMP, "mut_out.json")
    r = cli(["-u", target, "-o", out, "-f", "json",
             "--poc-dir", blocker, *COMMON], timeout=90)
    return (r.returncode == 0 and b"artifacts skipped" in r.stderr
            and b"Report write failed" not in r.stderr)


def check_ai_timeout():
    src = open(os.path.join(ROOT, "xssentinel", "__main__.py"),
               encoding="utf-8").read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "_run_ai_check")
    return "ai_timeout" in ast.unparse(fn)


MUTATIONS = [
    ("raw-request: stop catching RawRequestError",
     "xssentinel/__main__.py",
     b"        except RawRequestError as e:\n"
     b'            print(f"[!] Invalid raw HTTP request',
     b"        except (OSError, KeyError) as e:  # MUTATED\n"
     b'            print(f"[!] Invalid raw HTTP request',
     "raw"),
    ("resume: stop distinguishing a corrupt file from a missing one",
     "xssentinel/__main__.py",
     b"        if os.path.isfile(args.resume):\n",
     b"        if False:  # MUTATED\n",
     "resume"),
    ("self-test: go back to the hard-coded occupied port",
     "xssentinel/cli_commands.py",
     b"        port = _selftest_port()\n",
     b"        port = 8899  # MUTATED\n",
     "selftest"),
    ("poc-dir: let an artifact write error escape again",
     "xssentinel/__main__.py",
     b"            except (OSError, ValueError, TypeError) as e:\n"
     b'                print(f"[!] --poc-dir artifacts skipped: {e}",',
     b"            except (OSError, ValueError, TypeError) as e:\n"
     b"                raise  # MUTATED\n"
     b'                print(f"[!] --poc-dir artifacts skipped: {e}",',
     "poc"),
    ("ai-timeout: stop forwarding the flag",
     "xssentinel/__main__.py",
     b"                      timeout=getattr(args, \"ai_timeout\", None))\n",
     b"                      timeout=None)  # MUTATED\n",
     "ai_timeout"),
]


def main():
    srv = Quiet(("127.0.0.1", 0), T)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/?q=probe" % srv.server_address[1]
    checks = {"raw": check_raw, "resume": check_resume,
              "selftest": check_selftest,
              "poc": lambda: check_poc(target),
              "ai_timeout": check_ai_timeout}
    passed = []
    try:
        for name, rel, old, mutated, key in MUTATIONS:
            path = os.path.join(ROOT, rel)
            with open(path, "rb") as f:
                original = f.read()
            nl = b"\r\n" if b"\r\n" in original else b"\n"

            def norm(x):
                return x.replace(b"\r\n", b"\n").replace(b"\n", nl)
            old, mutated = norm(old), norm(mutated)
            if original.count(old) != 1:
                print("ABORT: %s -> %d anchors" %
                      (name, original.count(old)))
                return 1
            try:
                if not checks[key]():
                    print("ABORT: %s baseline is not green" % name)
                    return 1
                with open(path, "wb") as f:
                    f.write(original.replace(old, mutated, 1))
                if checks[key]():
                    print("FAIL: %s mutated pass is GREEN (no teeth)" % name)
                    return 1
            finally:
                with open(path, "wb") as f:
                    f.write(original)
            if not checks[key]():
                print("FAIL: %s restored pass is not green" % name)
                return 1
            passed.append(name)
            print("OK  %-58s green -> red -> green" % name)
    finally:
        srv.shutdown()
        srv.server_close()
    print("\n%d surface mutation controls passed." % len(passed))
    return 0


if __name__ == "__main__":
    sys.exit(main())
