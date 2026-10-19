"""External-validity driver: one real application target -> one report.

Every other range in this repo is a fixture *we* wrote, so its ground truth
is self-referential.  OWASP Juice Shop is not: it is a real Angular SPA +
Express API + SQLite application whose upstream ``challenges.yml`` lists
which of its surfaces are XSS.  This driver points the product's own CLI at
that one target and scores what comes back.

The prior external run (dev/_JUCESHOP_EXTERNAL_VALIDITY.md) scanned the
single endpoint ``/rest/products/search?q=apple`` and got 0 findings.  That
attribution was correct -- and it was also not a test of the delivery goal,
because it never scanned the *application*.  This driver does.

Usage::

    python dev/juiceshop_external.py serve            # start/stop the app
    python dev/juiceshop_external.py status           # is the target answering
    python dev/juiceshop_external.py surfaces         # probe app surface facts
    python dev/juiceshop_external.py writes           # write surfaces: captcha,
        #   sanitizer, auth walls -- so a miss can be attributed to the target
    python dev/juiceshop_external.py scan [name,...]  # run the scan matrix

Results land in dev/_js_out/.  Nothing here loosens a judgement: the
driver only starts a target, invokes the product, and reads its report.

Environment note (measured 2026-10-19).  The scan subprocess inherits the
caller's proxy settings.  On a box where HTTP(S)_PROXY points at an
egress proxy, loopback asset fetches get corrupted: the first bundle
fetched fine (main.js, 1.21 MB), while polyfills.js and scripts.js came
back as 9608 bytes of index.html, and SPA route mining returned **zero**
routes.  The same command with NO_PROXY=127.0.0.1,localhost returned the
three real bundles and five hash routes.  Export NO_PROXY for local runs
before drawing any conclusion about the target.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
#: The repo's own copy of the target.  The 2026-10 workspace wipe left
#: data/ and logs/ in place but removed build/ and node_modules/, so a
#: missing build is an ENVIRONMENT fact, not a target fact: say so instead
#: of health-polling 90s and reporting "never became healthy".
BUNDLE = os.environ.get(
    "XS_JUICE_BUNDLE",
    os.path.join(HERE, "_juiceshop", "app", "juice-shop_20.2.0"))
OUT = os.path.join(HERE, "_js_out")
PORT = int(os.environ.get("XS_JUICE_PORT", "18900"))
BASE = f"http://127.0.0.1:{PORT}"

#: Node 22 portable install: the Juice Shop v20 bundle will not run on the
#: v16 that sits on PATH here.  See also dev/pin_repo.py for the sibling
#: "measure your toolchain before blaming the code" lesson.
NODE_CANDIDATES = [
    r"C:\NodeJS22\node-v22.20.0-win-x64\node.exe",
    "node",
]


def node_bin() -> str:
    for c in NODE_CANDIDATES:
        p = shutil.which(c) or c
        if os.path.exists(p):
            ver = subprocess.run([p, "--version"], capture_output=True,
                                 text=True, timeout=30).stdout.strip()
            major = "".join(ch for ch in ver if ch.isdigit())[:2]
            if ver and int(major or 0) >= 20:
                return p
    raise SystemExit(f"no Node >=20 found (tried {NODE_CANDIDATES})")


def healthy(timeout: float = 90.0) -> bool:
    url = f"{BASE}/rest/products/search?q=apple"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(1.0)
    return False


def serve(action: str = "start") -> int:
    """Start (or check) the target app; it is a real server, not a fixture."""
    if action == "status":
        print(f"healthy={healthy(timeout=3)} base={BASE}")
        return 0
    app_js = os.path.join(BUNDLE, "build", "app.js")
    if not os.path.exists(app_js):
        print(f"[!] no built target at {app_js}")
        print("    the 2026-10 workspace wipe removed build/ and node_modules/")
        print("    from the repo's copy; set XS_JUICE_BUNDLE to an intact")
        print("    20.2.0 tree (source checkout with build/ + node_modules/).")
        return 1
    exe = node_bin()
    os.makedirs(OUT, exist_ok=True)
    logf = open(os.path.join(OUT, "juiceshop.log"), "ab", buffering=0)
    env = dict(os.environ, PORT=str(PORT), NODE_ENV="production")
    proc = subprocess.Popen([exe, "build/app.js"], cwd=BUNDLE, env=env,
                            stdout=logf, stderr=subprocess.STDOUT,
                            creationflags=getattr(subprocess, "CREATE_NEW_GROUP", 0)
                            if os.name == "nt" else 0)
    print(f"[*] started node build/app.js pid={proc.pid} port={PORT}")
    if not healthy():
        print("[!] target never became healthy; see dev/_js_out/juiceshop.log")
        proc.terminate()
        return 1
    print(f"[+] target up: {BASE}")
    if action == "serve":
        try:
            while proc.poll() is None:
                time.sleep(5)
        except KeyboardInterrupt:
            proc.terminate()
    else:
        proc.terminate()
        print("[*] stopped after health check")
    return 0


def get(path: str, headers: dict | None = None):
    req = urllib.request.Request(BASE + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()[:4000].decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:4000].decode("utf-8", "replace")
    except Exception as e:
        return None, str(e)


def surfaces() -> int:
    """Facts about the target, measured rather than recalled.

    Each line answers "what does the app actually do to an attacker string
    here", which is what a scanner can be expected to see.  Without this a
    miss is unattributable: the scanner cannot find a sink the target does
    not have in the mode it was started in.
    """
    marker = "xssent_9f3a2b"
    probes = [
        ("/rest/products/search?q=" + marker, "product search API"),
        ("/redirect?to=<iframe src=\"javascript:alert(`xss`)\">",
         "reflected XSS challenge route"),
        ("/redirect?to=" + marker, "redirect error page w/ marker"),
        ("/#/search", "SPA shell (DOM XSS host, client-side)"),
        ("/api/Feedbacks", "feedback collection (list)"),
        ("/rest/reviews", "reviews (list)"),
    ]
    rows = []
    for path, why in probes:
        st, body = get(path)
        if st is None:
            # Same rule as probe_writes: an unmade request is UNKNOWN, not a
            # False.  Writing False here would say "the target does not
            # reflect" on the strength of a connection error.
            rows.append({"path": path, "why": why, "status": None,
                         "error": str(body)[:120], "reflects_marker": None,
                         "iframe_present": None, "body_head": ""})
            print(f"  [ERR] {path[:58]:58} {why} -- {str(body)[:60]}")
            continue
        rows.append({
            "path": path, "why": why, "status": st,
            "reflects_marker": marker in (body or ""),
            "iframe_present": "<iframe" in (body or ""),
            "body_head": (body or "")[:160].replace("\n", " "),
        })
    for r in rows:
        print(f"  [{r['status']}] reflects={r['reflects_marker']!s:5} "
              f"iframe={r['iframe_present']!s:5} {r['path'][:58]:58} {r['why']}")
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "surfaces.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    return 0


#: One row per way of pointing the product at this target.  The first is
#: the delivery goal itself: ONE command, ONE target, ONE report.
#: ``extra`` args are appended verbatim to every invocation.
COMMON = ["--progress", "none", "--log-level", "error"]
SCAN_MATRIX = {
    "oneshot": {
        "desc": "the delivery goal: just the target URL (crawl + browser)",
        "args": ["-u", BASE, "-c", "--crawl-depth", "2", "--headless"],
    },
    "discover": {
        "desc": "browser-rendered input discovery (SPA forms + same-origin APIs)",
        "args": ["-u", BASE, "-c", "--discover", "--headless"],
    },
    "api-surface": {
        "desc": "the REST surface the SPA itself calls, with a query param",
        "args": ["-u", BASE + "/rest/products/search?q=apple", "--headless"],
    },
    # Capability vs discoverability, separated on purpose: this row hands the
    # scanner the hash route the app's own bundle declares
    # (`router.navigate(['/search'],{queryParams:{q:e}})` -> the component
    # binds `[innerHTML]="searchValue"`).  If this confirms XSS while the
    # crawl-only rows do not, the gap is *discovering* SPA routes, not
    # detecting the sink.
    "dom-route": {
        "desc": "explicit Angular hash route whose param binds [innerHTML]",
        "args": ["-u", BASE + "/#/search?q=apple", "--headless"],
    },
    "dom-route-result": {
        "desc": "the search-result route (the page that renders searchValue)",
        "args": ["-u", BASE + "/#/search-result?q=apple", "--headless"],
    },
}


def run_scan(name: str) -> dict | None:
    spec = SCAN_MATRIX[name]
    json_out = os.path.join(OUT, f"findings_{name}.json")
    cmd = ([sys.executable, "-m", "xssentinel"] + list(spec["args"])
           + COMMON + ["-f", "json", "-o", json_out])
    print(f"\n=== {name}: {spec['desc']}")
    print("    " + " ".join(cmd[:8]) + " ...")
    t0 = time.time()
    p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=3600)
    dt = time.time() - t0
    print(f"    exit={p.returncode} {dt:.1f}s")
    tail = [ln for ln in (p.stdout or "").splitlines()
            if any(k in ln for k in ("Scan complete", "finding", "incomplete",
                                     "Completeness", "circuit"))][-6:]
    for ln in tail:
        print("    | " + ln.strip()[:150])
    if not os.path.exists(json_out):
        print("    [!] no json report written; stderr tail:")
        for line in (p.stderr or "").splitlines()[-6:]:
            print("      " + line[:160])
        return None
    with open(json_out, encoding="utf-8") as f:
        data = json.load(f)
    print(f"    findings={len(data.get('findings') or [])} "
          f"requests={data.get('requests')} "
          f"attempted={data.get('requests_attempted')} "
          f"failed={data.get('requests_failed')}")
    for fd in (data.get("findings") or [])[:20]:
        print(f"      - {str(fd.get('type')):22} {str(fd.get('severity')):8} "
              f"{str(fd.get('confidence')):8} "
              f"{str(fd.get('evidence_class')):18} "
              f"{str(fd.get('url'))[:70]}")
    return data


def scan(names: list[str]) -> int:
    os.makedirs(OUT, exist_ok=True)
    summary = {}
    for n in names or list(SCAN_MATRIX):
        d = run_scan(n)
        summary[n] = {"findings": len((d or {}).get("findings") or []),
                      "requests": (d or {}).get("requests")}
    print("\n=== SUMMARY")
    print(json.dumps(summary, indent=2))
    return 0


def probe_writes() -> int:
    """What the target actually does to an attacker string, per surface.

    These are the measurements that let a miss be *attributed* instead of
    counted as a scanner failure: a sink the application does not have (in
    the mode it was started in) cannot be found by anyone.
    """
    m = "xssent_9f3a2b"
    iframe = f'<iframe src="javascript:alert(`{m}`)">'
    rows = []

    def note(name, **kw):
        rows.append({"surface": name, **kw})
        print(f"  {name:34} {kw}")

    # Error-page reflection: reflects, but HTML-escapes the value.
    st, body = get("/redirect?to=" + quote(iframe))
    if st is None:
        note("reflected /redirect?to=", error=str(body)[:90])
    else:
        note("reflected /redirect?to=", status=st,
             raw_iframe_in_body="<iframe" in body,
             escaped_iframe="&lt;iframe" in body, marker=str(m in body))
    # Template probe: reflected verbatim; "49" appears only as a line number.
    st, body = get("/redirect?to=" + quote("{{7*7}}"))
    if st is None:
        # A failed probe must not be written as a string of False flags: that
        # reads exactly like "this target does not reflect", which is the
        # conclusion the row exists to test.
        note("ssti probe {{7*7}}", error=str(body)[:90])
    else:
        note("ssti probe {{7*7}}", status=st, rendered_49="49" in body,
             verbatim="{{7*7}}" in body,
             coincidence=":149:" in body or "route.js:149" in body)
    # Write surfaces need the app's own captcha (answer is returned in JSON).
    st, cap = get("/rest/captcha")
    try:
        c = json.loads(cap)
        answer = str(eval(c["captcha"]))
        req_headers = {"Content-Type": "application/json"}
        data = json.dumps({"comment": iframe, "rating": 5,
                           "captchaId": c["captchaId"], "captcha": answer}).encode()
        rq = urllib.request.Request(BASE + "/api/Feedbacks", data=data,
                                    method="POST", headers=req_headers)
        try:
            with urllib.request.urlopen(rq, timeout=20) as r:
                post_status, post_body = r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            post_status, post_body = e.code, e.read().decode("utf-8", "replace")
        stored_empty = '"comment":""' in post_body or '"comment": ""' in post_body
        note("stored feedback POST /api/Feedbacks", status=post_status,
             sanitizer_stripped=stored_empty, raw_iframe_stored="<iframe" in post_body)
    except Exception as e:
        note("stored feedback", error=type(e).__name__ + ": " + str(e)[:60])
    st, body = get("/api/Users")
    note("user list GET /api/Users", status=st, needs_auth=st == 401)
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "write_surfaces.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)
    return 0


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    if action == "serve":
        return serve("serve")
    if action == "start":
        return serve("start")
    if action == "status":
        return serve("status")
    if action == "surfaces":
        return surfaces()
    if action == "writes":
        return probe_writes()
    if action == "scan":
        return scan(sys.argv[2:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
