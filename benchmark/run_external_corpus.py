"""Phase 392: open-source external XSS corpora -> classifier fidelity vs real Chromium.

Why this exists
---------------
`portswigger_corpus_coverage.py` (2026-10-04) did a *string-level* comparison:
third-party corpus -> our corpus fingerprint coverage.  Its own docstring says
"覆盖 != 能检出".  This runner is the next step for the corpora the project has
never executed: the vectors were written by OTHER projects' authors (PortSwigger,
SecLists curators, PayloadsAllTheThings, OWASP cheat sheet, html5sec) and are
used here as-is, so the measurement says something about detection that a
self-designed 194-case matrix cannot.

Two measurements, one harness:

M1 (flagship) -- sandbox classifier fidelity on externally-authored vectors.
    For each sampled external vector x reflection context we build a page that
    carries the vector verbatim and nothing else, then:
      * oracle: real Chromium (Playwright) loads the page; "EXEC" iff any
        alert/confirm/prompt dialog fired on load (the same execution notion
        the project's browser arm uses);
      * subject: `xssentinel.core.sandbox.judge(page, token="", sink="parser")`
        -- the exact function the engine's verify gate calls
        (core/verifier.py:733), with token="" because external vectors carry
        their own dialog callee and our pages carry nothing else.
    Agreement directions that cost something:
      * over-statement: oracle inert but sandbox says live  (feeds FPs)
      * under-statement: oracle EXEC but sandbox says inert (feeds FNs)
    `unknown` is counted separately -- the sandbox may defer, never guessed.
    Escaped-twin pages (server escaped the reflection) are the FP control:
    oracle must be inert AND sandbox must not say live.

M2 -- end-to-end facts on a reflection harness whose context taxonomy comes
    from the external corpora: 8 vulnerable twins (param q reflected raw) +
    5 escaped safe twins.  XSSentinel CLI batch scan, then dalfox / nuclei
    against the SAME URLs.  Fact table only for third-party tools (Phase 380
    rule): no TP/FP/TN/FN and no rates for them, because neither tool was
    given an execution-level oracle and our budgets differ.

What this is NOT
----------------
* Not a recall/F1 benchmark: XSSMaze (official target + official scorer) is
  and stays the only F1 source (external_validity_20261108.md).
* Baked/attacked pages are NOT in the CLI scanner's detection surface by
  design (detection is reflection-driven; measured in the Phase 392 pilot:
  8 oracle-EXEC baked pages -> 0 findings, plain and --headless).
* The oracle only sees dialogs-on-load: vectors needing user interaction, and
  dialog-less executions (print(), silent fetch), land in `inert`.  That is a
  known limitation of the ground truth, not a scanner verdict.

Usage::

    python benchmark/run_external_corpus.py --tree <short-sha> --part all
    python benchmark/run_external_corpus.py --part m1 --limit 12   # smoke
Writes benchmark/results/phase392_external_corpus_20261114.{json,md}
"""
from __future__ import annotations

import argparse
import hashlib
import html as H
import json
import os
import re
import subprocess
import sys
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote as _urlquote
from urllib.parse import unquote as _urlunquote

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _ROOT)

from xssentinel.core.sandbox import judge  # noqa: E402
from benchmark.portswigger_corpus_coverage import extract_vectors  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_CORPUS_DIR = os.path.join(_ROOT, "dev", "_external_corpus")
RESULT_STEM = "phase392_external_corpus_20261114"
ORACLE_CONCURRENCY = 8
ORACLE_SETTLE_MS = 2500
ORACLE_NAV_TIMEOUT_MS = 4500
ENGINE_SCAN_TIMEOUT = 90
DALFOX_TIMEOUT_S = 45
NUCLEI_TIMEOUT_S = 120

# corpus_id, filename, kind, cap.  Selection is first-N in file order, except
# the PortSwigger sheet which is round-robin over its own context tags (its
# vectors carry third-party context metadata) and split by its interaction
# group.  h5sc/vectors.txt == SecLists XSS-Vectors-Mario.txt (measured, same
# bundle): only one copy is sampled and the duplicate is stated in the report.
FLAT, FENCES, MARIO, PS = "flat", "md_fences", "mario_bundle", "portsweigger_html"
CORPORA = [
    ("ps-sheet-2026", "pw_cheatsheet_20261114.html", PS, 65),
    ("seclists-jhaddix", "seclists_jhaddix.txt", FLAT, 20),
    ("seclists-brutelogic", "seclists_brutelogic.txt", FLAT, 15),
    ("seclists-brutelogic-bypass", "seclists_brutelogic_bypass.txt", FLAT, 5),
    ("seclists-rsnake", "seclists_rsnake.txt", FLAT, 15),
    ("seclists-somdev", "seclists_somdev.txt", FLAT, 5),
    ("seclists-mario", "seclists_mario.txt", MARIO, 20),
    ("pat-filter-bypass", "pat_filter_bypass.md", FENCES, 15),
    ("pat-polyglot", "pat_polyglot.md", FENCES, 8),
    ("pat-waf-bypass", "pat_waf_bypass.md", FENCES, 8),
    ("pat-readme", "pat_readme.md", FENCES, 14),
    ("owasp-evasion", "owasp_evasion.md", FENCES, 25),
]
PS_NO_INTERACTION_CAP = 45
PS_REQUIRES_INTERACTION_CAP = 20

MAX_VECTOR_CHARS = 1000
MIN_VECTOR_CHARS = 4

# Reflection contexts.  Names mirror sandbox.HOSTS so the host table stays one
# vocabulary; templates here wrap into a full served document for the oracle.
RAW_HOSTS = [
    ("text", '<div id="c">__P__</div>'),
    ("attr_dq", '<div data-x="__P__">t</div>'),
    ("attr_unq", "<div data-x=__P__>t</div>"),
    ("script_dq", '<script>var a = "__P__";</script>'),
    ("script_block", "<script>__P__</script>"),
    ("comment", "<!--__P__-->"),
    ("href_dq", '<a href="__P__">t</a>'),
    ("iframe_srcdoc", '<iframe srcdoc="__P__"></iframe>'),
]
# Escaped twins = "the server HTML-escaped the reflection".  FP control:
# neither oracle nor sandbox may claim execution.  script_dq is NOT here: its
# twin is JS-STRING escaping, which does not neutralise a `</script>` breakout
# -- first round measured oracle-EXEC on those twins (true positives of the
# page, not an oracle failure), so the HTML-escape premise only holds for the
# four contexts below.
ESCAPED_CONTEXTS = ("text", "attr_dq", "comment", "href_dq")

PAGE_SHELL = ("<!doctype html><html><head><meta charset=\"utf-8\">"
              "<title>p392</title></head><body><h1>p392</h1>%s</body></html>")

# Controls: if the oracle cannot see these fire, the oracle is broken and the
# run must ABORT, not publish (mutation-control rule: assert the baseline
# before trusting the measurement).  Calm numbers so they cannot collide with
# sampled vectors.
KNOWN_EXEC_CONTROLS = [
    ("ctl-svg-onload", "<svg onload=alert(911)>", "text"),
    ("ctl-img-onerror", "<img src=x onerror=alert(912)>", "text"),
    ("ctl-script-plain", "<script>alert(913)</script>", "text"),
    ("ctl-autofocus", "<input autofocus onfocus=alert(914)>", "text"),
    ("ctl-srcdoc", '<iframe srcdoc="&lt;svg onload=alert(915)&gt;"></iframe>',
     "text"),
    ("ctl-attr-breakout", '"><img src=x onerror=alert(916)>', "attr_dq"),
]
BENIGN_CONTROLS = [
    ("ctl-benign-text", "<p>hello world</p>", "text"),
    ("ctl-benign-attr", "plain text value", "attr_dq"),
    ("ctl-benign-script", "just some words", "script_dq"),
]
# Expected sandbox verdicts per control, pinned so the semantics cannot drift
# silently.  The script controls are UNKNOWN by construction since Phase 393:
# judge without a token cannot attribute a script body's code-vs-data
# position (the sandbox defers instead of over-claiming), so
# ctl-script-plain is oracle-exec + sandbox-unknown and ctl-benign-script is
# oracle-inert + sandbox-unknown.
CONTROLS_EXPECTED_SANDBOX = {
    "ctl-svg-onload": "live",
    "ctl-img-onerror": "live",
    "ctl-script-plain": "unknown",
    "ctl-autofocus": "live",
    "ctl-srcdoc": "live",
    "ctl-attr-breakout": "live",
}
BENIGN_EXPECTED_SANDBOX = {
    "ctl-benign-text": "inert",
    "ctl-benign-attr": "inert",
    "ctl-benign-script": "unknown",
}

# ---------------------------------------------------------------------------
# corpus extraction (pure functions of the file contents)
# ---------------------------------------------------------------------------

PAYLOADISH = re.compile(
    r"<|javascript:|\bon[a-z]{3,20}\s*=|\balert\s*\(|\bconfirm\s*\("
    r"|\bprompt\s*\(|\beval\s*\(")
MARIO_DIV = re.compile(r'<div id="\d+">(.*?)</div>', re.S)
MARIO_TAIL = "//[\"'`-->]]>]"
FENCE = re.compile(r"```[a-zA-Z0-9]*\n(.*?)```", re.S)


def keep_vector(s: str) -> bool:
    s = s.strip()
    if not (MIN_VECTOR_CHARS <= len(s) <= MAX_VECTOR_CHARS):
        return False
    if s.startswith(("#", ">>>", "credit", "see:", "source:")):
        return False
    return bool(PAYLOADISH.search(s))


def extract_flat(text: str) -> list[str]:
    return [ln.strip() for ln in text.splitlines() if keep_vector(ln)]


def extract_mario(text: str) -> list[str]:
    out = []
    for m in MARIO_DIV.finditer(text):
        vec = m.group(1).strip()
        if vec.endswith(MARIO_TAIL):
            vec = vec[: -len(MARIO_TAIL)]
        if keep_vector(vec):
            out.append(vec)
    return out


def extract_fences(text: str) -> list[str]:
    out = []
    for m in FENCE.finditer(text):
        block = m.group(1).strip()
        if not block or block.count("\n") > 4:
            continue
        if keep_vector(block):
            out.append(block)
    return out


def extract_ps(text: str) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for entry in extract_vectors(text):
        if entry["group"] in ("no_interaction", "requires_interaction"):
            groups.setdefault(entry["group"], []).append(entry)
    return groups


def load_corpus(corpus_dir: str) -> tuple[dict, list[dict]]:
    """Return (stats, selection).  Selection is deterministic: file order,
    first-wins dedup on the exact vector string, caps per corpus."""
    stats: list[dict] = []
    selection: list[dict] = []
    seen: set[str] = set()
    for corpus_id, filename, kind, cap in CORPORA:
        path = os.path.join(corpus_dir, filename)
        if not os.path.exists(path):
            print(f"[abort] 语料缺失: {path}\n"
                  "抓取方式见 benchmark/run_external_corpus.py 模块注释",
                  file=sys.stderr)
            raise SystemExit(2)
        raw = open(path, encoding="utf-8", errors="ignore").read()
        digest = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()
        if kind == PS:
            groups = extract_ps(raw)
            noint = groups.get("no_interaction", [])
            reqint = groups.get("requires_interaction", [])
            by_ctx: "OrderedDict[str, list[str]]" = OrderedDict()
            for e in noint:
                by_ctx.setdefault(e["context"] or "unknown", []).append(
                    e["vector"])
            picked: list[str] = []
            depth = 0
            while len(picked) < PS_NO_INTERACTION_CAP:
                added = False
                for ctx in by_ctx:
                    if depth < len(by_ctx[ctx]):
                        picked.append(by_ctx[ctx][depth])
                        added = True
                        if len(picked) >= PS_NO_INTERACTION_CAP:
                            break
                if not added:
                    break
                depth += 1
            picked += [e["vector"] for e in reqint[:PS_REQUIRES_INTERACTION_CAP]]
            candidates = len(noint) + len(reqint)
            ctx_of = {e["vector"]: e["context"] for e in noint + reqint}
            grp_of = {e["vector"]: e["group"] for e in noint + reqint}
        elif kind == FLAT:
            picked = extract_flat(raw)[:cap]
            candidates = len(extract_flat(raw))
            ctx_of, grp_of = {}, {}
        elif kind == MARIO:
            allv = extract_mario(raw)
            picked = allv[:cap]
            candidates = len(allv)
            ctx_of, grp_of = {}, {}
        else:
            allv = extract_fences(raw)
            picked = allv[:cap]
            candidates = len(allv)
            ctx_of, grp_of = {}, {}

        used = 0
        for vec in picked:
            if vec in seen:
                continue
            seen.add(vec)
            selection.append({
                "id": f"{corpus_id}-{used + 1:03d}",
                "corpus": corpus_id,
                "vector": vec,
                "ps_group": grp_of.get(vec, ""),
                "ps_context": ctx_of.get(vec, ""),
            })
            used += 1
        stats.append({"corpus": corpus_id, "file": filename, "kind": kind,
                      "sha256_12": digest[:12], "candidates": candidates,
                      "selected": used, "cap": cap})
    return {"corpora": stats, "unique_vectors": len(selection)}, selection


# ---------------------------------------------------------------------------
# page building
# ---------------------------------------------------------------------------

def js_string_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def escape_for(s: str, ctx: str) -> str:
    if ctx == "script_dq":
        return js_string_escape(s)
    return H.escape(s, quote=True)


def build_page(vector: str, ctx: str, escaped: bool) -> str:
    host = dict(RAW_HOSTS)[ctx]
    payload = escape_for(vector, ctx) if escaped else vector
    return PAGE_SHELL % (host.replace("__P__", payload))


def context_plan() -> list[tuple[str, bool]]:
    plan = [(ctx, False) for ctx, _ in RAW_HOSTS]
    plan += [(ctx, True) for ctx in ESCAPED_CONTEXTS]
    return plan


# ---------------------------------------------------------------------------
# oracle
# ---------------------------------------------------------------------------

def run_oracle(pages: dict[str, str], base_url: str) -> dict[str, dict]:
    """pages: id -> html.  Returns id -> {oracle, dialogs, note}.

    Hardened after the first round (Phase 393): one fresh CONTEXT per page
    (a shared context let some verdicts not reproduce under an adjudication
    probe), dialog capture at CONTEXT level (also covers srcdoc frames), and
    `about:` URLs allowed so srcdoc documents are not aborted by the network
    policy.  The first round's oracle data is kept on disk as the `_r1`
    backup; r1-vs-r2 deltas are oracle-attributed, r2-vs-r3 deltas are
    sandbox-attributed.
    """
    from playwright.sync_api import sync_playwright

    ids = list(pages)
    results: dict[str, dict] = {}
    t0 = time.time()

    def _route(route):
        url = route.request.url
        if "://127.0.0.1" in url or "://localhost" in url \
                or url.startswith("about:"):
            route.continue_()
        else:
            route.abort()

    def _dismiss(dialog):
        try:
            dialog.dismiss()
        except Exception:  # noqa: BLE001
            pass

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        for i in range(0, len(ids), ORACLE_CONCURRENCY):
            chunk = ids[i:i + ORACLE_CONCURRENCY]
            holders = []
            for cid in chunk:
                ctx = browser.new_context()
                ctx.route("**/*", _route)
                seen: list[str] = []
                ctx.on("dialog",
                       lambda d, _s=seen: (_s.append(str(d.message)[:80]),
                                           _dismiss(d)))
                page = ctx.new_page()
                holders.append((cid, ctx, page, seen))
            for _cid, _ctx, page, _seen in holders:
                try:
                    page.goto(f"{base_url}/{_cid}",
                              timeout=ORACLE_NAV_TIMEOUT_MS,
                              wait_until="domcontentloaded")
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(ORACLE_SETTLE_MS / 1000.0)
            for cid, ctx, page, seen in holders:
                results[cid] = {
                    "oracle": "exec" if seen else "inert",
                    "dialogs": seen[:3],
                }
                try:
                    page.close()
                    ctx.close()
                except Exception:  # noqa: BLE001
                    pass
        browser.close()
    print(f"oracle: {len(ids)} pages in {time.time() - t0:.0f}s")
    return results


# ---------------------------------------------------------------------------
# sandbox subject
# ---------------------------------------------------------------------------

def run_sandbox(pages: dict[str, str]) -> dict[str, dict]:
    out = {}
    for cid, page_html in pages.items():
        try:
            v = judge(page_html, "", sink="parser")
            out[cid] = {
                "sandbox": v.state,
                "activation": bool(v.activation),
                "reason": (v.reason or "")[:220],
            }
        except Exception as e:  # noqa: BLE001
            out[cid] = {"sandbox": "error", "activation": False,
                        "reason": f"{type(e).__name__}: {e}"[:220]}
    return out


# ---------------------------------------------------------------------------
# agreement
# ---------------------------------------------------------------------------

DIRECTIONS = ("agree_live", "missed", "overstated", "activation_inert",
              "agree_inert", "unknown_on_exec", "unknown_on_inert",
              "oracle_error", "sandbox_error")


def classify(row: dict) -> str:
    o, s = row["oracle"], row["sandbox"]
    if s == "error":
        return "sandbox_error"
    if o == "exec":
        if s == "live":
            return "agree_live"
        if s == "inert":
            return "missed"
        if s == "unknown":
            return "unknown_on_exec"
        return "oracle_error"
    if o == "inert":
        if s == "live":
            # First-round lesson: a live verdict with activation=True is the
            # sandbox honestly saying "needs a click" -- an href-javascript:
            # vector can NEVER fire a load-time dialog, so counting it as
            # over-statement would blame the classifier for correct
            # semantics.  Only activation-free live verdicts over-state.
            if row.get("activation"):
                return "activation_inert"
            return "overstated"
        if s == "inert":
            return "agree_inert"
        if s == "unknown":
            return "unknown_on_inert"
    return "oracle_error"


def aggregate(rows: list[dict]) -> dict:
    def bucket(rows_subset: list[dict]) -> dict:
        counts = {d: 0 for d in DIRECTIONS}
        for r in rows_subset:
            counts[r["direction"]] += 1
        exec_pop = counts["agree_live"] + counts["missed"] \
            + counts["unknown_on_exec"]
        # activation_inert is expected-inert-on-load, NOT part of the
        # over-statement denominator.
        inert_pop = counts["agree_inert"] + counts["overstated"] \
            + counts["unknown_on_inert"]
        return {
            "counts": counts,
            "population": len(rows_subset),
            "oracle_exec_population": exec_pop,
            "oracle_inert_population": inert_pop,
            "activation_population": counts["activation_inert"],
            "understatement_rate":
                round(counts["missed"] / exec_pop, 4) if exec_pop else None,
            "overstatement_rate":
                round(counts["overstated"] / inert_pop, 4) if inert_pop else None,
        }

    out = {"overall": bucket(rows)}
    for key in ("corpus", "context", "escaped"):
        by: dict[str, list[dict]] = {}
        for r in rows:
            by.setdefault(str(r[key]), []).append(r)
        out[f"by_{key}"] = {k: bucket(v) for k, v in sorted(by.items())}
    return out


# ---------------------------------------------------------------------------
# M2: reflection twins + cross-tool fact table
# ---------------------------------------------------------------------------

class TwinHandler(BaseHTTPRequestHandler):
    served: dict[str, str] = {}

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in self.served:
            body = self.served[path].encode("utf-8")
            ctype = "text/html; charset=utf-8"
        else:
            body = b"not found"
            ctype = "text/plain"
        self.send_response(200 if path in self.served else 404)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def twin_url(base: str, kind: str, ctx: str, qvalue: str = "marker") -> str:
    return f"{base}/t/{kind}/{ctx}?q={_urlquote(qvalue)}"


def safe_reflect(q: str, ctx: str) -> str:
    """M2 safe twin: the CONTEXTUALLY CORRECT defence, not the naive one.

    html.escape neutralises markup (text/comment/attr breakout) but does NOT
    neutralise a javascript: URI in href -- attribute entities decode before
    URL parsing, which is exactly what the engine's high verdict on the first
    safe-href twin measured.  A URL-context defence validates the scheme.
    """
    if ctx == "href_dq":
        if re.match(r"\s*(javascript|data|vbscript)\s*:", q, re.I):
            return "#blocked"
        return H.escape(q, quote=True)
    return escape_for(q, ctx)


def serve_twin(request_path: str, query: str) -> str:
    """Resolve one /t/{kind}/{ctx}?q=... request into page HTML.

    Malformed context paths (the engine's path-segment probes append payloads
    to the path) answer as an empty 404-shaped page instead of raising: the
    first M2 run crashed the serving thread on every such probe.
    """
    path = request_path.split("?")[0]
    parts = path.split("/")
    if len(parts) != 4 or parts[2] not in ("vuln", "safe") \
            or parts[3] not in dict(RAW_HOSTS):
        return PAGE_SHELL % "<p>not found</p>"
    kind, ctx = parts[2], parts[3]
    host = dict(RAW_HOSTS)[ctx]
    q = ""
    marker = "q="
    if marker in query:
        q = query.split(marker, 1)[1].split("&")[0]
        q = _urlunquote(q)
    payload = q if kind == "vuln" else safe_reflect(q, ctx)
    return PAGE_SHELL % (host.replace("__P__", payload))


def run_m2(base_url: str, tree: str) -> dict:
    """Engine batch scan on the twins + third-party fact rows."""
    urls = []
    for kind in ("vuln", "safe"):
        for ctx, _host in RAW_HOSTS:
            if kind == "safe" and ctx not in ESCAPED_CONTEXTS:
                continue
            urls.append(twin_url(base_url, kind, ctx))
    batch_path = os.path.join(_ROOT, "dev", "_p392_twins_urls.txt")
    with open(batch_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + "\n")
    engine_cmd = [
        sys.executable, "-m", "xssentinel",
        "--batch", batch_path,
        "-f", "json", "-o", "-",
        "--progress", "none", "--log-level", "error",
        "--timeout", "10",
    ]
    try:
        t0 = time.time()
        proc = subprocess.run(engine_cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=ENGINE_SCAN_TIMEOUT * 3, cwd=_ROOT)
        engine_elapsed = time.time() - t0
    finally:
        try:
            os.unlink(batch_path)
        except OSError:
            pass
    rows = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    engine_rows = []
    for r in rows:
        findings = []
        for f in r.get("findings") or []:
            findings.append({
                "layer": f.get("layer") or f.get("type", ""),
                "severity": f.get("severity", ""),
            })
        engine_rows.append({
            "url": r.get("target", ""),
            "findings": findings,
        })
    vuln_hit = sum(1 for r in engine_rows
                   if "/t/vuln/" in r["url"] and r["findings"])
    safe_hit = sum(1 for r in engine_rows
                   if "/t/safe/" in r["url"] and r["findings"])

    tools = {}
    for tool, cmd_fn, ceiling in (
        ("dalfox", _dalfox_cmd, DALFOX_TIMEOUT_S),
        ("nuclei", _nuclei_cmd, NUCLEI_TIMEOUT_S),
    ):
        tool_rows = []
        for kind in ("vuln", "safe"):
            for ctx, _host in RAW_HOSTS:
                if kind == "safe" and ctx not in ESCAPED_CONTEXTS:
                    continue
                url = twin_url(base_url, kind, ctx)
                t1 = time.time()
                try:
                    p = subprocess.run(cmd_fn(url), capture_output=True,
                                       text=True, encoding="utf-8",
                                       errors="replace", timeout=ceiling,
                                       cwd=_ROOT)
                    hits = _tool_hits(tool, p.stdout or "")
                    tool_rows.append({"kind": kind, "context": ctx,
                                      "url": url, "detected": bool(hits),
                                      "hits": len(hits),
                                      "seconds": round(time.time() - t1, 1),
                                      "rc": p.returncode, "error": ""})
                except subprocess.TimeoutExpired:
                    tool_rows.append({"kind": kind, "context": ctx,
                                      "url": url, "detected": False,
                                      "hits": 0,
                                      "seconds": ceiling, "rc": None,
                                      "error": "timeout"})
                except Exception as e:  # noqa: BLE001
                    tool_rows.append({"kind": kind, "context": ctx,
                                      "url": url, "detected": False,
                                      "hits": 0,
                                      "seconds": round(time.time() - t1, 1),
                                      "rc": -1,
                                      "error": f"{type(e).__name__}"})
        tools[tool] = {"rows": tool_rows,
                       "note": "FACT TABLE ONLY. No TP/FP/TN/FN or rates "
                               "(Phase 380 rule): neither tool was given an "
                               "execution-level oracle and budgets differ."}
    return {
        "base_url": base_url,
        "engine": {
            "rc": proc.returncode,
            "seconds": round(engine_elapsed, 1),
            "rows": engine_rows,
            "vuln_twins_with_findings": vuln_hit,
            "safe_twins_with_findings": safe_hit,
            "vuln_twins_total": sum(1 for r in engine_rows
                                    if "/t/vuln/" in r["url"]),
            "safe_twins_total": sum(1 for r in engine_rows
                                    if "/t/safe/" in r["url"]),
        },
        "tools": tools,
        "tree": tree,
    }


def _dalfox_cmd(url: str) -> list[str]:
    return ["dalfox", "url", url, "--format", "json", "--silence",
            "--timeout", "30", "--worker", "1"]


def _nuclei_cmd(url: str) -> list[str]:
    templates = os.path.join(os.path.expanduser("~"), "nuclei-templates",
                             "dast", "vulnerabilities", "xss")
    return ["nuclei", "-u", url, "-dast", "-t", templates, "-jsonl",
            "-silent", "-no-color", "-timeout", "10", "-retries", "1",
            "-duc", "-nc"]


def _tool_hits(tool: str, stdout: str) -> list[dict]:
    hits = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        if tool == "dalfox" and str(j.get("type", "")).lower() != "vulnerability":
            # dalfox jsonl: only Vulnerability lines are confirmed findings
            if "data" in j or "vulnerabilities" in j:
                hits.append(j)
            continue
        if tool == "nuclei":
            sev = str((j.get("info") or {}).get("severity", "")).lower()
            if sev in ("medium", "high", "critical"):
                hits.append(j)
    return hits


# ---------------------------------------------------------------------------
# markdown rendering (same dict as the JSON -> 同源)
# ---------------------------------------------------------------------------

def to_markdown(data: dict) -> str:
    L: list[str] = []
    L.append("# Phase 392:外部开源 XSS 语料 -> 分类器保真度 vs Chromium oracle")
    L.append("")
    L.append(data["honesty_header"])
    L.append("")
    L.append("## 语料来源(全部第三方撰写,原样使用)")
    L.append("")
    L.append("| corpus | file | sha256_12 | kind | candidates | selected (cap) |")
    L.append("|---|---|---|---|---|---|")
    for c in data["selection"]["corpora"]:
        L.append(f"| {c['corpus']} | {c['file']} | {c['sha256_12']} | "
                 f"{c['kind']} | {c['candidates']} | {c['selected']} ({c['cap']}) |")
    L.append("")
    L.append(f"去重后唯一向量:**{data['selection']['unique_vectors']}**;"
             "h5sc/vectors.txt 与 SecLists XSS-Vectors-Mario.txt 是同一捆绑"
             "(只采一份,不重复计数)。")
    L.append("")
    agg = data["m1"]["agreement"]
    L.append("## M1:sandbox 分类器保真度(引擎真实调用 "
             "`judge(page, token=\"\", sink=\"parser\")`)")
    L.append("")
    L.append("| 组 | population | oracle EXEC | oracle inert | agree_live | "
             "missed | overstated | agree_inert | unknown(exec/inert) | "
             "understatement_rate | overstatement_rate |")
    L.append("|---|---|---|---|---|---|---|---|---|---|---|")

    def fmt(b):
        c = b["counts"]
        return (f"{b['population']} | {b['oracle_exec_population']} | "
                f"{b['oracle_inert_population']} | {c['agree_live']} | "
                f"{c['missed']} | {c['overstated']} | {c['agree_inert']} | "
                f"{c['unknown_on_exec']}/{c['unknown_on_inert']} | "
                f"{b['understatement_rate']} | {b['overstatement_rate']}")

    L.append(f"| **overall** | {fmt(agg['overall'])} |")
    for k, v in agg["by_escaped"].items():
        L.append(f"| escaped={k} | {fmt(v)} |")
    for k, v in agg["by_corpus"].items():
        L.append(f"| corpus={k} | {fmt(v)} |")
    L.append("")
    L.append("## M1 控制页(oracle/分类器健全性断言)")
    L.append("")
    L.append("| control | oracle | sandbox |")
    L.append("|---|---|---|")
    for row in data["m1"]["control_rows"]:
        L.append(f"| {row['id']} | {row['oracle']} | {row['sandbox']} |")
    L.append("")
    L.append("## M1 方向明细(每组前若干条)")
    L.append("")
    interesting = [r for r in data["m1"]["rows"]
                   if r["direction"] in ("overstated", "missed")]
    for r in interesting[:40]:
        L.append(f"- **{r['direction']}** `{r['id']}` ctx={r['context']} "
                 f"escaped={r['escaped']} vector=`{r['vector'][:90]}` "
                 f"oracle={r['oracle']} sandbox={r['sandbox']} "
                 f"why={r['reason'][:120]}")
    L.append("")
    m2 = data.get("m2")
    if m2:
        L.append("## M2:反射孪生页端到端(上下文分类来自外部语料)")
        L.append("")
        e = m2["engine"]
        L.append(f"引擎批量扫描 rc={e['rc']},{e['seconds']}s;"
                 f"vuln 孪生 {e['vuln_twins_with_findings']}/{e['vuln_twins_total']} "
                 f"有 findings,safe 孪生 {e['safe_twins_with_findings']}/"
                 f"{e['safe_twins_total']} 有 findings。")
        L.append("")
        L.append("| url | findings(layers/severity) |")
        L.append("|---|---|")
        for r in e["rows"]:
            ftxt = "; ".join(f"{f['layer']}/{f['severity']}"
                             for f in r["findings"]) or "-"
            L.append(f"| {r['url'].replace(data['m2']['base_url'], '')} | {ftxt} |")
        L.append("")
        for tool, blob in m2["tools"].items():
            L.append(f"### 第三方工具事实表:{tool}(只记事实,不算分)")
            L.append("")
            L.append("| kind | context | detected | hits | seconds | error |")
            L.append("|---|---|---|---|---|---|")
            for r in blob["rows"]:
                L.append(f"| {r['kind']} | {r['context']} | {r['detected']} | "
                         f"{r['hits']} | {r['seconds']} | {r['error']} |")
            L.append("")
            L.append(f"边界:{blob['note']}")
            L.append("")
    L.append("## 不可比项")
    L.append("")
    for line in data["not_comparable"]:
        L.append(f"- {line}")
    L.append("")
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tree", required=True,
                    help="short git sha this run belongs to (Phase 381 rule: "
                         "归属拿不到就别写 unknown)")
    ap.add_argument("--corpus-dir", default=DEFAULT_CORPUS_DIR)
    ap.add_argument("--part", choices=("m1", "m2", "all"), default="all")
    ap.add_argument("--limit", type=int, default=0,
                    help="smoke: 只取前 N 个向量")
    ap.add_argument("--skip-oracle", action="store_true",
                    help="M1 只跑 sandbox(冒烟/单测用),oracle 记为 skipped")
    ap.add_argument("--recompute", action="store_true",
                    help="不重跑 oracle:从已落盘证据的原始测量行"
                         "(oracle/sandbox/activation)重算方向与聚合;"
                         "测量代码改了、原始测量没变时用")
    ap.add_argument("--resandbox", action="store_true",
                    help="不重跑 oracle:oracle 列保持已落盘值,只重跑 "
                         "sandbox 判定(Phase 393:量化判定修复的前后差)"
                         ";控制页同样只重跑 sandbox")
    ap.add_argument("--port", type=int, default=0,
                    help="pages harness port; 0 = OS-assigned (Windows "
                         "excludes unpredictable port ranges, so fixed ports "
                         "abort at bind time -- measured on 18952/18955/18960)")
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    if args.part == "m2":
        # M2-only: keep the already-measured M1 rows on disk untouched and
        # re-run just the twin/cross-tool leg (the twin server had a crash
        # bug on its first run -- every request 500'd, which reads as
        # "engine found nothing" unless the harness itself is verified).
        src = args.out or os.path.join(_HERE, "results",
                                       RESULT_STEM + ".json")
        with open(src, encoding="utf-8") as fh:
            data = json.load(fh)
        srv = _serve_twin(args.port + 1)
        try:
            data["m2"] = run_m2(f"http://127.0.0.1:{args.port + 1}",
                                args.tree)
        finally:
            srv.shutdown()
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        with open(os.path.splitext(src)[0] + ".md", "w",
                  encoding="utf-8") as fh:
            fh.write(to_markdown(data))
        e = data["m2"]["engine"]
        print(f"M2 engine rc={e['rc']} secs={e['seconds']} "
              f"vuln_hit={e['vuln_twins_with_findings']}/"
              f"{e['vuln_twins_total']} "
              f"safe_hit={e['safe_twins_with_findings']}/"
              f"{e['safe_twins_total']}")
        return 0

    sel_stats, vectors = load_corpus(args.corpus_dir)
    if args.limit:
        vectors = vectors[:args.limit]
    plan = context_plan()

    if args.resandbox:
        src = args.out or os.path.join(_HERE, "results",
                                       RESULT_STEM + ".json")
        with open(src, encoding="utf-8") as fh:
            prior = json.load(fh)
        rows = prior["m1"]["rows"]
        pages = {r["id"]: build_page(r["vector"], r["context"], r["escaped"])
                 for r in rows}
        sandbox_out = run_sandbox(pages)
        new_rows = []
        for r in rows:
            s = sandbox_out[r["id"]]
            row = {**r, "sandbox": s["sandbox"],
                   "activation": s["activation"], "reason": s["reason"]}
            row["direction"] = classify(row)
            new_rows.append(row)
        ctl_pages = {cid: build_page(vec, ctx, False)
                     for cid, vec, ctx in KNOWN_EXEC_CONTROLS + BENIGN_CONTROLS}
        ctl_sandbox = run_sandbox(ctl_pages)
        ctl_rows = [{"id": r["id"], "oracle": r["oracle"],
                     "sandbox": ctl_sandbox[r["id"]]["sandbox"]}
                    for r in prior["m1"]["control_rows"]]
        m1 = {
            "selected_vectors": prior["m1"]["selected_vectors"],
            "contexts": prior["m1"]["contexts"],
            "pages": len(new_rows),
            "agreement": aggregate(new_rows),
            "rows": new_rows,
            "control_rows": ctl_rows,
            "resandbox_note": (
                "Phase 393:oracle 列保持上一轮(--part 全量重跑,升级后 "
                "oracle)的原始测量值,sandbox 列用修复后的 judge 重算;"
                "r2-vs-r3 差 = sandbox 修复的效果,oracle 参与不变。"),
        }
        data = {
            "phase": "392",
            "tree": args.tree,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "honesty_header": prior["honesty_header"],
            "selection": prior["selection"],
            "m1": m1,
            "not_comparable": prior["not_comparable"],
        }
        if "m2" in prior:
            data["m2"] = prior["m2"]
        with open(src, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        with open(os.path.splitext(src)[0] + ".md", "w",
                  encoding="utf-8") as fh:
            fh.write(to_markdown(data))
        ov = m1["agreement"]["overall"]
        print("\n== M1 resandboxed ==")
        for d in DIRECTIONS:
            print(f"  {d:<16} {ov['counts'][d]}")
        print(f"understatement_rate={ov['understatement_rate']} "
              f"overstatement_rate={ov['overstatement_rate']}")
        print(f"json -> {src}")
        return 0

    if args.recompute:
        src = args.out or os.path.join(_HERE, "results",
                                       RESULT_STEM + ".json")
        with open(src, encoding="utf-8") as fh:
            prior = json.load(fh)
        kept, discarded = [], []
        for r in prior["m1"]["rows"]:
            if r["context"] == "script_dq" and r["escaped"]:
                discarded.append({**r,
                                  "discard_reason": "script_dq escaped twin "
                                                    "is JS-string escaping, "
                                                    "not HTML-escaping; its "
                                                    "oracle-EXEC rows are "
                                                    "true positives of the "
                                                    "page"})
                continue
            r["direction"] = classify(r)
            kept.append(r)
        m1 = {
            "selected_vectors": prior["m1"]["selected_vectors"],
            "contexts": len(plan),
            "pages": len(kept),
            "agreement": aggregate(kept),
            "rows": kept,
            "control_rows": prior["m1"]["control_rows"],
            "recompute_note": (
                "2026-11-14 首轮跑完后自我纠正两处测量口径:① classify 拆出 "
                "activation_inert(oracle load 态 inert + sandbox live-with-"
                "activation 是诚实语义,不算 over-statement);② script_dq 从 "
                "escaped 孪生移除(JS 字符串转义不中和 </script> breakout,"
                "首轮该孪生里有 oracle-EXEC 的真漏洞页)。原始测量行"
                "(oracle/sandbox/activation)未变,方向是它们的纯函数;"
                f"丢弃 {len(discarded)} 行 script_dq 孪生,原文存 "
                "recompute_discarded。"),
            "recompute_discarded": discarded,
        }
        data = {
            "phase": "392",
            "tree": args.tree,
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "honesty_header": prior["honesty_header"],
            "selection": prior["selection"],
            "m1": m1,
            "not_comparable": prior["not_comparable"],
        }
        if "m2" in prior:
            data["m2"] = prior["m2"]
        out_json = args.out or os.path.join(_HERE, "results",
                                            RESULT_STEM + ".json")
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        with open(os.path.splitext(out_json)[0] + ".md", "w",
                  encoding="utf-8") as fh:
            fh.write(to_markdown(data))
        ov = m1["agreement"]["overall"]
        print("\n== M1 recomputed ==")
        for d in DIRECTIONS:
            print(f"  {d:<16} {ov['counts'][d]}")
        print(f"understatement_rate={ov['understatement_rate']} "
              f"overstatement_rate={ov['overstatement_rate']}")
        print(f"json -> {out_json}")
        return 0

    pages: "OrderedDict[str, str]" = OrderedDict()
    page_meta: dict[str, dict] = {}
    for vec_row in vectors:
        for ctx, escaped in plan:
            cid = f"{vec_row['id']}__{ctx}{'__esc' if escaped else ''}"
            pages[cid] = build_page(vec_row["vector"], ctx, escaped)
            page_meta[cid] = {"vector_row": vec_row, "context": ctx,
                              "escaped": escaped}
    control_pages: "OrderedDict[str, str]" = OrderedDict()
    for cid, vec, ctx in KNOWN_EXEC_CONTROLS:
        control_pages[cid] = build_page(vec, ctx, False)
    for cid, vec, ctx in BENIGN_CONTROLS:
        control_pages[cid] = build_page(vec, ctx, False)

    all_pages = OrderedDict(control_pages)
    all_pages.update(pages)

    # oracle (M1)
    if args.skip_oracle:
        oracle_out = {cid: {"oracle": "skipped", "dialogs": []}
                      for cid in all_pages}
    else:
        srv0 = _serve_pages(all_pages, args.port)
        pages_port = srv0.server_address[1]
        oracle_out = run_oracle(all_pages, f"http://127.0.0.1:{pages_port}")
        srv0.shutdown()

    # controls must be sane or we abort (no publishing a broken measurement)
    ctl_rows = []
    for cid in list(control_pages):
        o = oracle_out[cid]["oracle"]
        s = run_sandbox({cid: control_pages[cid]})[cid]["sandbox"]
        ctl_rows.append({"id": cid, "oracle": o, "sandbox": s})
    if not args.skip_oracle:
        for cid, _v, _c in KNOWN_EXEC_CONTROLS:
            if oracle_out[cid]["oracle"] != "exec":
                print(f"[abort] 控制页 {cid} oracle={oracle_out[cid]['oracle']},"
                      "oracle 坏了,不发布", file=sys.stderr)
                return 3
            if ctl_rows[[r["id"] for r in ctl_rows].index(cid)]["sandbox"] \
                    != CONTROLS_EXPECTED_SANDBOX[cid]:
                print(f"[abort] 控制页 {cid} sandbox="
                      f"{ctl_rows[[r['id'] for r in ctl_rows].index(cid)]['sandbox']}"
                      f"(期望 {CONTROLS_EXPECTED_SANDBOX[cid]})", file=sys.stderr)
                return 3
        for cid, _v, _c in BENIGN_CONTROLS:
            if oracle_out[cid]["oracle"] != "inert":
                print(f"[abort] 良性控制页 {cid} oracle={oracle_out[cid]['oracle']}",
                      file=sys.stderr)
                return 3

    # sandbox (M1)
    sandbox_out = run_sandbox(pages)

    rows = []
    for cid, meta in page_meta.items():
        row = {
            "id": cid,
            "vector": meta["vector_row"]["vector"],
            "corpus": meta["vector_row"]["corpus"],
            "context": meta["context"],
            "escaped": meta["escaped"],
            "oracle": oracle_out[cid]["oracle"],
            "dialogs": oracle_out[cid]["dialogs"],
            "sandbox": sandbox_out[cid]["sandbox"],
            "activation": sandbox_out[cid]["activation"],
            "reason": sandbox_out[cid]["reason"],
        }
        row["direction"] = classify(row)
        rows.append(row)

    m1 = {
        "selected_vectors": len(vectors),
        "contexts": len(plan),
        "pages": len(rows),
        "agreement": aggregate(rows),
        "rows": rows,
        "control_rows": ctl_rows,
    }

    data = {
        "phase": "392",
        "tree": args.tree,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "honesty_header": (
            "向量全部来自第三方开源项目(PortSwigger 2026 cheat sheet / SecLists / "
            "PayloadsAllTheThings / OWASP XSS Filter Evasion Cheat Sheet / "
            "html5sc),原样使用、不清洗不改写;oracle 是本机真实 Chromium 的 "
            "load 态对话框事件;被测对象是引擎 verify gate 用的同一个 "
            "sandbox 分类器(见下)。这不是 XSSMaze 那样的 F1 跑分,也不与 "
            "194 矩阵、bWAPP、Juice Shop 任何数字并列。"),
        "selection": sel_stats,
        "m1": m1,
        "not_comparable": [
            "本表是『外部向量上 sandbox 分类器与真浏览器的一致性』,不是检测器 F1;"
            "XSSMaze(官方靶+官方 scorer)仍是唯一 F1 来源",
            "oracle 只看 load 态对话框:需要交互的向量与无对话框执行(print()/"
            "静默外带)会被记 inert——是 ground truth 的已知局限,不是工具判定",
            "烤页(把向量直接写进页面)不在 CLI 扫描器的检出面上:检出是反射"
            "驱动的,Phase 392 pilot 实测 8 个 oracle-EXEC 烤页 plain 与 "
            "--headless 均 0 findings——这是引擎设计边界,如实记录",
            "M2 第三方工具行是事实表:dalfox/nuclei 没拿到执行级 oracle,"
            "预算也不同,按 Phase 380 规则不出 TP/FP/率",
        ],
    }

    def _write_evidence() -> tuple[str, str]:
        out_json = args.out or os.path.join(_HERE, "results",
                                            RESULT_STEM + ".json")
        os.makedirs(os.path.dirname(out_json), exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        md_path = os.path.splitext(out_json)[0] + ".md"
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(data))
        return out_json, md_path

    # M1 evidence hits disk BEFORE M2 runs: a crash in the cheap part must
    # never destroy the 20-minute oracle pass again (measured once already).
    out_json, md_path = _write_evidence()

    if args.part in ("m2", "all"):
        srv = _serve_twin(0 if args.port == 0 else args.port + 1)
        twin_port = srv.server_address[1]
        try:
            data["m2"] = run_m2(f"http://127.0.0.1:{twin_port}", args.tree)
        finally:
            srv.shutdown()
        out_json, md_path = _write_evidence()

    ov = data["m1"]["agreement"]["overall"]
    print("\n== M1 summary ==")
    print(f"vectors={len(vectors)} pages={len(rows)}")
    for d in DIRECTIONS:
        print(f"  {d:<16} {ov['counts'][d]}")
    print(f"understatement_rate={ov['understatement_rate']} "
          f"overstatement_rate={ov['overstatement_rate']}")
    print(f"json -> {out_json}")
    print(f"md   -> {md_path}")
    return 0


def _serve_pages(pages: dict[str, str], port: int):
    class _H(BaseHTTPRequestHandler):
        def do_GET(self):
            cid = self.path.lstrip("/").split("?")[0]
            if cid in pages:
                body = pages[cid].encode("utf-8")
                code, ctype = 200, "text/html; charset=utf-8"
            else:
                body, code, ctype = b"not found", 404, "text/plain"
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # noqa: N802
            pass

    import threading
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _serve_twin(port: int):
    class _RealHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            path, _, query = self.path.partition("?")
            body = serve_twin(path, query).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    import threading
    srv = ThreadingHTTPServer(("127.0.0.1", port), _RealHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    raise SystemExit(main())
