#!/usr/bin/env python3
"""Shape bridge: dalfox CLI -> XSSMaze official runner contract (Phase 342).

Mirrors wrapper.py (the XSSentinel bridge) byte-for-byte in contract:
  * stdout carries exactly {"findings": [{"url": ..., "type": ..., "severity": ...}]}
    -- the official runner's --detect-json 'findings[].url' reads presence of
    url entries as detections for that case.
  * one TSV row per invocation in $XSSMAZE_INVLOG, same column order as
    wrapper.py, so attribute.py and every offline replay work unchanged
    (the sevs column counts forwarded severities; the types column counts
    EVERY parsed entry, so a stricter/looser contract can be re-scored
    offline without re-scanning).

Forwarding rule: V/found entries only -- see the invocation section below
for the measured reason (R entries are reflection notes, not claims).

Parsing helpers are LOCAL COPIES (_p342_toolparse), not benchmark.adapters
imports: the adapters import chain pulls in benchmark/server.py, which the
host AV quarantined mid-run on 2026-10-30 (measured: 976 consecutive
silent wrapper crashes scored as "not flagged").  See that module's
docstring for the full record.

Env:
  XSSMAZE_TIMEOUT=100    wrapper-side wall cap (p341 XSSentinel parity)
  XSSMAZE_INVLOG=path    TSV invocation log (same columns as wrapper.py)
  XSSMAZE_DALFOX_BIN=... binary override; default _p342_toolparse.find_tool
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _p342_toolparse import find_tool, parse_dalfox_findings  # noqa: E402


def _counts(items):
    out = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return ",".join(f"{k}:{v}" for k, v in sorted(out.items())) or "-"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: wrapper_dalfox.py URL", file=sys.stderr)
        return 2
    url = sys.argv[1]
    timeout = float(os.environ.get("XSSMAZE_TIMEOUT", "100"))
    binary = os.environ.get("XSSMAZE_DALFOX_BIN") or find_tool("dalfox")
    if not binary:
        print(json.dumps({"findings": []}))
        print("dalfox binary not found", file=sys.stderr)
        return 0

    # --skip-headless is load-bearing, measured 2026-10-30: dalfox's chromedp
    # headless layer (DOM-XSS / inJS verification) is host-unstable here --
    # clean scans alternate with teardown hangs (findings already on stdout,
    # process never exits) and a hard `panic: close of closed channel` inside
    # chromedp.(*ExecAllocator).Allocate (rc=2); ~50% of invocations, on a
    # plain localhost server too.  --skip-headless is 5/5 stable at 1.5-1.7s.
    # The main arm therefore runs dalfox's stable HTTP battery; the headless
    # layer's contribution is quantified separately on a sample (p342 record).
    #
    # Workers stay at dalfox's default (no --worker 1), also measured: with
    # --worker 1 dalfox serializes its ~2000-query battery and multi-param
    # XSSMaze pages take 60-100s+ (level1 hit the 100s cap, level2 74.7s);
    # default workers complete the same pages in 1-2s.
    cmd = [binary, "url", url, "--format", "json", "--silence"]
    # XSSMAZE_DALFOX_HEADLESS=1 re-enables the chromedp layer -- used only by
    # the p342 quantification sample that measures what --skip-headless costs
    # the main arm; never by the main run (see the measured note above).
    if os.environ.get("XSSMAZE_DALFOX_HEADLESS", "").strip() not in ("1", "true", "yes"):
        cmd.append("--skip-headless")
    parsed = []
    rc = None
    err = ""
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout)
        rc = proc.returncode
        parsed = parse_dalfox_findings(proc.stdout or "")
        err = (proc.stderr or "").strip().splitlines()[-1][:300] if proc.stderr else ""
        if not parsed and rc not in (0, None):
            err = f"{err} | dalfox rc={rc}".strip(" |")
    except subprocess.TimeoutExpired:
        rc = "timeout"
        err = f"wrapper timeout after {timeout}s"
    except OSError as exc:
        rc = "oserror"
        err = str(exc)[:300]
    elapsed = time.time() - t0

    # stdin=DEVNULL is load-bearing: dalfox treats a non-terminal stdin as a
    # piped URL list and blocks under subprocess.run (measured 60s timeouts
    # in-wrapper vs 5.8s real scan with DEVNULL).  Forwarding is V/found
    # only: dalfox v2.13.0 emits R entries ("Reflected Payload in HTML",
    # message_id 464, severity Medium) carrying payload fields; counting
    # them would score every reflection candidate as detection (level3
    # measured R:507 vs V:1).  The TSV keeps the full type census.
    forwarded = [f for f in parsed
                 if str(f.get("type", "")).lower() in ("v", "found")]
    payload = {"findings": [
        {"url": url, "type": f"dalfox:{str(f.get('type', '?'))}",
         "severity": str(f.get("severity", "")).strip().lower() or None}
        for f in forwarded if isinstance(f, dict)
    ]}
    print(json.dumps(payload))

    log_path = os.environ.get("XSSMAZE_INVLOG")
    if log_path:
        types = _counts([str(f.get("type", "?")) for f in parsed])
        sevs = _counts([str(f.get("severity", "?")).strip().lower()
                        for f in forwarded])
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write("\t".join([
                time.strftime("%H:%M:%S"), url, str(rc), f"{elapsed:.1f}",
                str(len(forwarded)), sevs, types, err.replace("\t", " "),
            ]) + "\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - never fail silently
        # The runner discards stderr and scores an empty stdout as "not
        # flagged"; the AV-quarantine incident scored 976 cases through this
        # path invisibly.  A crash must leave a visible TSV row.
        url = sys.argv[1] if len(sys.argv) > 1 else "?"
        log_path = os.environ.get("XSSMAZE_INVLOG")
        if log_path:
            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write("\t".join([
                    time.strftime("%H:%M:%S"), url, "wrapper-error", "0.0",
                    "0", "-", "-", repr(exc)[:200].replace("\t", " "),
                ]) + "\n")
        print(json.dumps({"findings": []}))
        raise
