#!/usr/bin/env python3
"""Shape bridge: nuclei DAST-xss templates -> XSSMaze official runner contract.

Mirrors wrapper.py (the XSSentinel bridge) byte-for-byte in contract:
  * stdout carries exactly {"findings": [{"url": ..., "type": ..., "severity": ...}]}
    -- the official runner's --detect-json 'findings[].url' reads presence of
    url entries as detections for that case.
  * one TSV row per invocation in $XSSMAZE_INVLOG, same column order as
    wrapper.py, so attribute.py and every offline replay work unchanged.

The nuclei invocation and the severity filter are the Phase 196b contract,
REUSED verbatim so the two comparison rounds are one ruler:
  nuclei -u <url> -dast -t <dast/vulnerabilities/xss> -jsonl -silent
         -no-color -timeout 10 -retries 1 -duc -nc
  a hit is a JSONL line whose info.severity is medium/high/critical
  (info-level reflection detections are not claims of a vulnerability).
-duc / -nc are load-bearing on this host: without them the template-update
probe hung for the full ceiling before a single fuzz request (196b).
stdin is pinned to DEVNULL: nuclei also reads a non-terminal stdin as a URL
list (dalfox measured blocking exactly there on 2026-10-30), and a hung
child must never be able to wait on an inherited pipe.

Parsing helpers are LOCAL COPIES (_p342_toolparse), not benchmark.adapters
imports: the adapters import chain pulls in benchmark/server.py, which the
host AV quarantined mid-run on 2026-10-30 (measured: 976 consecutive
silent wrapper crashes scored as "not flagged").  See that module's
docstring for the full record.

Env:
  XSSMAZE_TIMEOUT=100          wrapper-side wall cap (p341 XSSentinel parity)
  XSSMAZE_INVLOG=path          TSV invocation log (same columns as wrapper.py)
  XSSMAZE_NUCLEI_BIN=...       binary override; default _p342_toolparse.find_tool
  XSSMAZE_NUCLEI_TEMPLATES=... template dir override; default ~/nuclei-templates/dast/vulnerabilities/xss
"""
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _p342_toolparse import find_tool  # noqa: E402


def _counts(items):
    out = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return ",".join(f"{k}:{v}" for k, v in sorted(out.items())) or "-"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: wrapper_nuclei.py URL", file=sys.stderr)
        return 2
    url = sys.argv[1]
    timeout = float(os.environ.get("XSSMAZE_TIMEOUT", "100"))
    binary = os.environ.get("XSSMAZE_NUCLEI_BIN") or find_tool("nuclei")
    templates = os.environ.get("XSSMAZE_NUCLEI_TEMPLATES") or os.path.join(
        os.path.expanduser("~"), "nuclei-templates", "dast",
        "vulnerabilities", "xss")
    if not binary or not os.path.isdir(templates):
        print(json.dumps({"findings": []}))
        print(f"nuclei binary or templates missing (bin={binary}, "
              f"tpl={templates})", file=sys.stderr)
        return 0

    cmd = [binary, "-u", url, "-dast", "-t", templates, "-jsonl", "-silent",
           "-no-color", "-timeout", "10", "-retries", "1", "-duc", "-nc"]
    hits = []
    rc = None
    err = ""
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout)
        rc = proc.returncode
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            sev = str((entry.get("info") or {}).get("severity", "")).lower()
            if sev in ("medium", "high", "critical"):
                hits.append(entry)
        err = (proc.stderr or "").strip().splitlines()[-1][:300] if proc.stderr else ""
    except subprocess.TimeoutExpired:
        rc = "timeout"
        err = f"wrapper timeout after {timeout}s"
    except OSError as exc:
        rc = "oserror"
        err = str(exc)[:300]
    elapsed = time.time() - t0

    payload = {"findings": [
        {"url": url,
         "type": f"nuclei:{entry.get('template-id', entry.get('templateID', '?'))}",
         "severity": str((entry.get("info") or {}).get("severity", "")).lower() or None}
        for entry in hits if isinstance(entry, dict)
    ]}
    print(json.dumps(payload))

    log_path = os.environ.get("XSSMAZE_INVLOG")
    if log_path:
        types = _counts([
            str(e.get("template-id", e.get("templateID", "?"))) for e in hits])
        sevs = _counts([str((e.get("info") or {}).get("severity", "?")).lower()
                        for e in hits])
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write("\t".join([
                time.strftime("%H:%M:%S"), url, str(rc), f"{elapsed:.1f}",
                str(len(hits)), sevs, types, err.replace("\t", " "),
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
