#!/usr/bin/env python3
"""Shape bridge: xssentinel CLI -> XSSMaze official runner contract.

The official runner requires an explicit detection contract; per-URL mode
asks "did this invocation flag anything" by extracting `findings[].url`
from stdout.  This wrapper runs the scanner once, prints exactly that shape,
and appends one TSV row per invocation to $XSSMAZE_INVLOG so a run can be
attributed offline (the runner discards the scanner's own output).

It filters nothing: every finding the scanner reports is forwarded, because
the lab's FP definition is "any finding on a control endpoint".  Severity
and type are copied into the TSV so the credited-severity view can be
reconstructed without re-scanning.

Env:
  XSSMAZE_HEADLESS=1     add --headless
  XSSMAZE_ASYNC=1        add --async
  XSSMAZE_EXTRA="..."    extra CLI args (shlex-split)
  XSSMAZE_TIMEOUT=110    wrapper-side timeout; keep below runner's per-URL one
  XSSMAZE_INVLOG=path    TSV invocation log

  XSSMAZE_POST_AWARE=1   OPT-IN: the official runner passes only a URL, so
                         POST-only endpoints were scanned with a GET and no
                         body -- they could never be detected.  With this
                         flag AND XSSMAZE_MAP_INDEX, POST endpoints get
                         ``-m POST -d <params>``.  OFF by default so the
                         historical scorecard stays byte-reproducible.
  XSSMAZE_MAP_INDEX=...  JSON ``{path: {method, params}}`` from /map/json
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlparse

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip() in ("1", "true", "yes")


def _counts(items):
    out = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return ",".join(f"{k}:{v}" for k, v in sorted(out.items())) or "-"


def _post_params(url: str):
    """Return the POST body parameter names for this URL, or None.

    Opt-in AND fail-safe: with the flag off, the index missing, the path
    absent, or a read/parse error, this returns None and the command stays
    byte-identical to the historical wrapper.  A GET endpoint in the index
    also returns None -- the fix must never change the GET population.
    """
    if not _flag("XSSMAZE_POST_AWARE"):
        return None
    index_path = os.environ.get("XSSMAZE_MAP_INDEX", "").strip()
    if not index_path:
        return None
    try:
        with open(index_path, encoding="utf-8") as fh:
            index = json.load(fh)
        entry = index.get(urlparse(url).path)
    except (OSError, ValueError, TypeError):
        return None
    if not isinstance(entry, dict):
        return None
    if str(entry.get("method", "GET")).upper() != "POST":
        return None
    params = [p for p in (entry.get("params") or [])
              if isinstance(p, str) and p.strip()]
    return params or None


def _build_cmd(url, out_path, headless, use_async, extra, post_params):
    """One command shape; the DEFAULT branch must never drift."""
    cmd = [sys.executable, "-m", "xssentinel", "-u", url,
           "-f", "json", "-o", out_path,
           "--progress", "none", "--log-level", "error"]
    if headless:
        cmd.append("--headless")
    if use_async:
        cmd.append("--async")
    if post_params:
        cmd += ["-m", "POST", "-d",
                urlencode({p: "xssentinel_bench_probe" for p in post_params})]
    cmd += extra
    return cmd


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: wrapper.py URL", file=sys.stderr)
        return 2
    url = sys.argv[1]
    timeout = float(os.environ.get("XSSMAZE_TIMEOUT", "110"))
    headless = _flag("XSSMAZE_HEADLESS")
    use_async = _flag("XSSMAZE_ASYNC")
    extra = shlex.split(os.environ.get("XSSMAZE_EXTRA", ""))
    post_params = _post_params(url)

    findings = []
    rc = None
    err = ""
    with tempfile.TemporaryDirectory(prefix="xmz_") as tmp:
        out_path = os.path.join(tmp, "report.json")
        cmd = _build_cmd(url, out_path, headless, use_async, extra,
                         post_params)
        env = os.environ.copy()
        env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
        t0 = time.time()
        try:
            proc = subprocess.run(cmd, cwd=REPO, env=env, capture_output=True,
                                  text=True, encoding="utf-8", errors="replace",
                                  timeout=timeout)
            rc = proc.returncode
            err = (proc.stderr or "").strip().splitlines()[-1][:300] if proc.stderr else ""
        except subprocess.TimeoutExpired:
            rc = "timeout"
            err = f"wrapper timeout after {timeout}s"
        elapsed = time.time() - t0
        if os.path.exists(out_path):
            try:
                with open(out_path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                findings = doc.get("findings") or []
            except Exception as exc:  # noqa: BLE001 - rig must never crash a case
                err = f"{err} | report parse: {exc}"[:400]

    payload = {"findings": [
        {"url": url, "type": f.get("type"), "severity": f.get("severity")}
        for f in findings if isinstance(f, dict)
    ]}
    print(json.dumps(payload))

    log_path = os.environ.get("XSSMAZE_INVLOG")
    if log_path:
        if post_params:
            # Audit trail: which invocations used the POST-aware shape.
            tag = "POST:" + "+".join(post_params)
            err = (err + " | " + tag) if err else tag
        types = _counts([f.get("type", "?") for f in findings])
        sevs = _counts([f.get("severity", "?") for f in findings])
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write("\t".join([
                time.strftime("%H:%M:%S"), url, str(rc), f"{elapsed:.1f}",
                str(len(findings)), sevs, types, err.replace("\t", " "),
            ]) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
