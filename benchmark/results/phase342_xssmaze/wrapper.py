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
"""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip() in ("1", "true", "yes")


def _counts(items):
    out = {}
    for it in items:
        out[it] = out.get(it, 0) + 1
    return ",".join(f"{k}:{v}" for k, v in sorted(out.items())) or "-"


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: wrapper.py URL", file=sys.stderr)
        return 2
    url = sys.argv[1]
    timeout = float(os.environ.get("XSSMAZE_TIMEOUT", "110"))
    headless = _flag("XSSMAZE_HEADLESS")
    use_async = _flag("XSSMAZE_ASYNC")
    extra = shlex.split(os.environ.get("XSSMAZE_EXTRA", ""))

    findings = []
    rc = None
    err = ""
    with tempfile.TemporaryDirectory(prefix="xmz_") as tmp:
        out_path = os.path.join(tmp, "report.json")
        cmd = [sys.executable, "-m", "xssentinel", "-u", url,
               "-f", "json", "-o", out_path,
               "--progress", "none", "--log-level", "error"]
        if headless:
            cmd.append("--headless")
        if use_async:
            cmd.append("--async")
        cmd += extra
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
