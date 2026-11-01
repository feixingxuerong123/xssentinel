#!/usr/bin/env python3
"""Local copies of the two benchmark.adapters helpers the p342 wrappers need.

WHY A COPY AND NOT AN IMPORT (measured 2026-10-30): importing
benchmark.adapters pulls in benchmark.runner (for the gate budgets), whose
module body does `from server import run_server` -> benchmark/server.py.
That file -- a vulnerable HTTP server whose body is hundreds of XSS
payloads -- was quarantined by the host's AV suite (360SPService/HipsDaemon
running; Defender service stopped) at 2026-10-30 ~03:45, mid-run, after the
wrapper had imported it ~64 times.  Every wrapper invocation then died in
~256ms with ModuleNotFoundError; the official runner saw empty stdout and
scored 976 consecutive "not flagged" -- the 30/983 scorecard was an AV
artifact, not a measurement.  Decoupling the wrappers from the repo's
package graph removes benchmark/server.py from the critical path entirely.

PROVENANCE (keep in sync by intent, not by import): the three functions
below are copied verbatim from benchmark/adapters.py (Phase 196b, measured
against dalfox v2.13.0 including the trailing-{} terminator quirk and the
info/meta-entry FP artifact).  If adapters' parsing ever changes, revisit
these copies -- the p342 records name this file as the dalfox/nuclei
parsing contract for the XSSMaze rig.
"""
from __future__ import annotations

import json
import os
import shutil


def find_tool(name: str) -> str | None:
    """Locate an externally-installed tool, PATH first then $GOPATH/bin.

    Copied verbatim from benchmark.adapters._find_tool (Phase 148):
    ``go install`` writes to $GOPATH/bin which is not necessarily on PATH;
    an adapter that only calls which() reports "not installed" and the
    comparison quietly degrades to XSSentinel-only.
    """
    found = shutil.which(name)
    if found:
        return found
    dirs = [os.path.join(os.path.expanduser("~"), "go", "bin")]
    gopath = os.environ.get("GOPATH")
    if gopath:
        dirs.insert(0, os.path.join(gopath, "bin"))
    for d in dirs:
        for suffix in (".exe", ""):
            cand = os.path.join(d, name + suffix)
            if os.path.isfile(cand):
                return cand
    return None


def _is_dalfox_finding(f) -> bool:
    """True only for entries that carry real vulnerability signal.

    Copied verbatim from benchmark.adapters._is_dalfox_finding (Phase 196b).
    """
    if not isinstance(f, dict) or not f:
        return False
    t = str(f.get("type", "")).lower()
    if t in ("v", "found"):
        return True
    return bool(f.get("poc") or f.get("payload"))


def parse_dalfox_findings(stdout: str) -> list:
    """Parse dalfox `--format json` output into a list of finding dicts.

    Copied verbatim from benchmark.adapters._parse_dalfox_findings (196b):
    handles both the JSON array with trailing `{}` terminator and JSONL.
    """
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [f for f in data if _is_dalfox_finding(f)]
        if isinstance(data, dict):
            inner = data.get("findings")
            if isinstance(inner, list):
                return [f for f in inner if _is_dalfox_finding(f)]
            return [data] if _is_dalfox_finding(data) else []
    except json.JSONDecodeError:
        pass
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if _is_dalfox_finding(obj):
            findings.append(obj)
    return findings
