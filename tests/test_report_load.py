"""The report-load benchmark keeps working (OPTIMIZATION 2.2).

The script is the committed BASELINE artifact: if someone changes the
report builders, re-running it must still produce every format and a
result JSON.  50 findings keep the test fast; the 1000-finding numbers
live in benchmark/results/report_load_*.json.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_report_load_benchmark_runs_all_formats(tmp_path):
    import subprocess
    out = os.path.join(str(tmp_path), "report_load.json")
    r = subprocess.run(
        [sys.executable, os.path.join("benchmark", "report_load.py"),
         "--findings", "50", "--out", out],
        capture_output=True, text=True, timeout=120,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert r.returncode == 0, r.stderr[-500:]
    data = json.loads(open(out, encoding="utf-8").read())
    assert data["findings"] == 50
    for fmt in ("html", "json", "csv", "sarif", "junit", "markdown",
                "burp", "nuclei"):
        assert fmt in data["results"], fmt
        assert data["results"][fmt]["bytes"] > 0
        assert data["results"][fmt]["seconds"] < 10


def test_synthetic_findings_are_deterministic_and_shaped():
    from benchmark.report_load import synthetic_findings
    a = [f.data for f in synthetic_findings(20, seed=7)]
    b = [f.data for f in synthetic_findings(20, seed=7)]
    assert a == b                                    # deterministic
    for d in a:
        # every field the report builders read is present
        for key in ("url", "param", "type", "context", "payload",
                    "severity", "confidence", "evidence_class",
                    "detail", "proof", "transform", "param_in"):
            assert key in d, key
        assert len(d["payload"]) > 10
