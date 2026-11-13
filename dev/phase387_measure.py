#!/usr/bin/env python3
"""Phase 387: measure the four official strict-gate wall-clock baselines.

The budgets are MEASURED, not aspirational, so re-measuring them has to be a
repeatable command rather than four hand-typed shell lines whose port, TEMP
redirection and NO_PROXY settings drift between runs.

Each arm is an independent real strict-gate run through the supported scratch
wrapper (``dev/gate_run_scratch.py``), on its own clean loopback port, with the
report scratch outside the workspace (the safe-delete guard caps file
deletions/overwrites inside it) and NO_PROXY set (the agent shell injects an
egress proxy that otherwise serves the target's index.html for subsequent
static assets).  Arms run SERIALLY: parallel arms would contend for loopback
and contaminate the wall clock the budget is made of.

Resumable: an arm whose artifact is already a clean strict-gate result is
skipped unless ``--force``; ``--only quick:sync`` re-measures one arm.

Usage:
    C:/Python39/python.exe dev/phase387_measure.py
    C:/Python39/python.exe dev/phase387_measure.py --only full:async --force
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmark" / "results"
LOCAL = RESULTS / "_local_archive"
SCRATCH = ROOT.parent / "_xssentinel_scratch" / "tmp"
WRAPPER = ROOT / "dev" / "gate_run_scratch.py"
PY = sys.executable

ARMS = (("quick", "sync"), ("quick", "async"),
        ("full", "sync"), ("full", "async"))
BASE_PORT = 18951
PORT_LIMIT = 19000


def _free_port(start: int) -> int:
    """First loopback port that can actually be bound (zombie LISTENING
    sockets from earlier gate runs are a documented host condition)."""
    for port in range(start, PORT_LIMIT):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"no free loopback port in {start}..{PORT_LIMIT}")


def _env() -> dict:
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)          # clean environment, as the release gate
    SCRATCH.mkdir(parents=True, exist_ok=True)
    probe = SCRATCH / "phase387_write_probe"
    probe.write_text("ok", encoding="utf-8")
    probe.unlink()
    env["TEMP"] = str(SCRATCH)
    env["TMP"] = str(SCRATCH)
    env["NO_PROXY"] = "127.0.0.1,localhost,::1"
    env["no_proxy"] = "127.0.0.1,localhost,::1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _clean_artifact(path: Path) -> dict | None:
    """An already-measured arm is reusable ONLY if it is a clean strict-gate
    result.  A red/degraded artifact must never be promoted into a baseline."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (data.get("fp") or data.get("fn") or data.get("errors")):
        return None
    if not (data.get("tp", 0) + data.get("tn", 0)):
        return None
    if data.get("total_cases") != len(data.get("cases", [])):
        return None
    return data


def _run_arm(mode: str, engine: str, port: int, out: Path,
             env: dict, date: str) -> dict:
    cmd = [PY, str(WRAPPER), "--strict-gate", "--engine", engine,
           "--port", str(port), "-o", str(out)]
    if mode == "quick":
        cmd.append("--quick")
    log = LOCAL / f"phase387_{mode}_{engine}_{date}.log"
    started = time.monotonic()
    with log.open("w", encoding="utf-8") as fh:
        fh.write(f"cmd: {' '.join(cmd)}\n")
        fh.write(f"TEMP={env['TEMP']} NO_PROXY={env['NO_PROXY']}\n\n")
        fh.flush()
        proc = subprocess.run(cmd, cwd=str(ROOT), env=env, stdout=fh,
                              stderr=subprocess.STDOUT, text=True,
                              timeout=900 if mode == "quick" else 2400)
        fh.write(f"\nexit={proc.returncode} "
                 f"wall={time.monotonic() - started:.1f}s\n")
    data = _clean_artifact(out)
    if proc.returncode != 0 or data is None:
        tail = log.read_text(encoding="utf-8", errors="replace")[-1200:]
        raise RuntimeError(f"{mode}/{engine} rc={proc.returncode} "
                           f"clean_artifact={data is not None}\n{tail}")
    return data


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--date", default=datetime.now().strftime("%Y%m%d"),
                    help="artifact date stamp (default: today)")
    ap.add_argument("--only", choices=[f"{m}:{e}" for m, e in ARMS],
                    help="re-measure just one arm (resumable)")
    ap.add_argument("--force", action="store_true",
                    help="re-measure arms that already have a clean artifact")
    args = ap.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    LOCAL.mkdir(parents=True, exist_ok=True)
    env = _env()
    summary: dict[str, dict] = {}
    failures: list[str] = []
    port_cursor = BASE_PORT

    for mode, engine in ARMS:
        if args.only and args.only != f"{mode}:{engine}":
            continue
        out = RESULTS / f"perf_baseline_{mode}_{engine}_{args.date}.json"
        reused = None if args.force else _clean_artifact(out)
        if reused is not None:
            data = reused
            status = "REUSED (clean artifact)"
        else:
            if out.exists():
                backup = LOCAL / (out.name + ".pre387." +
                                  datetime.now().strftime("%H%M%S"))
                shutil.move(str(out), str(backup))
                print(f"[*] previous {out.name} preserved at {backup.name}",
                      flush=True)
            port = _free_port(port_cursor)
            port_cursor = port + 1
            print(f"[*] measuring {mode}/{engine} on port {port} ...",
                  flush=True)
            try:
                data = _run_arm(mode, engine, port, out, env, args.date)
                status = "MEASURED"
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                failures.append(f"{mode}/{engine}: {exc}")
                print(f"[!] {mode}/{engine} FAILED: {exc}", flush=True)
                continue
        skipped = sum(1 for c in data["cases"] if c["verdict"] == "SKIP")
        row = {
            "artifact": out.name,
            "status": status,
            "total_cases": data["total_cases"],
            "total_time_s": data["total_time_s"],
            "timestamp": data["timestamp"],
            "engine": data["engine"],
            "fp": data["fp"], "fn": data["fn"], "errors": data["errors"],
            "scored": data["tp"] + data["tn"],
            "skipped": skipped,
        }
        summary[f"{mode}/{engine}"] = row
        print(f"[+] {mode}/{engine}: {status} "
              f"{row['total_time_s']:.2f}s / {row['total_cases']} cases "
              f"(scored {row['scored']}, SKIP {skipped})", flush=True)

    (LOCAL / f"phase387_summary_{args.date}.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nsummary: {len(summary)} arms, {len(failures)} failures",
          flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
