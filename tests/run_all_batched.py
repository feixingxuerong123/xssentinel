"""Run the whole test suite file-by-file with one automatic retry.

Why this exists: on this host a security product intermittently kills
loopback connections, so a SINGLE-process `pytest tests/` wedges.  Running
file-by-file with a per-file timeout and one retry is the only reliable
full-suite gate here (file count is whatever tests/ holds at run time --
a count frozen in this docstring rotted from 46 to 129 within a few
months, so it is not written down anymore; expect 10+ minutes).  Usage:

    python tests/run_all_batched.py            # all files
    python tests/run_all_batched.py --quiet    # only print failures

Exit code: number of files that still fail after the retry (0 = green).
"""
from __future__ import annotations
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PER_FILE_TIMEOUT = 540        # seconds
# Phase 114: per-file overrides.  test_benchmark_fp.py runs one FULL CLI
# scan per safe manifest case (47+ of them since Phases 109-113 added the
# blind-spot families), which on a slow host exceeds the default budget
# even though nothing is wrong.  The file is the FPR regression gate, so
# it gets its own, larger budget instead of being trimmed down.
PER_FILE_TIMEOUT_OVERRIDES = {
    # Phase 203: the parity gate runs a 12-endpoint reflection slice AND a
    # 12-endpoint DOM slice (real browser renders) through BOTH engines --
    # legitimately the slowest gate file in the suite.
    "test_engine_parity_gate.py": 1500,
    "test_benchmark_fp.py": 1800,
    # Measured 2026-09-26: 11 passed in 3112s on this host -- the budget
    # accounting tests are legitimately slow on the degraded loopback,
    # not wedged.  The old 540s ceiling burned 2 retries and recorded the
    # file "unverified" every gate; a green gate needs its real budget.
    "test_async_budget.py": 3600,
}
RETRIES = 1


LOG_DIR = os.path.join(ROOT, "benchmark", "results", "regression_logs")
RUN_TS = time.strftime("%Y%m%d-%H%M%S")


def _dump_log(path: str, attempts: list) -> None:
    """Persist captured pytest output.

    With --quiet the runner used to throw every file's output away and
    print only "FAIL <file>" -- a red gate with no way to see WHY short of
    re-running the whole file (which, on a degraded-loopback host, can
    take hours).  Evidence must survive the run.
    """
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        buf = []
        for attempt, rc, out, err in attempts:
            buf.append(f"===== attempt {attempt} rc={rc} =====")
            for label, blob in (("stdout", out), ("stderr", err)):
                if not blob:
                    continue
                text = blob.decode("utf-8", "replace") \
                    if isinstance(blob, bytes) else str(blob)
                buf.append(f"--- {label} ---")
                buf.append(text[-20000:])
        buf.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(buf))
    except Exception as e:          # logging must never break the gate
        print(f"[!] could not write {path}: {e}", flush=True)


def _skip_counts(stdout) -> tuple:
    """(skipped_tests, all_skipped) from a pytest summary line.

    A green file is not the same claim as a file that RAN.  Several files
    carry `pytestmark = skipif(not SOCKETPAIR_OK, ...)` -- 21 of them, by
    the AST count in dev/_socketpair_gate_flip_probe.py -- and when this
    host throttles socketpair they report "skipped" and the runner still
    counts them green.  Without this, "170/170 files green" reads as
    "everything ran" when it only means "nothing failed".

    Returns the count of SKIPPED tests, and whether the file was skipped
    WHOLE (every test skipped, i.e. the file contributed nothing).
    """
    # 20 files by the AST census in dev/_audit_test_suite.py (2026-10-07);
    # the "21" in earlier notes came from a probe whose classifier also
    # counted per-test markers.  Quote the census, not the probe.


    text = (stdout or b"")
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    m = re.search(r"(\d+) skipped", text)
    skipped = int(m.group(1)) if m else 0
    p = re.search(r"(\d+) passed", text)
    passed = int(p.group(1)) if p else 0
    return skipped, (skipped > 0 and passed == 0)


def _write_timing_report(timings: list, failures: list, dt: float) -> str:
    """Persist per-file wall time.

    The gate has always printed only its total.  With 170 files and a
    6700s run, "which file is slow" was unanswerable without re-running
    everything -- so speed work on the suite was guesswork.  The total is
    still the headline; this is the evidence behind it.
    """
    path = os.path.join(LOG_DIR, RUN_TS, "_timings.txt")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = [f"total {dt:.0f}s  files {len(timings)}  "
                 f"failures {len(failures)}",
                 "# file seconds  (sorted slowest first)"]
        for f, secs in sorted(timings, key=lambda t: -t[1]):
            lines.append(f"{secs:8.1f}  {f}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except Exception as e:      # reporting must never break the gate
        print(f"[!] could not write timing report: {e}", flush=True)
        return ""
    return path


def main() -> int:
    quiet = "--quiet" in sys.argv
    # Any argv item that names a test file limits the run to those files --
    # lets a long degraded run be resumed file by file instead of redone.
    wanted = [a for a in sys.argv[1:] if a.startswith("test_")]
    os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")
    files = sorted(f for f in os.listdir(HERE)
                   if f.startswith("test_") and f.endswith(".py"))
    if wanted:
        files = [f for f in files if f in wanted]
    failures: list[str] = []
    skipped_files: list[tuple] = []   # (file, skipped_test_count)
    timings: list[tuple] = []         # (file, seconds) -- every file, incl. fails
    t0 = time.perf_counter()
    for f in files:
        budget = PER_FILE_TIMEOUT_OVERRIDES.get(f, PER_FILE_TIMEOUT)
        t_file = time.perf_counter()
        rc = 1
        attempts: list = []
        for attempt in range(RETRIES + 1):
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pytest", os.path.join(HERE, f),
                     "-q"],
                    cwd=ROOT, timeout=budget,
                    capture_output=True)
                rc = r.returncode
                attempts.append((attempt, rc, r.stdout, r.stderr))
            except subprocess.TimeoutExpired as exc:
                rc = 2   # hung file: treat as failure, do not kill the gate
                attempts.append((attempt, "TIMEOUT",
                                 exc.stdout or b"", exc.stderr or b""))
            if rc == 0:
                break
        if rc == 0:
            skipped, whole = _skip_counts(attempts[-1][2] if attempts else b"")
            if skipped:
                skipped_files.append((f, skipped, whole))
        timings.append((f, time.perf_counter() - t_file))
        log_path = os.path.join(LOG_DIR, RUN_TS, f + ".log")
        if attempts and (rc != 0 or len(attempts) > 1):
            _dump_log(log_path, attempts)
        if rc != 0:
            failures.append(f)
            if os.path.exists(log_path):
                print(f"FAIL {f}  log: {log_path}", flush=True)
            else:
                print(f"FAIL {f}", flush=True)
            if not quiet:
                tail = (r.stdout or b"")[-2000:].decode("utf-8", "replace")
                print(tail, flush=True)
        else:
            if not quiet:
                print(f"ok   {f}", flush=True)
    dt = time.perf_counter() - t0
    print(f"\n{len(files) - len(failures)}/{len(files)} files green "
          f"in {dt:.0f}s; failures: {failures or 'none'}")
    # 'green' means 'nothing failed', not 'everything ran'.  Report the
    # second number so the first one cannot be read as the second.
    total_skipped = sum(n for _f, n, _w in skipped_files)
    whole = [f for f, n, w in skipped_files if w]
    if skipped_files:
        print(f"skipped tests: {total_skipped} across "
              f"{len(skipped_files)} file(s)")
        for f, n, w in skipped_files:
            print(f"  SKIP {f}: {n} skipped"
                  f"{'  (WHOLE FILE -- contributed nothing)' if w else ''}")
    else:
        print("skipped tests: 0")
    if whole:
        print(f"\n! {len(whole)} file(s) contributed nothing to this gate "
              f"while counting as green.\n  A green gate with skipped "
              f"files is not the same claim as a green gate\n  where "
              f"everything ran; quote both numbers together.")
    # Slowest files: without a per-file number, "the gate is slow" cannot
    # be turned into "this file is slow", and speed work stays guesswork.
    if timings:
        slowest = sorted(timings, key=lambda t: -t[1])[:15]
        top = sum(s for _f, s in slowest)
        print(f"\nslowest {len(slowest)} files "
              f"({top:.0f}s of {dt:.0f}s = {100*top/dt:.0f}% of the run):")
        for f, secs in slowest:
            print(f"  {secs:8.1f}s  {f}")
        tp = _write_timing_report(timings, failures, dt)
        if tp:
            print(f"per-file timings: {tp}")
    if failures:
        print(f"logs: {os.path.join(LOG_DIR, RUN_TS)}")
    return len(failures)


if __name__ == "__main__":
    sys.exit(main())
