"""Dual-engine parity over a 64-family representative slice (Phase 208).

Runs every `(ground_truth, context)` family representative from
`benchmark/manifest.json` through BOTH engines using the parity gate's own
helpers (`test_engine_parity_gate._run_sync/_run_async/_diff`), and reports
wall time plus any verdict divergence.

Why this is a separate script and not part of the gate: it costs ~7 minutes
on a quiet host and has been measured at 3x that when the host's security
software drops loopback connections mid-run (WinError 10053 / WinError 64).
It is a periodic audit, not a gate -- see dev/PHASE208_parity_slice.md.

Three things this script does that the first version did not, each bought
with a lost run:

1. `benchmark.server.run_server()` is NOT a factory -- it enters
   `serve_forever()` and only returns after `shutdown()`.  Inline use
   (`srv = run_server(port=0)`) deadlocks before the first request: 17 min
   wall, 0.42s CPU, no output.  Correct shape: thread + `ready_callback`.
2. Every batch is persisted the moment it finishes (`_p208_state.json`,
   written atomically).  The first complete-ish run was killed at batch 6/8
   with all results in memory -- 20 minutes produced nothing.
3. A single batch cannot kill the run: each is wrapped in try/except with
   one retry; a batch that fails twice is stored as `{"error": ...}` and
   reported, never silently skipped.

Resume: just re-run it.  Batches already on disk are skipped.

    python benchmark/parity_slice_measure.py
"""
import os
import sys
import time
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))
sys.path.insert(0, HERE)

import json  # noqa: E402
import threading  # noqa: E402

from server import run_server as bench_run_server  # noqa: E402
from test_engine_parity_gate import _diff, _run_async, _run_sync  # noqa: E402

STATE = os.path.join(ROOT, "_p208_state.json")
BATCH = 8


def representatives():
    """One case per (ground_truth, context) family -- coverage, not sampling."""
    cases = json.load(open(os.path.join(HERE, "manifest.json"),
                          encoding="utf-8"))["cases"]
    seen = OrderedDict()
    for c in cases:
        fam = (c.get("ground_truth"), c.get("context"))
        if fam not in seen:
            seen[fam] = c
    return [(c["path"], c.get("param", "q")) for c in seen.values()]


def load_state():
    if os.path.exists(STATE):
        try:
            return json.load(open(STATE, encoding="utf-8"))
        except Exception as exc:
            print(f"state unreadable ({exc!r}) -- starting fresh", flush=True)
    return {"batches": {}}


def save_state(state):
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, default=str)
    os.replace(tmp, STATE)


def main():
    reps = representatives()
    print(f"representatives: {len(reps)}", flush=True)

    holder = {"ready": threading.Event(), "server": None, "port": None}

    def on_ready(srv):
        holder["server"] = srv
        holder["port"] = srv.server_address[1]
        holder["ready"].set()

    threading.Thread(target=bench_run_server, args=(0,),
                     kwargs={"ready_callback": on_ready}, daemon=True).start()
    assert holder["ready"].wait(15), "benchmark server did not start"
    srv = holder["server"]
    base = f"http://127.0.0.1:{holder['port']}"
    print(f"server ready: {base}", flush=True)

    state = load_state()
    done = state["batches"]
    nb = -(-len(reps) // BATCH)
    if done:
        print(f"resuming: {len(done)}/{nb} batches already on disk", flush=True)

    failed = []
    try:
        for i in range(0, len(reps), BATCH):
            tag = str(i // BATCH)
            if tag in done:
                continue
            batch = reps[i:i + BATCH]
            for attempt in (1, 2):
                try:
                    t0 = time.time()
                    s_out = _run_sync(base, batch)
                    ts = time.time() - t0
                    t0 = time.time()
                    a_out = _run_async(base, batch)
                    ta = time.time() - t0
                    done[tag] = {"sync": s_out, "async": a_out,
                                 "t_sync": ts, "t_async": ta}
                    save_state(state)
                    print(f"batch {int(tag) + 1}/{nb}: "
                          f"sync {ts:.1f}s  async {ta:.1f}s", flush=True)
                    break
                except Exception as exc:
                    print(f"batch {int(tag) + 1}/{nb} attempt {attempt} "
                          f"FAILED: {exc!r}", flush=True)
                    if attempt == 2:
                        done[tag] = {"error": repr(exc)}
                        save_state(state)
                        failed.append(int(tag) + 1)
    finally:
        srv.shutdown()

    sync_out, async_out = {}, {}
    t_sync = t_async = 0.0
    for k in range(nb):
        b = done[str(k)]
        if "error" in b:
            continue
        sync_out.update(b["sync"])
        async_out.update(b["async"])
        t_sync += b.get("t_sync", 0.0)
        t_async += b.get("t_async", 0.0)
    diffs = _diff(sync_out, async_out)

    print(f"sync  : {t_sync:.1f}s", flush=True)
    print(f"async : {t_async:.1f}s", flush=True)
    print(f"total : {t_sync + t_async:.1f}s", flush=True)
    print(f"scored: {len(sync_out)} endpoints", flush=True)
    if failed:
        print(f"FAILED batches (not scored, honest accounting): {failed}",
              flush=True)
    print(f"divergences: {len(diffs)}", flush=True)
    for p, v in list(diffs.items())[:30]:
        print(f"  {p}\n     sync ={v['sync']}\n     async={v['async']}",
              flush=True)


if __name__ == "__main__":
    main()
