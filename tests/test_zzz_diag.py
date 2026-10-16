"""TEMPORARY diagnostic: inspect asyncio state after test_benchmark_fp."""
import asyncio
import sys


def test_zzz_diag():
    try:
        loop = asyncio.get_running_loop()
        print(f"\n  RUNNING: {loop!r}")
        print(f"  is_running={loop.is_running()} is_closed={loop.is_closed()}")
        print(f"  _thread_id={getattr(loop, '_thread_id', None)}")
        print(f"  current thread={threading_ident()}")
    except RuntimeError as e:
        print(f"\n  NO running loop: {e}")
        loop = None

    print(f"  sys.modules has asyncio: {'asyncio' in sys.modules}")
    pol = asyncio.get_event_loop_policy()
    print(f"  policy={pol!r}")
    try:
        cur = pol.get_event_loop()
        print(f"  policy.get_event_loop()={cur!r} closed={cur.is_closed()}"
              f" running={cur.is_running()}")
    except Exception as e:
        print(f"  policy.get_event_loop() raised {type(e).__name__}: {e}")
    assert True


def threading_ident():
    import threading
    return threading.get_ident()
