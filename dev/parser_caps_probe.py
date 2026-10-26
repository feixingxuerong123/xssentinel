# -*- coding: utf-8 -*-
"""Probe: parser resource limits on hostile responses (Phase 328 follow-up).

Measures the two paths the scanner actually uses on untrusted bytes:

* BeautifulSoup -> lxml (``parser_utils.bs_parser``) on deep nesting,
  attribute amplification and entity-heavy HTML;
* stdlib ``xml.etree.ElementTree`` on a billion-laughs sitemap, in a child
  process with a wall-clock and RSS ceiling so the probe cannot take the
  machine down with it.

Run: python dev/parser_caps_probe.py

Phase 328b: the sitemap cases now come back empty in ~0.0s; before the
guard, ``billion_laughs_7`` (585 bytes) was killed at a 720 MB RSS cap.
"""
from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import psutil                                       # noqa: E402
from bs4 import BeautifulSoup                       # noqa: E402

from xssentinel.core.parser_utils import bs_parser  # noqa: E402


def _rss() -> int:
    return psutil.Process().memory_info().rss


def measure_html(label: str, html: str) -> dict:
    parser = bs_parser()
    gc.collect()
    before = _rss()
    started = time.perf_counter()
    err = None
    count = None
    try:
        soup = BeautifulSoup(html, parser)
        count = len(soup.find_all(True))
    except BaseException as e:                      # noqa: BLE001 -- measured
        err = f"{type(e).__name__}: {e}"
    elapsed = time.perf_counter() - started
    return {"case": label, "parser": parser, "bytes": len(html),
            "elements": count, "seconds": round(elapsed, 3),
            "rss_delta_mb": round((_rss() - before) / 1048576, 1),
            "error": err}


def _laughs(levels: int) -> str:
    parts = ['<!DOCTYPE lolz [', '<!ENTITY lol "lol">']
    prev = "lol"
    for i in range(1, levels + 1):
        parts.append(f'<!ENTITY lol{i} "{("&" + prev + ";") * 10}">')
        prev = f"lol{i}"
    parts.append("]>")
    return "".join(parts) + f"<lolz>&{prev};</lolz>"


CHILD = r"""
import os, sys, time, json
sys.path.insert(0, %(root)r)
import psutil
from xssentinel.core.sitemap_import import _iter_locs
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
before = psutil.Process().memory_info().rss
t = time.perf_counter()
try:
    urls, is_index = _iter_locs(text)
    err = None
    detail = [len(urls), is_index]
except BaseException as e:
    err = type(e).__name__ + ": " + str(e)[:200]
    detail = None
print(json.dumps({"seconds": round(time.perf_counter() - t, 3),
                  "rss_delta_mb": round((psutil.Process().memory_info().rss
                                         - before) / 1048576, 1),
                  "detail": detail, "error": err}))
"""


def measure_xml(label: str, levels: int, timeout: float = 12.0,
                rss_cap_mb: int = 700) -> dict:
    payload = _laughs(levels)
    fd, path = tempfile.mkstemp(suffix=".xml", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
        proc = subprocess.Popen(
            [sys.executable, "-c", CHILD % {"root": ROOT}, path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace")
        peak = 0
        started = time.perf_counter()
        killed = None
        sample = psutil.Process(proc.pid)
        while proc.poll() is None:
            try:
                peak = max(peak, sample.memory_info().rss)
            except psutil.Error:
                pass
            if peak > rss_cap_mb * 1048576:
                proc.kill()
                killed = "rss_cap"
                break
            if time.perf_counter() - started > timeout:
                proc.kill()
                killed = "timeout"
                break
            time.sleep(0.05)
        out, err = proc.communicate(timeout=5)
        parsed = None
        if out.strip():
            try:
                parsed = json.loads(out.strip().splitlines()[-1])
            except json.JSONDecodeError:
                parsed = {"raw": out.strip()[:200]}
        return {"case": label, "payload_bytes": len(payload),
                "levels": levels, "killed": killed,
                "peak_rss_mb": round(peak / 1048576, 1),
                "child": parsed, "stderr": (err or "")[:200]}
    finally:
        os.unlink(path)


def main() -> int:
    rows = []
    rows.append(measure_html("baseline", "<html><body><div>MARK</div></body></html>"))
    for n in (2_000, 20_000, 100_000):
        rows.append(measure_html(f"nested_div_{n}", "<div>" * n + "MARK" + "</div>" * n))
    for n in (1_000, 20_000):
        attrs = " ".join(f'a{i}="v{i}"' for i in range(n))
        rows.append(measure_html(f"attrs_{n}", f"<div {attrs}>MARK</div>"))
    rows.append(measure_html("entities_2m", "&amp;" * 2_000_000 + "MARK"))
    for levels in (5, 6, 7):
        rows.append(measure_xml(f"billion_laughs_{levels}", levels))
    print(json.dumps(rows, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
