#!/usr/bin/env python3
"""Vendor the DOMPurify builds into range6/vendor/ (reproducible re-fetch).

Why these two versions:

  * ``2.0.7`` -- last release before 2.0.8, inside CVE-2020-26870's range.
    The namespace-confusion mXSS PoC produces a real dialog through this
    build in Chromium (measured: dev/_r6_mxss_premise.py).
  * ``3.4.17`` -- the vendor's current release at vendoring time; every
    published advisory in core/sanitizer_bypass.py's table is closed by
    3.4.16, and the identical PoC is stripped (same probe).

Tarballs come from registry.npmjs.org (unpkg is unreachable from this
host).  Only ``dist/purify.min.js`` is kept -- the range's consumer is a
browser.  Each version directory gets an ``integrity.txt`` carrying the
tarball URL and the sha512 of the exact bytes fetched, so a silent
upstream swap is detectable and a re-run is reproducible.

Lives in dev/ rather than under the ``_``-prefix convention: like
fetch_range5_vendor.py, it is meant to be kept and re-run.
"""
from __future__ import annotations

import hashlib
import io
import pathlib
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "range6" / "vendor" / "dompurify"

VERSIONS = ("2.0.7", "3.4.17")
TIMEOUT = 60


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        return r.read()


def main() -> int:
    for ver in VERSIONS:
        url = f"https://registry.npmjs.org/dompurify/-/dompurify-{ver}.tgz"
        blob = fetch(url)
        out = VENDOR / ver
        out.mkdir(parents=True, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            member = tf.extractfile("package/dist/purify.min.js")
            assert member is not None, f"purify.min.js missing in {ver}"
            data = member.read()
        (out / "purify.min.js").write_bytes(data)
        (out / "integrity.txt").write_text(
            f"dompurify@{ver}\ntarball: {url}\n"
            f"sha512: {hashlib.sha512(blob).hexdigest()}\n",
            encoding="utf-8")
        print(f"{ver}: purify.min.js {len(data)} bytes -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
