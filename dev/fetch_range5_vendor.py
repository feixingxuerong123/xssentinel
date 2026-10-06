#!/usr/bin/env python3
"""Vendor the Lit release bundles into range5/vendor/ (no build step, offline-runnable).

Why Lit first for range5: it is the only one of the three remaining frameworks
(angular / svelte / lit) that ships a browser-ready ES module with no compile
step.  Svelte's npm package is a *compiler* (no runtime bundle to vendor) and
Angular needs TypeScript + AOT, so both need a toolchain that this range would
then have to ship too.  Lit also has the exact sink this range is about:
`unsafeHTML` -- the analogue of React's dangerouslySetInnerHTML and Vue's
v-html -- whose safe twin is a plain `${expr}` interpolation, which Lit renders
as a text node.

Bundles come from registry.npmjs.org tarballs (unpkg is unreachable from this
host).  Only .js / .js.map-free files are kept; the README records the exact
versions so a re-run is reproducible.

STATUS: ``range5/`` DOES NOT EXIST YET.  This script is the vendoring half
of an unstarted range (the Lit ``unsafeHTML`` family, the analogue of
range4's React ``dangerouslySetInnerHTML`` / Vue ``v-html``), kept here so
the vendor fetch is reproducible instead of re-derived later.  Running it
now creates ``range5/vendor/`` for a target that has no pages, no ground
truth and no runner -- harmless, but it does not make the range runnable.
It lives in ``dev/`` rather than under the ``_``-prefix convention because,
unlike the probes, it is meant to be kept and re-run.
"""
from __future__ import annotations

import io
import json
import pathlib
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "range5" / "vendor"

# npm name -> directory under vendor/
PKGS = {
    "lit": "lit",
    "lit-html": "lit-html",
    "lit-element": "lit-element",
    "@lit/reactive-element": "reactive-element",
}

TIMEOUT = 60


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
        return r.read()


def main() -> int:
    VENDOR.mkdir(parents=True, exist_ok=True)
    recorded = []
    for npm_name, dst in PKGS.items():
        try:
            meta = json.loads(fetch(f"https://registry.npmjs.org/{npm_name}").decode())
        except Exception as exc:  # network on this host is day-to-day
            print(f"FAIL {npm_name}: {exc}")
            return 1
        version = meta["dist-tags"]["latest"]
        tarball = meta["versions"][version]["dist"]["tarball"]
        try:
            raw = fetch(tarball)
        except Exception as exc:
            print(f"FAIL {npm_name} tarball: {exc}")
            return 1

        out = VENDOR / dst
        if out.exists():
            for p in out.rglob("*"):
                p.unlink()
        out.mkdir(parents=True, exist_ok=True)

        kept = 0
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                name = member.name.split("/", 1)[1]  # strip "package/"
                if not (name.endswith(".js") or name == "package.json"):
                    continue
                if "/development/" in name or name.startswith("development/"):
                    continue  # dev builds, not needed
                (out / name).parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(member) as src:
                    (out / name).write_bytes(src.read())
                kept += 1
        size = sum(p.stat().st_size for p in out.rglob("*"))
        print(f"  {npm_name:<24} {version:<10} -> vendor/{dst}/ ({kept} files, {size//1024} KB)")
        recorded.append((npm_name, version, dst, kept))

    lines = ["# range5 vendored framework bundles", "",
             "Upstream release tarballs pulled from `registry.npmjs.org` (unpkg is",
             "unreachable from the author's host).  Vendored so the range runs",
             "offline and in CI without a package manager.",
             "", "Fetched by `dev/fetch_range5_vendor.py`.", "",
             "| npm package | version | directory | files |", "|---|---|---|---|"]
    for name, version, dst, kept in recorded:
        lines.append(f"| `{name}` | {version} | `vendor/{dst}/` | {kept} |")
    (VENDOR / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {VENDOR / 'README.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
