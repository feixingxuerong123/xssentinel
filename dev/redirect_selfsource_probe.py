r"""Phase 210b: does the redirect-sink fix kill the FP without killing the TP?

Measured, not assumed.  The claim under test is that
``USER_INPUT_RE``'s ``window.location`` alternative matched the sink's own
qualifier, so a hardcoded ``window.location.replace(host + '/profile')``
inside the target's bundle was reported as an open redirect "fed by user
input".

Both arms run over the SAME bytes:
  * arm CUR  = the working tree (masking in place)
  * arm HEAD = `git show HEAD:...redirect_xss.py`, i.e. the shipped code

Every sink HEAD reports and CUR drops is PRINTED with its snippet.  A drop
we cannot read as "hardcoded destination" is a regression, not a fix -- the
printout is the attribution, not the count.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from pin_repo import pin  # noqa: E402
pin()

REPO = os.path.dirname(HERE)
# forward slashes: this string goes into `git show HEAD:<path>`, and
# os.path.join would emit backslashes that git then reads as escapes
MODPATH = "xssentinel/core/redirect_xss.py"

BUNDLE = os.path.join(HERE, "_juiceshop", "app", "juice-shop_20.2.0",
                      "frontend", "dist", "frontend")

#: A DOM-based redirect that really is attacker-fed.  Must survive both arms.
TRUE_POSITIVE = (
    "<script>document.addEventListener('DOMContentLoaded',function(){"
    "var p=new URLSearchParams(location.search);"
    "location.replace(p.get('next'));});</script>")


def _load(name: str, source: str):
    path = os.path.join(tempfile.gettempdir(), f"_xs_{name}.py")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(source)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _head_source() -> str:
    out = subprocess.run(["git", "show", f"HEAD:{MODPATH}"], cwd=REPO,
                         capture_output=True)
    if out.returncode != 0:
        raise SystemExit("git show failed: " + out.stderr.decode("utf-8", "replace"))
    return out.stdout.decode("utf-8")


def _report(mod, label: str, sources: dict) -> dict:
    res = {}
    for name, src in sources.items():
        hits = [s for s in mod.find_redirect_sinks(src) if s["exploitable"]]
        res[name] = hits
    total = sum(len(v) for v in res.values())
    print(f"[{label}] exploitable redirect sinks: {total}")
    for name, hits in res.items():
        for h in hits:
            print(f"    {name}: {h['sink']} :: {h['snippet'][:160]}")
    return res


def main() -> int:
    # Bundle bytes contain characters this console's default codec (GBK)
    # cannot encode; a probe that dies on its own printout is worse than no
    # probe -- it reads as "no findings".
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cur = __import__("xssentinel.core.redirect_xss", fromlist=["x"])
    head = _load("_rx_head", _head_source())

    sources = {}
    for root, _dirs, files in os.walk(BUNDLE):
        for f in files:
            if f.endswith(".js"):
                p = os.path.join(root, f)
                try:
                    if os.path.getsize(p) > 12 * 1024 * 1024:
                        continue
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        sources[os.path.relpath(p, BUNDLE)] = fh.read()
                except OSError:
                    pass
    sources["TRUE_POSITIVE_FIXTURE"] = TRUE_POSITIVE
    print(f"scanning {len(sources)} JS documents")

    a = _report(cur, "CURRENT ", sources)
    b = _report(head, "HEAD    ", sources)

    # Compare by COUNT per document: the judged window is narrower now, so
    # the same true positive prints with a shorter snippet.  Matching on the
    # snippet text would report that as "a new finding".
    dropped = {k: len(b[k]) - len(a.get(k, [])) for k in b
               if len(b[k]) > len(a.get(k, []))}
    added = {k: len(a[k]) - len(b.get(k, [])) for k in a
             if len(a[k]) > len(b.get(k, []))}
    print("\n--- findings the fix removes (each must be a hardcoded "
          "destination) ---")
    for k, n in dropped.items():
        print(f"  {k}: -{n}")
        for h in b[k][len(a.get(k, [])):]:
            print(f"     {h['sink']}\n     {h['snippet'][:400]}")
    print("\n--- findings only CURRENT reports (must be empty) ---")
    for k, n in added.items():
        for h in a[k][len(b.get(k, [])):]:
            print(f"  {k}: {h['sink']} :: {h['snippet'][:200]}")

    tp_cur = [h for h in a.get("TRUE_POSITIVE_FIXTURE", [])]
    tp_head = [h for h in b.get("TRUE_POSITIVE_FIXTURE", [])]
    bundle_cur = sum(len(v) for k, v in a.items()
                     if k != "TRUE_POSITIVE_FIXTURE")
    print(f"\nfixture TP kept: current={len(tp_cur)} head={len(tp_head)}")
    print(f"findings on the real bundle: current={bundle_cur}")
    if not tp_cur:
        print("FAIL: the fix silenced a real attacker-fed location.replace()")
        return 1
    if added:
        print("FAIL: the fix introduced new findings")
        return 1
    if not dropped:
        print("FAIL: nothing changed -- the mask is not reaching the bundle "
              "shape it claims to reach")
        return 1
    if bundle_cur:
        print(f"FAIL: {bundle_cur} bundle finding(s) still reported")
        return 1
    print("OK: FP class removed from the real bundle, TP retained, "
          "no new findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
