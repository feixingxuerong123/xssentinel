"""Phase 185: 最小复现 —— DOMParser 链各形状的钩子是否命中。

用 about:blank 直接注入 _init_script 再跑形状，绕开 HTTP 服务器与探针投递，
所以"没命中"只可能是钩子本身的问题，不会是探针没把 marker 送到位。

注：Playwright 的 page.evaluate 自身走 eval，而脚本源码里带 MARKER，所以每次
都会有一条 `eval` 命中——那是实验装置的噪声，真实扫描里 marker 由 location.hash
投递，不会出现。判定时只关心 Node.*/Element.*/CharacterData.* 这些插入点。
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, r"D:\qoder\xssentinel")

from playwright.sync_api import sync_playwright  # noqa: E402

from xssentinel.core.dom_engine import _init_script  # noqa: E402

MARKER = "XSSP185MARK"
NOISE = "eval"      # page.evaluate 自带，见 docstring

SHAPES = {
    "importNode + appendChild":
        "document.body.appendChild(document.importNode(d.body, true));",
    "adoptNode + appendChild":
        "document.body.appendChild(document.adoptNode(d.body));",
    "adoptNode(firstChild) + appendChild":
        "document.body.appendChild(document.adoptNode(d.body.firstChild));",
    "importNode + insertBefore":
        "document.body.insertBefore(document.importNode(d.body, true),"
        " document.body.firstChild);",
    "appendChild(createTextNode) [must be silent]":
        "document.body.appendChild(document.createTextNode('%s'));" % MARKER,
}


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("about:blank")
        page.evaluate(_init_script(MARKER))

        diag = page.evaluate("""() => ({
            adopt: String(Document.prototype.adoptNode),
            imp: String(Document.prototype.importNode),
            appendChild: String(Node.prototype.appendChild),
        })""")
        print("--- 钩子是否装上了 ---")
        for k, v in diag.items():
            print(f"  {k:<12} wrapped={'__tainted' in v or 'taintedHit' in v} "
                  f"native={'native code' in v}")

        print("\n--- 形状 ---")
        for name, tail in SHAPES.items():
            page.evaluate("window.__xss_dom_hits = []; window.__err = '';")
            js = (
                "() => { try { var d = new DOMParser().parseFromString('%s',"
                " 'text/html'); %s } catch(e) { window.__err = String(e); } }"
                % (MARKER, tail)
            )
            page.evaluate(js)
            hits = page.evaluate("window.__xss_dom_hits || []")
            err = page.evaluate("window.__err || ''")
            real = [h["sink"] for h in hits if h["sink"] != NOISE]
            print(f"{'HIT ' if real else 'MISS'} {name:<42} "
                  f"{json.dumps(real, ensure_ascii=False)}"
                  f"{'  err=' + err if err else ''}")
        browser.close()


if __name__ == "__main__":
    main()
