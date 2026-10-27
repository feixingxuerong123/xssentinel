"""PortSwigger（Burp 官方）XSS cheat sheet 语料覆盖对照。

为什么需要这份对照
------------------
项目自有的 192 例基准是**我们自己设计的**，修复也是对着这些用例做的——
sync/async 双引擎都在它上面拿 f1=1.000。这个数字能证明"内部一致"，
证明不了"检测面够广"。要回答后者，需要一个**第三方撰写的权威向量集**做参照。

PortSwigger（Burp Suite 的厂商）公开维护的 XSS cheat sheet 就是这个参照：
由商业工具厂商撰写、业界公认为最全的 XSS 向量清单，且自带两项第三方标注：

* **是否需要用户交互**（`do-not-require` / `do-require` 两个分区）
* **适用上下文**（每条向量示例链接里的 `&context=`）

分组口径（这是这份对照的关键）
------------------------------
cheat sheet 穷举了浏览器的整个事件面，其中一大半（pointerdown / mousemove /
mouseenter …）**必须用户交互才会触发**。拿它们要求一个自动化扫描器是不公平的，
把两类混在一起算覆盖率会得出一个误导性的低数字（实测混算只有 15.4%）。

所以本脚本**分开算**，并且以 `no_interaction` 组为唯一主指标：

* `no_interaction` —— 注入即执行。扫描器理应覆盖，**这一组的覆盖率才算数**。
* `requires_interaction` —— 需要模拟交互才触发。仅作参考，不计入主指标。

对照口径（以及它不能说明什么）
------------------------------
做的是**技术面覆盖对照**，不是检出率对照：从双方语料各提取同一类"技术指纹"
（事件处理器名 / 标签名 / URI 协议），算 PortSwigger 用到的技术在
XSSentinel 语料里的出现比例。

三条局限，别拿这个数字自欺：

1. **字符串出现 ≠ 语义等价**。语料里出现 `onanimationend` 不代表我们有一条能
   真正触发它的完整载荷，更不代表扫描器会在对应上下文选中它。
2. **覆盖 ≠ 能检出**。只测"语料/检测面有没有提到这项技术"，不测端到端检出。
3. **不区分浏览器**。PortSwigger 标注了各向量的浏览器支持，本对照忽略。

用法::

    python benchmark/portswigger_corpus_coverage.py [--html PATH] [--json OUT]

`--html` 缺省读环境变量 `PORTSWIGGER_CHEATSHEET`，再缺省读本地缓存路径。
cheat sheet 需自行抓取（本仓库不内联第三方内容）::

    curl -o pw.html https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
"""

from __future__ import annotations

import argparse
import html as H
import json
import os
import re
import sys

# ---------------------------------------------------------------- 数据来源

DEFAULT_HTML = os.environ.get("PORTSWIGGER_CHEATSHEET", "")

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

# XSSentinel 侧参与对照的全部语料来源
CORPUS_FILES = [
    "xssentinel/data/payloads.json",
    "xssentinel/data/svg_xss.json",
    "xssentinel/data/framework_xss.json",
]

# cheat sheet 的分区 id（h3 id）→ 我们给的组名
GROUP_BY_ID_FRAGMENT = [
    ("do-not-require-user-interaction", "no_interaction"),
    ("do-require-user-interaction", "requires_interaction"),
]

# ---------------------------------------------------------------- 指纹提取

EVENT_RE = re.compile(r"\bon([a-z]{3,30})\s*=", re.I)
TAG_RE = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)")
PROTO_RE = re.compile(r"\b(javascript|data|vbscript|blob|filesystem)\s*:", re.I)
SECTION_RE = re.compile(r"<h3[^>]*id=\"([^\"]+)\"", re.I)

DIMENSIONS = ("events", "tags", "protocols")


def extract_vectors(html_text: str) -> list[dict]:
    """从 cheat sheet 里取出向量，并带上第三方标注的分区与上下文。

    注意剥标签的顺序：先删掉 PortSwigger 用于语法高亮的**真实**标签，再 unescape
    实体。向量本身在源码里是 `&lt;svg&gt;` 这样的转义文本，顺序反了会把向量
    自己也当成标签删掉。
    """
    marks = sorted((m.start(), m.group(1)) for m in SECTION_RE.finditer(html_text))
    out: list[dict] = []
    for m in re.finditer(r"<code[^>]*>(.*?)</code>", html_text, re.S):
        text = H.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()
        if not text or len(text) > 4000:
            continue
        pos = m.start()

        section = "unknown"
        for mark_pos, section_id in marks:
            if mark_pos < pos:
                section = section_id
            else:
                break

        group = "other"
        for fragment, name in GROUP_BY_ID_FRAGMENT:
            if fragment in section:
                group = name
                break

        # 上下文标注在向量前的示例链接里（...&context=html）。
        # 实体可能转义也可能不转义（`&amp;context=` / `&context=`），两种都认。
        window = html_text[max(0, pos - 600):pos]
        contexts = re.findall(r"[&?](?:amp;)?context=([\w-]+)", window)

        out.append(
            {
                "vector": text[:300],
                "section": section,
                "group": group,
                "context": contexts[-1] if contexts else "",
            }
        )
    return out


def fingerprint(text: str) -> dict[str, set[str]]:
    return {
        "events": {m.group(1).lower() for m in EVENT_RE.finditer(text)},
        "tags": {m.group(1).lower() for m in TAG_RE.finditer(text)},
        "protocols": {m.group(1).lower() for m in PROTO_RE.finditer(text)},
    }


def _walk_strings(node, sink: list[str]) -> None:
    if isinstance(node, str):
        sink.append(node)
        return
    if isinstance(node, dict):
        for value in node.values():
            _walk_strings(value, sink)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk_strings(item, sink)


def load_corpus_fingerprints(root: str) -> tuple[dict[str, set[str]], list[str]]:
    acc: dict[str, set[str]] = {d: set() for d in DIMENSIONS}
    loaded: list[str] = []
    for rel in CORPUS_FILES:
        path = os.path.join(root, rel)
        if not os.path.exists(path):
            print(f"[warn] 语料缺失，跳过: {rel}", file=sys.stderr)
            continue
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        strings: list[str] = []
        _walk_strings(data, strings)
        for text in strings:
            fp = fingerprint(text)
            for d in DIMENSIONS:
                acc[d] |= fp[d]
        loaded.append(rel)
    return acc, loaded


# ---------------------------------------------------------------- 对照


def compare_group(
    entries: list[dict], ours: dict[str, set[str]]
) -> dict[str, dict]:
    theirs: dict[str, set[str]] = {d: set() for d in DIMENSIONS}
    freq: dict[str, dict[str, int]] = {d: {} for d in DIMENSIONS}
    for entry in entries:
        fp = fingerprint(entry["vector"])
        for d in DIMENSIONS:
            theirs[d] |= fp[d]
            for name in fp[d]:
                freq[d][name] = freq[d].get(name, 0) + 1

    report: dict[str, dict] = {}
    for d in DIMENSIONS:
        ref = theirs[d]
        missing = ref - ours[d]
        report[d] = {
            "portswigger_total": len(ref),
            "covered": len(ref & ours[d]),
            "missing": len(missing),
            "coverage_pct": round(100.0 * len(ref & ours[d]) / len(ref), 1) if ref else None,
            "missing_top": sorted(
                ({"name": n, "uses": freq[d].get(n, 0)} for n in missing),
                key=lambda x: -x["uses"],
            )[:40],
        }
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--html", default=DEFAULT_HTML, help="cheat sheet HTML 路径")
    ap.add_argument("--json", default="", help="结果落盘路径")
    ap.add_argument("--root", default=_ROOT, help="仓库根目录")
    args = ap.parse_args()

    if not os.path.exists(args.html):
        print(
            f"[error] 找不到 cheat sheet: {args.html}\n"
            "请先抓取：curl -o pw.html "
            "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
            file=sys.stderr,
        )
        return 2

    with open(args.html, encoding="utf-8", errors="ignore") as fh:
        html_text = fh.read()

    vectors = extract_vectors(html_text)
    if not vectors:
        print("[error] 未提取到向量——页面结构可能变了，检查 <code> 提取逻辑", file=sys.stderr)
        return 2

    ours, loaded = load_corpus_fingerprints(args.root)

    groups: dict[str, list[dict]] = {}
    for entry in vectors:
        groups.setdefault(entry["group"], []).append(entry)

    report = {g: compare_group(items, ours) for g, items in groups.items()}

    out = {
        "source": {
            "provider": "PortSwigger (Burp Suite) XSS cheat sheet",
            "url": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
            "html_cache": args.html,
            "vectors_extracted": len(vectors),
            "vectors_by_group": {g: len(v) for g, v in groups.items()},
        },
        "corpus_files": loaded,
        "primary_metric": "no_interaction",
        "groups": report,
        "caveats": [
            "字符串出现 != 语义等价：语料里有该事件名不代表有能触发它的完整载荷",
            "覆盖 != 能检出：本对照不测端到端检出率",
            "忽略 PortSwigger 标注的浏览器支持差异",
        ],
    }

    print(f"PortSwigger 向量 {len(vectors)} 条 | 对照语料 {len(loaded)} 个文件")
    print("分组: " + ", ".join(f"{g}={len(v)}" for g, v in sorted(groups.items())))
    print()
    for group in sorted(groups):
        tag = " ← 主指标" if group == "no_interaction" else ""
        print(f"[{group}]{tag}  ({len(groups[group])} 条向量)")
        print(f"  {'维度':<12}{'第三方用到':>10}{'已覆盖':>8}{'缺口':>8}{'覆盖率':>9}")
        for d in DIMENSIONS:
            r = report[group][d]
            pct = "—" if r["coverage_pct"] is None else f"{r['coverage_pct']:.1f}%"
            print(
                f"  {d:<12}{r['portswigger_total']:>10}{r['covered']:>8}"
                f"{r['missing']:>8}{pct:>9}"
            )
        for d in DIMENSIONS:
            top = ", ".join(
                f"{m['name']}({m['uses']})" for m in report[group][d]["missing_top"][:10]
            )
            if top:
                print(f"    缺口 {d}: {top}")
        print()

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
        print(f"已落盘: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
