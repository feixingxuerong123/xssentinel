"""PortSwigger 语料覆盖对照的契约测试。

全部用例用内联的 mini HTML fixture，**不依赖网络、不依赖本地缓存文件**——
cheat sheet 是外部抓取物，测试不能因为它不在就失败或跳过。

锁住的契约：

1. 向量提取必须先剥真实标签、再 unescape 实体（顺序反了会把向量自己删掉）
2. 按 `<h3 id=...>` 分区正确归组（无需交互 / 需交互 / 其他）
3. `&context=` 第三方上下文标注能取到
4. 覆盖率算术正确
5. 分母为空时给 `None` 而不是 0%（0% 是在假装测过）
"""

from __future__ import annotations

import json

import pytest

from benchmark.portswigger_corpus_coverage import (
    compare_group,
    extract_vectors,
    fingerprint,
    load_corpus_fingerprints,
)

FIXTURE = """
<h3 id="event-handlers-that-do-not-require-user-interaction">No user interaction</h3>
<p>Event: Description:</p>
<a href="https://portswigger-labs.net/xss/xss.php?x=%3Csvg%3E&amp;context=html">
  <code>&lt;svg onload=alert(1)&gt;</code>
</a>
<a href="https://portswigger-labs.net/xss/xss.php?x=%3Cxmp%3E&amp;context=html">
  <code>&lt;xmp onanimationend=alert(1)&gt;</code>
</a>
<h3 id="event-handlers-that-do-require-user-interaction">User interaction required</h3>
<a href="https://portswigger-labs.net/xss/xss.php?x=%3Cxss%3E&amp;context=html">
  <code>&lt;xss onpointerdown=alert(1)&gt;</code>
</a>
<h3 id="consuming-tags">Consuming tags</h3>
<a href="https://portswigger-labs.net/xss/xss.php?x=%3Cscript%3E&amp;context=js">
  <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>
</a>
"""


def test_vectors_are_extracted_with_entities_decoded() -> None:
    """向量在源码里是 &lt;svg&gt;，提取后必须是真的 <svg ...>。"""
    got = extract_vectors(FIXTURE)
    assert len(got) == 4
    assert got[0]["vector"] == "<svg onload=alert(1)>"
    assert got[3]["vector"] == "<script>alert(1)</script>"


def test_highlight_markup_does_not_leak_into_vector() -> None:
    """PortSwigger 的语法高亮标签必须被剥掉，不混进向量文本。"""
    html = '<h3 id="consuming-tags">t</h3><code><span class="hl">&lt;b&gt;x&lt;/b&gt;</span></code>'
    got = extract_vectors(html)
    assert got[0]["vector"] == "<b>x</b>"


def test_groups_split_interaction_from_no_interaction() -> None:
    got = extract_vectors(FIXTURE)
    by_group = {}
    for entry in got:
        by_group.setdefault(entry["group"], []).append(entry["vector"])
    assert len(by_group["no_interaction"]) == 2
    assert len(by_group["requires_interaction"]) == 1
    assert len(by_group["other"]) == 1
    assert by_group["requires_interaction"][0] == "<xss onpointerdown=alert(1)>"


def test_third_party_context_annotation_is_captured() -> None:
    got = extract_vectors(FIXTURE)
    assert got[0]["context"] == "html"
    assert got[3]["context"] == "js"


def test_fingerprint_extracts_events_tags_protocols() -> None:
    fp = fingerprint('<svg onload=alert(1)><a href="javascript:x">')
    assert fp["events"] == {"load"}
    assert "svg" in fp["tags"] and "a" in fp["tags"]
    assert fp["protocols"] == {"javascript"}


def test_coverage_math_and_missing_list() -> None:
    ours = {
        "events": {"load"},
        "tags": {"svg", "xmp"},
        "protocols": {"javascript"},
    }
    entries = [e for e in extract_vectors(FIXTURE) if e["group"] == "no_interaction"]
    report = compare_group(entries, ours)

    ev = report["events"]
    assert ev["portswigger_total"] == 2
    assert ev["covered"] == 1
    assert ev["missing"] == 1
    assert ev["coverage_pct"] == 50.0
    assert [m["name"] for m in ev["missing_top"]] == ["animationend"]

    # 语料里两条标签都有 → 全覆盖
    assert report["tags"]["coverage_pct"] == 100.0


def test_empty_dimension_reports_none_not_zero() -> None:
    """一个维度没有任何第三方用法时，覆盖率是 None，不是 0%。

    0% 会让人以为测过并且很差；None 才能表达"这个维度没有可比样本"。
    """
    ours = {"events": set(), "tags": set(), "protocols": set()}
    entries = [{"vector": "plain text with no markup", "group": "other", "context": ""}]
    report = compare_group(entries, ours)
    for dim in ("events", "tags", "protocols"):
        assert report[dim]["portswigger_total"] == 0
        assert report[dim]["coverage_pct"] is None


def test_missing_corpus_files_warn_instead_of_crash(tmp_path, capsys) -> None:
    """语料文件缺失时返回空指纹并告警，不抛异常——对照脚本不该因为
    仓库布局变化而炸掉。"""
    ours, loaded = load_corpus_fingerprints(str(tmp_path))
    assert loaded == []
    assert ours == {"events": set(), "tags": set(), "protocols": set()}


def test_corpus_json_strings_are_walked_recursively(tmp_path) -> None:
    """语料 JSON 结构不统一（list / dict / 嵌套），必须递归取到所有字符串。"""
    (tmp_path / "xssentinel").mkdir()
    (tmp_path / "xssentinel" / "data").mkdir()
    payload = {
        "_meta": {"note": "ignore"},
        "payloads": ["<svg onload=alert(1)>", {"nested": "<math onfocusin=alert(1)>"}],
        "polyglots": ["javascript:alert(1)"],
    }
    with open(tmp_path / "xssentinel" / "data" / "payloads.json", "w", encoding="utf-8") as fh:
        json.dump(payload, fh)

    ours, loaded = load_corpus_fingerprints(str(tmp_path))
    assert loaded == ["xssentinel/data/payloads.json"]
    assert {"load", "focusin"} <= ours["events"]
    assert "svg" in ours["tags"] and "math" in ours["tags"]
    assert "javascript" in ours["protocols"]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
