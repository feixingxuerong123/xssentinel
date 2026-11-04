# -*- coding: utf-8 -*-
"""中英 README 与 CHANGELOG 的「全量分批门禁口径」必须同源。

背景(2026-11-04, OPTIMIZATION.md §7 item 4):Phase 346 的 ``258/258`` +
``75 skip / 10 文件`` 是当时真实的门禁结果,1.4.0 轮已换成 ``274/274 有效绿``
+ ``69 skip / 18 文件``。两版 README 仍以「最近一次 / latest run」的现在时
引旧数字,而 ``test_quick_gate_slice.py`` 只钉矩阵/切片数字,没有守卫看门禁
口径;外部评审 2026-11-01 也只修过 EN 的一处实错,没有建立检查单。

判据收窄到「两边都认」:每个事实给中/英两个精确短语,要求中文短语只在中文
文档里找、英文短语只在英文文档里找。少一边、只改一边、或把口径表删空,
都必须红。AGENTS.md 是运行时证据的权威记录,守卫也核对它 —— 否则只改
README 就能骗过这道门。CHANGELOG 的 1.4.0 条目另按「绿必须同时报跳过数」
单独钉住。

带日期的历史记录(CHANGELOG 旧版本段、dev/PHASE346_log.md、docs/archive/、
_review_20261101/)不是现在时表述,不受本闸管辖,禁止为过闸去改它们。
"""
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ZH = "README.md"
_EN = "README.en.md"
_CHANGELOG = "CHANGELOG.md"
_EVIDENCE = "AGENTS.md"

# (事实标识, 中文精确短语, 英文精确短语)。改门禁口径时四个文件一起改,
# 并同步本表;不要为了让门变绿而删条目 —— 条数由下面的断言钉住。
_GATE_FACTS = (
    ("274/274", "**274/274 文件有效绿**", "**274/274 files effectively green**"),
    ("271 in-gate", "**271 文件 in-gate 绿", "271 in-gate green"),
    ("3 standalone", "3 个环境超时文件单跑复绿",
     "3 environment-timeout files green on standalone rerun"),
    ("69 skips", "**skip 69 例 / 18 文件", "**69 skips across 18 files"),
    ("5 whole files", "5 个整文件零贡献", "5 whole files contributed nothing"),
    ("1412s", "1412s", "1412 s"),
)

# 曾经为真、随后腐烂的现在时口径。再出现即意味着文档与证据又一次脱节:
# 修文档,不要把字符串加回允许列表。
_STALE_LIVE_CLAIMS = (
    "258/258",
    "75 skips / 10 files",
    "skip 75 例 / 10 文件",
)


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_gate_figures_present_in_both_readmes():
    """「两边都认」:同一事实必须同时出现在中英两版,少一边即失败。"""
    assert len(_GATE_FACTS) == 6, "口径表被删空,这道守卫会退化成永绿的空断言"
    zh, en = _read(_ZH), _read(_EN)
    for key, zh_phrase, en_phrase in _GATE_FACTS:
        assert zh_phrase in zh, f"README.md 缺门禁口径 {key}: {zh_phrase!r}"
        assert en_phrase in en, f"README.en.md 缺门禁口径 {key}: {en_phrase!r}"


def test_gate_figures_agree_with_runtime_evidence():
    """只改 README 不改 AGENTS.md(或反过来)都要红。"""
    evidence = _read(_EVIDENCE)
    for needle in (
        "271/274 文件 in-gate 绿",
        "skip 69 个 / 18 文件",
        "274/274 文件绿",
        "1412s",
    ):
        assert needle in evidence, (
            f"AGENTS.md 的运行时证据口径与 README 不同步: {needle!r}")


def test_changelog_reports_skips_next_to_the_green_count():
    """「绿」和「跑过」是两个词:1.4.0 的全绿声明必须带跳过数。"""
    text = _read(_CHANGELOG)
    section = text.split("## [1.4.0]", 1)[1].split("### Added", 1)[0]
    assert "274 文件有效绿" in section, "CHANGELOG 1.4.0 缺当前门禁结论"
    assert "skip 69 例 / 18 文件" in section, "CHANGELOG 1.4.0 报了绿却没报 skip"


def test_stale_gate_figures_absent_from_live_docs():
    """旧口径不许以现在时回潮;带日期的历史记录不在此列。"""
    for rel in (_ZH, _EN):
        text = _read(rel)
        for stale in _STALE_LIVE_CLAIMS:
            assert stale not in text, (
                f"{rel} 又用现在时引用旧门禁口径: {stale!r}")


def test_changelog_latest_version_matches_package_version():
    """版本号是同一契约的两处手写:发版时只改一处就会悄悄脱节。

    `pyproject.toml` 用 attr 动态读 `__version__`,所以包元数据不会说谎;
    会说谎的是 CHANGELOG 的章节标题。禁词表那一族门管「旧口径回潮」,
    这一族管「当前版本」,两者不互相替代。
    """
    import re

    from xssentinel import __version__

    changelog = _read(_CHANGELOG)
    assert "## [Unreleased]" in changelog, "发版后必须保留空的 Unreleased 段"
    released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", changelog, flags=re.M)
    assert released, "CHANGELOG 找不到已发布版本标题"
    assert released[0] == __version__, (
        f"CHANGELOG 最新版本 {released[0]} 与 xssentinel.__version__ "
        f"{__version__} 不同步:发版时两处要一起改")
