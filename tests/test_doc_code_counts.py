# -*- coding: utf-8 -*-
"""README 引用的「代码派生计数」必须与代码本体同步。

背景(2026-11-01 外部评审):test_quick_gate_slice 的文档数字闸只覆盖切片/矩阵类
数字;README 的 REGISTRY 家族数(自称 23,实测 28)在多个 Phase 里无人看守地腐烂。
本文件把这一族数字也钉住:README(中/英)写的家族计数必须等于 len(REGISTRY),
历史烂账表述不得回潮。能力清单条数随 Phase 持续增长,已改为去数字化表述
(没有数字就没有数字可腐烂),不在本闸管辖。
"""
import os

from xssentinel.core.transform import REGISTRY

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 曾在某时点为真、随后腐烂的计数表述。再出现即意味着文档与代码又一次脱节;
# 修文档,不要把字符串加回这里。
_STALE_COUNT_CLAIMS = ("23 种", "23 transform", "36 项", "36-item")

_GUARDED_DOCS = ("README.md", "README.en.md", os.path.join("docs", "QUICKSTART.md"))


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def test_readme_waf_family_count_matches_registry():
    n = len(REGISTRY)
    texts = {rel: _read(rel) for rel in _GUARDED_DOCS}
    assert f"**{n} 个**变形/编码家族" in texts["README.md"], (
        "README 的 WAF 变形家族计数与 core/transform.py REGISTRY 不同步: "
        f"代码实有 {n} 个而 README 未写。改 README,或同步更新本测试并在提交"
        "信息里写明理由。")
    assert f"{n} transform/encoding families" in texts["README.en.md"], (
        f"README.en 的 WAF 变形家族计数与 REGISTRY 不同步(代码实有 {n} 个)。")
    for rel, text in texts.items():
        for stale in _STALE_COUNT_CLAIMS:
            assert stale not in text, f"{rel} 回潮旧计数表述: {stale!r}"
