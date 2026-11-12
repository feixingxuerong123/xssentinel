# -*- coding: utf-8 -*-
"""Gitignored runtime data must not be swept into a wheel by ``data/*.json``.

Background (2026-11-12, delivery gate): a wheel built from a clean copy of
this tree contained ``xssentinel/data/llm_state.json`` -- a file gitignored
on purpose because it is process-local runtime state (provider failure
counters).  The same wildcard would ship ``llm_providers.json``, which holds
API keys.  ``.gitignore`` has NO effect on ``package-data``.

The guard pins the two lists together instead of trusting a hand-written
allowlist: every ``xssentinel/data/*.json`` path ignored by git must appear
in ``exclude-package-data``, and the exclusion list must contain nothing
else -- so deleting a gitignore rule, or silently adding an exemption, fails.
The wildcard itself is asserted too: without it this file would guard nothing.

The real wheel contents are measured separately at delivery time (uv build +
unzip -l); this test is the cheap, every-run ratchet on the configuration.
"""
import os
import re

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _gitignored_data_files():
    out = set()
    for line in _read(".gitignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^xssentinel/data/([^/\s]+\.json)$", line)
        if match:
            out.add("data/" + match.group(1))
    return out


def _exclusion_patterns():
    text = _read("pyproject.toml")
    match = re.search(
        r"^\[tool\.setuptools\.exclude-package-data\]\s*$\n(.*?)(?=^\[|\Z)",
        text, re.M | re.S)
    assert match, (
        "pyproject.toml 缺 [tool.setuptools.exclude-package-data]:"
        "打包排除清单不见了,这道守卫必须响亮地红")
    return set(re.findall(r'"([^"]+\.json)"', match.group(1)))


def test_wildcard_package_data_is_still_present():
    """没有通配就不需要排除;守卫必须跟着被测物的形状一起活着。"""
    text = _read("pyproject.toml")
    assert re.search(
        r'^\s*xssentinel\s*=\s*\[[^\]]*"data/\*\.json"',
        text, re.M), (
        "package-data 不再通配 data/*.json —— 若改用显式白名单,请同步"
        "重写本守卫并在提交信息里写明理由,别留一个永绿的空断言")


def test_every_gitignored_data_file_is_excluded():
    """单向漂移与集合增删都要红:两个清单必须逐项相等。"""
    ignored = _gitignored_data_files()
    assert ignored, (
        ".gitignore 里没有 xssentinel/data/*.json 规则 —— 集合空了,"
        "这道守卫会退化成永绿")
    excluded = _exclusion_patterns()
    missing = ignored - excluded
    assert not missing, (
        f"这些被 git 忽略的运行期文件仍会被 data/*.json 打进 wheel: "
        f"{sorted(missing)}")
    assert excluded == ignored, (
        f"打包排除清单与 .gitignore 不同源: excluded={sorted(excluded)} "
        f"vs ignored={sorted(ignored)}(多余项可能是私自开的豁免口)")


def test_the_two_runtime_files_are_named_explicitly():
    """凭信念列名单之外,再钉一次两个真正带状态/密钥的名字。"""
    excluded = _exclusion_patterns()
    assert {
        "data/llm_state.json",
        "data/llm_providers.json",
    } <= excluded, "运行期状态或 provider 密钥配置没有显式排除"
