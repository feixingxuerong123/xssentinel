# -*- coding: utf-8 -*-
"""dependency-audit 门不能被缩窄,工具链漏洞不能被豁免。

背景(2026-11-04, run 41817920644):手动 dispatch 让 `dependency-audit` 第一次
真实变红 —— runner 预装的 setuptools 79.0.1 触发 CVE-2026-59890 /
GHSA-xmj3-9gf7-h52w 共 3 条告警,两次重试都报同样的结果(不是 OSV 传输抖动)。
修法是**升级工具链**(`pip install -U "setuptools>=84.1.0"`),不是给 pip-audit
加 `--ignore-vuln` 或把 runner 预装包排除出审计面 —— 后者等于引入豁免名单、
缩窄门,下一次工具链真出漏洞会被藏起来(与 Phase 207「不引入豁免名单」同族)。

判据收窄到「两边都认」:workflow 与 docs/DEPENDENCY_AUDIT.md 必须写同一个版本
下限;升级命令必须是 install 步骤的最后一条(否则 pip-audit 看到的不是最终
环境);审计命令原样保留、不含任何缩窄开关;job 仍只在 schedule/dispatch 跑。
守卫自身的豁免开关集合条数被钉住,删条目不能悄悄过闸。
"""
import os

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORKFLOW = os.path.join(".github", "workflows", "ci.yml")
_DOC = os.path.join("docs", "DEPENDENCY_AUDIT.md")

_MIN = "setuptools>=84.1.0"
_UPGRADE = 'pip install -U "setuptools>=84.1.0"'
_AUDIT_CMD = "python -m pip_audit --format json -o pip-audit.json"
_NARROWING_FLAGS = ("--ignore-vuln", "--disable-pip", "--no-deps",
                    "--require-hashes")


def _text(rel):
    with open(os.path.join(_ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _workflow():
    # BaseLoader keeps `on` a string and every `if:` as a plain string.
    return yaml.load(_text(_WORKFLOW), Loader=yaml.BaseLoader)


def _job():
    return _workflow()["jobs"]["dependency-audit"]


def test_guard_flag_set_is_pinned():
    """删掉一个豁免开关,守卫会退化成看得见却咬不到的门。"""
    assert len(_NARROWING_FLAGS) == 4, "豁免开关集合被改动,重新审视守卫"


def test_upgrade_is_the_last_install_command():
    steps = _job()["steps"]
    installs = [s for s in steps
                if "pip install pip-audit" in str(s.get("run", ""))]
    assert len(installs) == 1, "dependency-audit 必须保留单一 install 步骤"
    lines = [line.strip() for line in installs[0]["run"].splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert _UPGRADE in lines, "install 步骤缺少 setuptools 升级命令"
    assert lines[-1] == _UPGRADE, (
        "升级必须是最后一条命令,否则 pip-audit 审的不是最终环境")


def test_minimum_version_is_shared_with_the_doc():
    assert _MIN in _text(_WORKFLOW), "workflow 的版本下限与守卫不同步"
    assert _MIN in _text(_DOC), "DEPENDENCY_AUDIT.md 缺少同一版本下限"
    assert "2026-11-04" in _text(_DOC), "文档未记录本次发现与处置"


def test_audit_command_is_not_narrowed():
    steps = _job()["steps"]
    audits = [s for s in steps
              if "python -m pip_audit" in str(s.get("run", ""))]
    assert len(audits) == 1, "审计命令步骤必须恰好一个"
    run = audits[0]["run"]
    assert _AUDIT_CMD in run, "pip_audit 调用方式被改动"
    for flag in _NARROWING_FLAGS:
        assert flag not in run, f"审计门被缩窄: 出现豁免开关 {flag!r}"


def test_audit_job_still_runs_on_schedule_and_dispatch():
    cond = _job().get("if", "")
    assert "github.event_name == 'schedule'" in cond
    assert "github.event_name == 'workflow_dispatch'" in cond
