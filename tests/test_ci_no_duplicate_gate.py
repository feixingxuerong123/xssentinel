# -*- coding: utf-8 -*-
"""每次 CI run,全量文件门禁只能由一个 job 跑一次。

背景(2026-11-04, OPTIMIZATION.md §7 item 2 方案①):`tests` job 没有 job 级
`if:`,`nightly-gate` 只在 schedule/workflow_dispatch 跑,而两者主步骤**都是**
`python tests/run_all_batched.py --quiet`。于是每次 schedule/dispatch run 同一个
全量门禁跑两遍 —— CI #18(`41424021886`)同 run 实测 `tests` 45m36s +
`nightly-gate` 29m38s,总墙钟 45m40s。方案①让 `tests` 在 schedule/dispatch
让位,由 150min ceiling 的 `nightly-gate` 独跑,`tests` 保留 ruff。

判据收窄到「两边都认」,并覆盖守卫自身的空转形状:
  * 门禁入口的 job 集合被钉死 —— 新增第三个入口或删掉一个都红;
  * 两个 `if` 与期望字符串精确相等,再对四种触发事件求值,XOR 必须恒为 1;
  * 求值器自己带硬编码真值表,写反了会红(不然互补断言可能是假绿);
  * `on` 的触发集合被钉死 —— 新增触发方式时必须回来重新评估分工;
  * `tests` 的失败证据步骤必须带同样的事件排除条件(两个 job 的 artifact
    同名 `regression-logs`,不能在同一 run 里抢)。
不认识的条件原子直接 raise,绝不静默返回 False —— 匹配不到东西的门比没有门
更危险(Phase 222 / 归档「守卫空转的五种失效形状」)。
"""
import os
import re

import yaml

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WORKFLOW = os.path.join(".github", "workflows", "ci.yml")

_GATE_CMD = "python tests/run_all_batched.py --quiet"
_GATE_OWNERS = frozenset({"tests", "nightly-gate"})
_TRIGGERS = frozenset({"push", "pull_request", "workflow_dispatch", "schedule"})

_TESTS_IF = ("github.event_name != 'schedule' && "
             "github.event_name != 'workflow_dispatch'")
_NIGHTLY_IF = ("github.event_name == 'schedule' || "
               "github.event_name == 'workflow_dispatch'")
_EXCLUDED_ATOMS = ("github.event_name != 'schedule'",
                   "github.event_name != 'workflow_dispatch'")


def _workflow():
    with open(os.path.join(_ROOT, _WORKFLOW), encoding="utf-8") as fh:
        # BaseLoader keeps `on` a string (PyYAML's default resolver turns the
        # bare key into bool True) and leaves every `if:` as a plain string.
        return yaml.load(fh, Loader=yaml.BaseLoader)


def _gate_steps(job):
    return [step for step in job.get("steps", [])
            if _GATE_CMD in str(step.get("run", ""))]


def _eval(expr, event):
    """Only the two condition shapes this workflow uses are supported."""
    expr = expr.strip()
    if "||" in expr:
        return any(_eval(part, event) for part in expr.split("||"))
    if "&&" in expr:
        return all(_eval(part, event) for part in expr.split("&&"))
    match = re.fullmatch(r"github\.event_name\s*(==|!=)\s*'([a-z_]+)'", expr)
    assert match, f"unsupported if atom -- guard would be a no-op: {expr!r}"
    op, name = match.groups()
    return (event == name) if op == "==" else (event != name)


def test_exactly_two_jobs_own_the_full_gate():
    """集合本身被钉住:新增第三个入口或删掉一个,都不能悄悄过闸。"""
    jobs = _workflow()["jobs"]
    owners = {name for name, job in jobs.items() if _gate_steps(job)}
    assert owners == _GATE_OWNERS, (
        f"full-gate owners changed: {sorted(owners)} != {sorted(_GATE_OWNERS)}")
    for name in sorted(owners):
        assert len(_gate_steps(jobs[name])) == 1, (
            f"{name} runs the full gate more than once")


def test_trigger_set_is_pinned():
    """新增触发方式时必须回来重新评估谁跑全量门禁。"""
    on = _workflow()["on"]
    assert isinstance(on, dict), "workflow `on` is no longer a mapping"
    assert set(on.keys()) == set(_TRIGGERS), (
        f"triggers changed: {sorted(on)} != {sorted(_TRIGGERS)}")


def test_event_conditions_are_exact_and_complementary():
    jobs = _workflow()["jobs"]
    tests_step = _gate_steps(jobs["tests"])[0]
    assert tests_step.get("if", "").strip() == _TESTS_IF, (
        "tests gate step lost its event condition")
    assert jobs["nightly-gate"].get("if", "").strip() == _NIGHTLY_IF, (
        "nightly-gate job condition changed")
    for event in sorted(_TRIGGERS):
        runs_tests = _eval(_TESTS_IF, event)
        runs_nightly = _eval(_NIGHTLY_IF, event)
        assert runs_tests != runs_nightly, (
            f"{event}: full gate would run {int(runs_tests) + int(runs_nightly)} "
            "times in one run")


def test_nightly_gate_step_is_unconditional():
    """job 级 if 已经是唯一闸门;再给步骤加 if 可能让 schedule 整个不跑。"""
    step = _gate_steps(_workflow()["jobs"]["nightly-gate"])[0]
    assert "if" not in step, "nightly-gate's gate step acquired its own if"


def test_tests_failure_evidence_is_scoped_with_its_gate():
    steps = _workflow()["jobs"]["tests"]["steps"]
    evidence = [s for s in steps if s.get("name") == "Upload failure evidence"]
    assert len(evidence) == 1, "tests job must keep its failure-evidence step"
    cond = evidence[0].get("if", "")
    for atom in _EXCLUDED_ATOMS:
        assert atom in cond, (
            f"tests evidence upload can collide with nightly-gate's "
            f"`regression-logs` artifact on the same run: missing {atom!r}")


def test_evaluator_truth_table_is_not_inverted():
    """守卫自己写反就会把互补断言变成假绿 —— 先钉死求值器。"""
    expected = {
        "push": (True, False),
        "pull_request": (True, False),
        "schedule": (False, True),
        "workflow_dispatch": (False, True),
    }
    assert set(expected) == set(_TRIGGERS)
    for event, pair in expected.items():
        assert (_eval(_TESTS_IF, event), _eval(_NIGHTLY_IF, event)) == pair, (
            f"evaluator truth table drifted for {event}")
    assert _eval("github.event_name == 'push'", "push")
    assert not _eval("github.event_name == 'push'", "schedule")
