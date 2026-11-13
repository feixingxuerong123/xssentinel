# Phase 389 轮次报告 — 只修 `marquee/onstart` 这一格(2026-11-13)

结论先行:Phase 388 把缺陷收窄到 9 个 polyglot 执行原语里唯一一条
「验证器确认、Chromium 148 不执行」的形状;本轮在**沙箱的浏览器事实表**
里把这一格标为 `inert`,让既有的 Phase 169 veto 收回确认。同一量具
72 臂重测:`verifier_only` **1 → 0**,`true_detection` **8 保持**,
浏览器事实逐形状一位未变。**语料集合一个形状都没删。**

## 根因(两处认知各差一步)

1. `verifier._verify_semantic_impl` 第 2 步只看属性名:任何
   `attr.startswith("on")` 且 token 在 value 里就 `confirmed=True`
   (除 CSP / UTF-7 门),不看元素、不看事件是否真会派发。
2. `sandbox._handler_state` 对没进测量表的 handler 落到通用 tail
   → `"activation"`(「一次点击就执行」),`judge` 折成
   `Verdict("live", activation=True)`;而 **veto 只认 `inert`**
   ⇒ 确认收不回来。修复前实测:
   `judge = live, activation=True, "marquee.onstart requires user interaction"`
   —— 这句「需要用户交互」本身就是没量过的猜测。

## 修法

`sandbox.py` 新增 `INERT_HANDLER_PAIRS = {("marquee","onstart")}`,
`_handler_state` 在一切门类之前返回 `inert`;验证器随后给出
`confirmed=False` / `detail="sandbox: ..."` / `sandbox_state=inert`。

**是元素 × 属性的 pair,不是 handler 名黑名单**:Phase 362 在 XSSMaze
eventhandler/level5 量过,尖括号被剥离后 `onstart` 落在宿主元素上
(不是 `<marquee>`)是活的。守卫里 `<div marquee onstart=...>` 明确断言
仍确认,钉住这条边界。`polyglot.py` 那句「legacy but still fires」注释
按浏览器事实改正,**集合不变** —— 删形状会动覆盖率与 stride 路由,而
验证器拒了之后 L7 自然不再发射,没必要动。

## 前后对照(同一量具,不是重写一份数字)

给 `dev/phase388_primitive_matrix.py` 加 `--out`,用完全相同的
9 原语 × 2 sink × 4 esc = 72 臂重测,388 的带日期事实表保留不覆盖。

| 轮次 | true_detection | verifier_only | marquee verifier | marquee browser | controls_valid |
|---|---|---|---|---|---|
| 388(修复前) | 8 | 1 | True | False | True |
| 389(修复后) | 8 | **0** | **False** | False | True |

逐形状比对:浏览器事实完全一致,**只有 marquee 的 verifier 位翻转**。
单元级对照:8 个活形状仍 `confirmed=True`、Phase 362 属性形状仍确认、
沙箱保真度与 gate 守卫合计 20 例全绿。

## 纪律

- 「`on*` 属性名 == 可执行」和「未识别 handler == 一次点击就活」都是
  **照属性名 / 照猜测报**,不是照浏览器事实报。
- 修在沙箱的测量表里让既有 veto 生效,而不是在验证器加
  `if attr == "onstart"` 特判(那会误伤 Phase 362)。
- `<div onstart>` 之类本轮**没量过**的形状按「没量过不进门禁」保持原状。
- 判定语义变更 ⇒ 全量 194 两档 + quick 两档 + 对照矩阵 + 邻接组,
  数字统一记 OPTIMIZATION §8.20 验收节,不在本报告复制。

## 边界与证据索引

- 不动语料集合、不动 stride、不动 CLI/MCP/REST 契约。
- 决策与验收数字: `docs/OPTIMIZATION.md` §8.20;条目: `CHANGELOG.md`
  `[Unreleased]`。
- 事实表: `phase388_primitive_matrix_20261113.json`(前)、
  `phase389_primitive_matrix_20261113.json`(后)。
- 代码: `xssentinel/core/sandbox.py`、`xssentinel/core/polyglot.py`(注释)。
- 工具: `dev/phase388_primitive_matrix.py`(`--out`)、
  `dev/phase389_mutations.py`;守卫 `tests/test_phase389_marquee_inert.py`。
