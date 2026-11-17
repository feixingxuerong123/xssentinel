# Phase 401 / Phase 391 `onstart`「证据冲突」定谳：假冲突

日期：2026-11-18。事实表，**不与 XSSMaze F1 / 194 矩阵 / 外部语料任何数字并列**（Phase 380 规则）。
证据：`benchmark/results/phase401_*_20261118.json`；守卫 `tests/test_phase401_onstart_adjudication.py`；变异 `dev/phase401_mutations.py`。

## 结论先行

Phase 391 留下的「11 个 onstart 形状 verifier 确认但浏览器不执行，与 Phase 362 靶场 live 证据冲突，未定谳」——本轮定谳为**假冲突**，由两个错误构造：

1. **误判 level5 页面性质**：Phase 391 以为 Phase 362 的 live 来自「有页面脚本、有挑战自己判定口径」的真实页面。拿到源码后发现 level5 就是**纯静态 `<div>`，无脚本、无派发**——和裸 HTML 同一口径，可以直接互证。
2. **误读 Phase 362 证据等级**：Phase 362 那条 finding 是 `browser-unavailable / headless=None / execution unverified`——从不是浏览器确认的执行，只是未验证反射。没有「靶场说 live」的证据可与 Phase 391 冲突。

真浏览器复测（有效对照）确认：onstart 在 level5 真页面确实 verifier 过判、浏览器不执行——与 Phase 391 裸 HTML 结论**一致**，没有冲突。

## 取证与定谳四步

### 1. 靶场真源码

`git clone hahwul/xssmaze`（走全局 ghfast insteadOf 绕开 GitHub 超时）+ `git fetch --unshallow`。定位 commit `2976f2e`。`event_handler.cr` 的 level5 逻辑自 c7a0a83 起未变（git diff 核实）：纯服务端拼接 + handler denylist，无 `<script>`。快照固化在 `phase401_xssmaze_level5_source_snapshot_20261118.json`（带 commit hash、关键代码、onstart 不在 denylist 的断言）。

### 2. level5 真页面 = 裸 HTML

```crystal
def self.build_html(query)
  query = Filters.strip_angles(query)   # 去掉 < >
  "<div #{query}>Event Handler Test :: #{query}</div>"
end
```

没有页面脚本、没有事件派发、没有挑战自己的打分脚本。Phase 391 的「不同口径不能互否」前提不成立。

### 3. Phase 362 证据等级

从 `dev/_xssmaze/_p362b_post/eventhandler-level5.json`（2026-11-06）实读：

```
payload: marquee onstart=alert('xssv_97f9ef15')
evidence_class: browser-unavailable
headless: null
detail: token reflected in onstart handler | no browser replay available; execution unverified
```

### 4. 有效对照的浏览器复测

**第一版探针被丢弃**：纯 load 态 oracle 下，连 level5 官方答案（`ononmouseovermouseover`→`onmouseover`，需 hover）都不弹 ⇒ `controls_valid=False`。按 Phase 388 纪律「对照不成立即 ABORT、不裁定」，该结论作废，未写入定谳。

**第二版**（load + hover，XSSMaze client-benchmark 口径）：

| 形状 | cleaned | browser dialog | verifier |
|---|---|---|---|
| 正对照：官方答案 `ononmouseovermouseover` | `onmouseover` | **True** | True |
| 负对照：`div id=x` | — | False | False |
| Phase 362：`marquee onstart` | `marquee onstart` | **False** | True |
| Phase 391：`div onstart` | `div onstart` | **False** | True |
| 嵌套绕过 `ononstartstart` | `ononstartstart` | **False** | True |

`controls_valid=True`。结论：onstart 三形状浏览器不执行而 verifier 仍确认——与 Phase 391 裸 HTML 一致。

## 边界：定谳 ≠ 修复

本轮**不改判定层**。`INERT_HANDLER_PAIRS` 仍是 `{("marquee","onstart")}`，Phase 389 的 `<div marquee onstart>` 仍 confirmed。扩 pair 覆盖其余 11 形状属判定语义变更，若要做须独立成轮 + 对照矩阵 + 全量 192。带日期的 §8.22 原文保留不改，以 §8.32 为准。

## 验收

- 守卫 `tests/test_phase401_onstart_adjudication.py` **5 例**：有效对照+定谳 / 真页面无脚本 / Phase 362 证据等级（交叉核对历史 artifact）/ onstart 浏览器 inert 而 verifier 确认 / 本轮未改判定层。
- Phase 389/391 旧守卫回归：**16 passed**（未因定谳被破坏，Phase 391 的「未定谳」历史约束仍兼容）。
- 变异 `dev/phase401_mutations.py` **3/3**（controls / onstart dialog / page_has_script 各篡改一位，baseline 绿→红→字节还原绿）。
- ruff 全仓零基线。
