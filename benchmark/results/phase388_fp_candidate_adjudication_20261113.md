# Phase 388 轮次报告 — 推翻「2 个真 FP」,把「候选 ≠ 判定」固化成工具(2026-11-13)

结论先行:上一轮(§8.17 / CHANGELOG [2.0.1])记下的「fn_net 2 个真 FP、
L7 polyglot 层在引号转义画像下降档」**是错的**。用 finding **自己的载荷**
在同一渲染下回渲 + 真 Chromium dialog 复判,并枚举产品语料的全部执行原语
做确定性矩阵后:绝大多数形状是**真阳性**,只有一条原语是 verifier-only。
**按该方向修会制造 FN,修复方向作废**;本轮零判定层改动。

## 起点

`benchmark/results/fn_net_20261113.json` 的 FP 臂给出两个候选:
`script_dq / encode_quotes / sink=none|dom`,验证器拒绝 top-3 语料但扫描器
报 1 条 `polyglot_reflection`。§8.17 据 `dev/_p334_browser_oracle.py` 里
手写形状「浏览器证伪」把它定性为真 FP,并列出 L7 降档候选。

## 三层证据(职责各不相同)

| 层 | 工具 / 产物 | 回答什么 |
|---|---|---|
| 快速复判 | `dev/_p387_fp_probe.py` → `dev/_p387_fp_probe.json`(均 gitignore) | finding 自己的载荷在 `encode_quotes` 下 verifier 与真 Chromium 是否都确认 |
| 通用裁定器 | `dev/fn_net_adjudicate.py` → `benchmark/results/fn_net_adjudication_20261113.json` | 把 Phase 256 方法固化成可复跑命令:同源渲染 + 引擎验证器 + 浏览器 + 正/负对照臂 |
| **确定性矩阵(定性依据)** | `dev/phase388_primitive_matrix.py` → `benchmark/results/phase388_primitive_matrix_20261113.json` | 枚举产品 `_EXEC_PRIMITIVES` 全部形状 × 2 sink × 4 esc,消除随机量具 |

裁定器的正式产物里保留了一条 `inconclusive`:那次扫描随机选中
`<marquee onstart=...>`,连 `raw` 正对照都不执行 ⇒ `controls_valid=False`。
**没有硬凑结论**——这条 inconclusive 本身是「对照组不能省」的实证。

## 为什么 §8.17 会错

`build_multi_stage_polyglot` 的执行原语由
`sum(ord(c) for c in token) % len(_EXEC_PRIMITIVES)` 挑选,token 随机,
**单次扫描报出的 payload 每次不同**。§8.17 用的 oracle case 是手写的
「相近」形状:`&lt;/script&gt;` 在 script rawtext 里根本不解码(不会闭合
脚本),另一个裸闭合字符串的引号拼接有 bug。两者都不是 finding 自己的载荷,
也不是真实渲染出的完整 HTML —— 是伪影,不是浏览器事实。

矩阵脚本不手写任何形状:原语取自 `polyglot._EXEC_PRIMITIVES`,breakout
前缀取自产品自己的 `build_multi_stage_polyglot`,页面取自真实
`/fuzz/render`,浏览器加载的是**回渲后的完整 HTML**。

## 定性结果

`script_dq + encode_quotes`,两个 sink 结论一致;详细 72 臂与逐形状名单见
`phase388_primitive_matrix_20261113.json` 与 OPTIMIZATION §8.19 的表。
`raw` 正对照有 fired、`html` / `encode_angles` 负对照全静 ⇒
`controls_valid=True`,oracle 不空转。

⇒ 真实缺口**收窄为一条原语**(语料时基陈旧 / 验证器事件表过宽),而不是
「L7 在转义画像下整体降档」。修它属于判定语义变更,按纪律**独立成轮 +
对照矩阵 + 全量 194**,本轮不改判定层。

## 五条纪律(这一轮踩出来的)

1. 网的 FP 臂只试 top-3 语料,「验证器拒绝 + 扫描器报」只是**候选**,
   必须用 finding 自己的载荷回渲回验才能定性。
2. oracle 不许手写「听起来相近」的形状;载荷与页面都要来自真实入口。
3. 正/负对照臂是裁定有效性的前提,`controls_valid=False` 只能
   `inconclusive`,不许硬下结论。
4. 随机量具要么固定 token、要么枚举全空间,否则结论不可复现。
5. 带日期的历史结论不改写:用 `[Unreleased]` 勘误 + §8.17 原文旁注纠正;
   守卫同时钉住「勘误存在」与「2.0.1 / §8.17 原文仍在」。

## 边界与下轮

- 本轮**零判定层改动** ⇒ 不跑全量 194(不拿 11-13 早间数字顶账);回归
  证据是守卫、变异、邻接组、ruff 与 quick 两档 strict gate,数字统一记在
  OPTIMIZATION §8.19 验收节,不在本报告复制。
- 下轮候选**替换**为「`marquee onstart` 单形状的验证器 / 语料修复」,
  不再是「L7 画像降档」。parity 全矩阵 2/194 存量分歧与 PyPI Trusted
  Publisher 不变。

## 证据索引

- 决策与验收数字: `docs/OPTIMIZATION.md` §8.19(§8.17 旁有更正注记)
- 勘误: `CHANGELOG.md` `[Unreleased]`(2.0.1 历史原文保留)
- 事实表: `benchmark/results/phase388_primitive_matrix_20261113.json`、
  `benchmark/results/fn_net_adjudication_20261113.json`
- 工具: `dev/phase388_primitive_matrix.py`、`dev/fn_net_adjudicate.py`、
  `dev/phase388_mutations.py`
- 守卫: `tests/test_phase388_primitive_matrix.py`
