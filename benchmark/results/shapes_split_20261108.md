# Phase 371：scanner.py 架构瘦身 + 层注册缺陷（2026-11-08）

> 本轮起点是上一轮"收口发版"建议里的**架构优化**：`scanner.py` 超行数预算
> 143 行。按项目硬规则选择**拆**，不抬预算；全程**纯搬运、零逻辑改动**。
> 顺带在广回归里发现并修掉一个从 Phase 364 起就存在、但前几轮没跑到的缺陷。

## 一、做了什么

| 文件 | 变化 |
|---|---|
| `xssentinel/core/scanner_shapes.py` | **新建**。`ShapesMixin`，承载 Phase 364 的 3 个形状探测方法 |
| `xssentinel/core/scanner.py` | 移出 171 行；加 import、`ShapesMixin` 组合声明 |
| `xssentinel/core/coverage.py` | `LAYERS` 补 3 个漏注册的 layer id |
| `benchmark/layer_coverage.py` | `COVERAGE` 同步补 3 条（`None` = 无对应 manifest case） |
| `tests/test_architecture_scale.py` | `BUDGETS` 登记新 Mixin（215 行） |
| `tests/test_mixin_contracts.py` | `HIERARCHIES` 登记 `ShapesMixin` |

搬走的 3 个方法：`_try_srcdoc_bypass`、`_try_js_callback`、
`_try_param_name_injection`（`scanner.py:1712-1881`）。调用点原本只在
`Scanner` 内部 3 处（`:754 / :1047 / :1061`），**一行未改**。

### 纯搬运的证明

- 按字节切分（自动适配行尾；`scanner.py` 当前是纯 LF），
  切片 **7650 字节 / 171 行 / sha256 `985aa18ea6c09e2c`**。
- 插入新文件后重新取出该切片做哈希比对：`VERDICT: pure movement OK`；
  旧文件中该切片已消失。
- import smoke：`Scanner.__mro__` = `Scanner, StoredBlindMixin,
  StoredAutoMixin, AdvancedLayerMixin, CrawlMixin, ShapesMixin, object`；
  3 个 `self._try_*` 全部解析到 `ShapesMixin.*`。
- 符合项目硬规则「搬代码与改逻辑绝不混在同一轮」。

### 架构守卫转绿

| | 拆分前 | 拆分后 |
|---|---|---|
| `scanner.py` | 2793 行（> 2650，**红**） | **2624 行（< 2650，绿）** |
| `scanner_shapes.py` | — | 193 行（< 215，绿） |

`test_architecture_scale` 全部 4 例、`test_mixin_contracts` 全绿。

## 二、顺带发现并修掉的真实缺陷（自我纠正）

广回归跑到 `tests/test_layer_registry_parity.py` 时红了：

```
layer_ids used by touch_layer() but missing from coverage.LAYERS:
['L1_js_callback', 'L1_param_name', 'L1_srcdoc_entity']
```

- 这 3 个 id 是你 **Phase 364** 新增形状探测时用的，从未注册到
  `coverage.LAYERS`，所以 `record_layer()` 走 unknown-layer 兜底，
  **统计、摘要、覆盖矩阵里全部看不到它们**。
- 守卫用 `_CORE.rglob("*.py")` 扫全部 core 文件，**与本次搬运无关**——
  搬运前后都会红。根因是**我前几轮的回归组没包含这个守卫**，
  所以上一轮我报"两个红项"（架构 / 版本同源）时**少算了一个**。
  这是归因错误，在此更正。
- 修法按项目硬规则「两处同时注册」：`coverage.LAYERS` 加 3 条；
  `benchmark/layer_coverage.py::COVERAGE` 同步加 3 条，patterns 用矩阵
  自带的 `None`（194 例 manifest 确实没有对应 mode，这些是 XSSMaze
  专属形状），不编造 mode、不引入 stale 条目。
- 这是 AGENTS.md 记的「Phase 187/192 两次被门禁抓到的同一课」**第三次踩**。

## 三、证据链

| 环节 | 结果 |
|---|---|
| 搬运字节校验 | 7650 B / 171 行 sha256 一致，旧文件已无该切片 |
| 组合契约 | MRO 与 3 个方法解析全部正确 |
| 守卫组 | 架构 / Mixin 契约 / 层注册 / 覆盖矩阵 / 层记账 / Phase 364 形状 **27 passed** |
| 广回归 | 层注册等 14 文件 **151 passed / 1 failed** —— 那 1 个 red 正是上面发现的缺陷，修后转绿 |
| ruff | 全仓 `All checks passed` |
| 四档门禁 | quick sync 64（0 SKIP）/ quick async 64（1 SKIP）/ full sync 194（0 SKIP）/ full async 194（12 SKIP），**全部 FP0 FN0 ERROR0、exit 0**，15m51s |

## 四、仍未处理（需要你决定，我没擅自做）

1. **版本同源守卫仍红**：`CHANGELOG` 最新 `1.4.3` vs `__version__ 1.4.4`。
   定 1.4.4 还是 1.5.0、补 CHANGELOG 是发版策略，不代你决定。
2. **未提交、未推送**。工作树仍是 15 M + 33+ 未跟踪（本轮又新增 1 个
   `scanner_shapes.py`），本地领先远端 9 个提交。按项目「每个 Phase
   独立提交」的规矩，应先按 Phase 拆提交再推。
3. PyPI Trusted Publisher 未配（README 已声明）。

## 五、取舍

- 本轮之后**不建议再做架构拆分或加契约守卫**：`scanner.py` 回到预算内，
  两处漂移（Mixin 登记、层注册）都已由守卫钉住，继续拆是纯装饰。
- 下一步真正的阻塞项是**收口**：版本定级 → 拆提交 → 推送。
  这三件都需要你的决定/授权，不是技术活。
