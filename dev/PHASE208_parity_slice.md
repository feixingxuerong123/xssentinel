# Phase 208：64 族代表切片的双引擎对等测量

目的：回答"parity gate 要不要从现有切片扩到全族代表切片"。
现有 gate（`tests/test_engine_parity_gate.py`）跑的是一个固定切片；64 族代表
切片 = manifest 里每个 `(ground_truth, context)` 族各取一条代表（`_p208_measure.py`
的 `representatives()`，去重后 64 条）。

产物：`benchmark/results/p208_parity_slice.json`（8 批 × 8 例的 sync/async 结果与耗时）
日志：`_p208_run4.log`（续跑那次）、`_p208_url03.log`（分歧单跑定性）

## 结果

| 项 | 值 |
|---|---|
| 计分端点 | 64 / 64，无失败批 |
| sync 墙钟 | 211.3s |
| async 墙钟 | 217.4s |
| 合计 | 428.7s（7.1 分钟） |
| **分歧** | **1 处** |

## 分歧：`/r/url03`（meta_refresh 上下文，ground_truth = vulnerable）

```
sync  = [['polyglot_reflection', 'medium', 'medium']]
async = [['reflected',           'high',   'high']]
```

单跑定性（`dev/_p208_url03.py`，同一进程内双引擎对同一 URL）：

| 字段 | sync | async |
|---|---|---|
| type | `polyglot_reflection` | `reflected` |
| severity / confidence | medium / medium | high / high |
| context | `event_handler` | `event_handler` |
| evidence_class | **model-only** | **model-only** |
| payload | polyglot（multi_stage） | polyglot 变体 |
| evidence | token 反射进 onerror handler | 同（onload/onerror） |

**两边证据强度完全相同** —— 同一个上下文、同为 model-only、同为 polyglot 命中，
却给出两个不同的严重性。sync 侧 `scanner_layers.py:732` 有专门的
`type="polyglot_reflection"` 发射路径，其注释（Phase 198）写明理由：polyglot
尝试多种 breakout，是**比上下文特定 hit 更宽泛的声明**，所以 medium 是诚实的
model-only 默认值。

async 侧只有 polyglot **探针**（`async_scanner.py:991` 附近构建变体），命中后落进
通用 reflected 路径 ⇒ 拿到 high/high。**在证据等价的前提下 async 偏乐观。**

### 修复方向（未做，留给下一轮）

1. async 的 polyglot 变体命中应归类为 `polyglot_reflection`，severity/confidence
   取 medium/medium，并复用 sync 的 `_poly_non_html()` 降级（非 HTML 响应 → low）。
2. 用测试锁住"polyglot 载荷命中的 finding 不得落到 reflected"。
3. **改判定语义 ⇒ 必须配全量 192 例矩阵验收**，不与其它改动混在同一轮。

## 三条方法层面的发现（比数字更值钱）

1. **`benchmark.server.run_server()` 不是工厂，它会自己进 `serve_forever()`**，
   只在 `shutdown()` 之后才 return。测量脚本首版写成 `srv = run_server(port=0)`
   ⇒ 死锁在第一行有效代码上：**17 分钟墙钟、0.42s CPU、一个请求都没发、没有任何
   输出说它卡住了**。正确形状是 gate fixture 那套：线程里跑 + `ready_callback` 取端口。
2. **中间结果必须落盘，且单批异常必须隔离**。首轮完整跑被会话中断在批 6/8，
   因为结果只在内存 ⇒ 20 分钟产出为零。第二版改为每批结束立刻写
   `_p208_state.json`（原子 replace），并给每批套 try/except + 一次重试；
   仍失败则落 `{"error": ...}` 并在汇总里打印失败批号 —— 不静默跳过。
   第三轮 async 撞 `WinError 64`（asyncio ProactorEventLoop）与服务端
   `WinError 10053` 时，靠"杀进程 + 续跑只补批 7/8"把最后 16 例补齐。
3. **这台机器上的墙钟不能当门禁指标**。同一批、同样代码：
   async 批 5 首轮 678.2s、复跑 45.0s（15×）；整轮合计 ~25 分钟 vs 7.1 分钟。
   差值是本机安全软件间歇掐断 loopback 造成的，不是引擎特性。
   ⇒ 结论：**64 族切片可以周期性地手动跑，但不适合挂进常驻门禁**（成本 ~7 分钟
   且在这台机器上波动可达数倍）；现有 gate 切片的规模是对的。

## 效度限定（必须与结论一起读）

- 64 例是**跨两次进程**完成的（批 1–6 与批 7–8 之间我杀过进程），且**期间工作区
  有并行 agent 的改动**（`redirect_xss.py` / `websocket_xss.py` / `postmessage.py`
  等被改动，Phase 210b 的产物同时出现）。墙钟数字因此不可用于跨轮比较。
- 但**那 1 处分歧是同进程内复核过的**（`dev/_p208_url03.py`：sync 1.1s / async 0.3s
  同一 URL、同一批代码），不受跨进程问题影响。
- 切片里的族代表是"每族第一条"，不是随机抽样 ⇒ 覆盖的是族，不是族内分布。
