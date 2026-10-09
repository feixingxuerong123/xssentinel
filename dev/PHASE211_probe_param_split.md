# Phase 211 预备：`_probe_param` 拆分方案（未动代码）

`docs/OPTIMIZATION.md` 1.4 记的是"683 行单方法"。**实测现在是 787 行**
（`async_scanner.py:750` 起）——它比文档记的又长了 100 行，是全库最大的单个方法，
也是项目第一条约定（"新增能力进对应 Mixin，不堆回主文件"）在方法粒度上的唯一例外。

| 度量 | 值 |
|---|---|
| 行数 | 787 |
| `if` / `try` / `for` / `async for` / `async with` | 44 / 20 / 13 / 4 / 18 |
| 嵌套函数 | 0 |
| 调用的私有 helper | 8（`_probe_kv` / `_throttle` / `_req_headers` / `_next_proxy` / `_record_status` / `_try_pre_encoded_async` / `_scan_time_based` / `_scan_advanced_param_layers`） |

## 内部阶段（按既有 Phase 注释划分，行号对当前工作树）

| 段 | 行 | 内容 |
|---|---|---|
| A | 750–829 | L1 探针（发 marker、留 headers/body，Phase 100）、容器参数（178c）、多反射点分类（177）、escaped 收敛（93） |
| B | 830–966 | 结构化参数预编码（35）、多语料跨上下文采样（43）、反射画像 + 生成式载荷（37）、profile escape 收敛（95）、RCDATA breakout（96）、WAF bypass（93 门控） |
| C | 967–1059 | **主 variant 循环**：evasion 变体（86）+ polyglot 探针 + 发射 finding（165/208/164），flag + break（132） |
| D | 1060–1138 | concat 重试（166，27-1 预算） |
| E | 1139–1252 | 参数位置变换（37）+ flipped is_body（47）+ 二次 concat |
| F | 1253–end | CSP nonce 泄漏利用（100），同样 gated on `not param_confirmed`（132） |

## 切法

切成 A–F 六个方法，共享状态（`marker` / `context` / `marker_escaped` /
`param_confirmed` / `cands` / `variants` / `resp_headers` / `profile`）用一个
模块内 dataclass 承载，显式传递 —— **不用实例属性**：`param_confirmed` 决定了
后三段跑不跑（Phase 132 的门），放在 `self` 上会让"这次调用"和"下一次调用"串味。

C/D/E/F 是 async generator，委托写法 `async for f in sub(...): yield f`。

## 风险（每一条都要单独验证）

1. **异常传播**：`BudgetExhausted` / `CircuitOpen` 现在是 `raise`（不降级为 continue）。
   拆到子方法后，任何新加的 `except Exception` 都会把它们吞掉 —— 这是 async 错误
   分类学里最容易退化的一处。
2. **副作用计数**：`self.requests_made`、`self._record_status()`、`self.coverage`
   必须仍发生且只发生一次。委托到子方法本身不破坏（都在 `self` 上），但重排顺序会。
3. **polyglot 分类（刚修的）**：C 段里 `_is_poly` 的判据跨了主循环与 D 段 concat 重试
   两处。拆分时若只搬一处，Phase 208b 修的那条分歧会**原样回来**。
4. **`--quick` 与全量的 SKIP 口径不同**（quick ≈ 0–1 SKIP，全量 10 SKIP），别拿两者
   数字对比。

## 验收（改逻辑，四件套 + 逐例比对）

基线已经就绪：`benchmark/results/p208_full_async.json`（全量 async 192 例，
**含 `finding_details`** —— Phase 206 那份没有这个字段，所以只能比对
verdict/findings_count）。

1. `dev/compare_baseline.py <baseline> <new>` —— 逐例比对 verdict / detected /
   findings_count / error / finding 的 type·severity·confidence·context，
   请求数只报告不判失败（本机墙钟与请求数都会因安全软件抖动 8 倍）。
   脚本已用它验过 Phase 208b：与 Phase 206 基线 **192 例逐例 0 差异**（可比字段）。
2. parity gate（~225s）
3. `--quick --strict-gate` 双引擎
4. 全量 async 192 例矩阵（~15 min，环境差时翻倍）
5. 反证：拆完后故意把 `param_confirmed` 门去掉一处，请求数/结果必须变化 ——
   否则说明那段根本没被跑到。

## 为什么单独立一轮

787 行、跨 6 个语义阶段、含 4 个必须保持的跨阶段门控（132/165/166/208）。
"搬代码与改逻辑绝不混在同一轮"是项目既有约定，这条拆分**只能通过改逻辑完成**
（要引入状态对象），所以它需要自己的一轮、自己的基线和自己的全量验收。
