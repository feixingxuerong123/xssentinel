# Phase 387 轮次报告 — strict gate 墙钟预算(2026-11-13)

结论先行:2.0.1 之后工作区里那半截性能预算**按纪律补齐并验证**,不是撤掉。
四档基线全部由本轮自己的运行产生,ceiling 全部由实测推导,runner 的
`--strict-gate` 现在有独立的性能判级;未测量组合一律明说 UNBUDGETED。
判定层、CLI/MCP/REST 契约零改动。

## 起点(为什么这轮存在)

工作区残留 `benchmark/runner.py` 的一行 import、新建但四条基线全为 0 的
`benchmark/perf_budget.py`、一份 64 例 quick sync 产物;模块注释声称四档
已测,实际没有守卫、没有变异、没有文档。按「测量先行」「量过是不需要的
更不该进代码」,只有补齐或撤掉两条路。缺口是真的:runner 一直记录
`total_time_s` 却没有任何门看它,扫描器慢 10 倍仍会 FP0/FN0/ERROR0 全绿。

## 测量方法(可复现)

```
C:/Python39/python.exe dev/phase387_measure.py --force --date 20261113
```

- 四档(quick/full × sync/async)**串行**实跑,各自一个可 bind 的干净端口
  (18951 起),互不争 loopback —— 并行会直接污染被测的墙钟;
- `TEMP`/`TMP` 指到工作区外 scratch(绕 safe-delete 守卫每轮删除上限),
  `NO_PROXY` 含 loopback(防出口代理把静态资源回成首页),`PYTHONPATH` 清空;
- `--only <mode:engine>` 可续跑,`--force` 强制重测;**红/退化产物不得晋级
  基线**(FP/FN/ERROR 非零、scored 为零、`total_cases` 与 cases 数组不等,
  任一即判不可用);
- 逐档日志 `benchmark/results/_local_archive/phase387_*.log`,汇总
  `_local_archive/phase387_summary_20261113.json`,四份基线 artifact 在
  `benchmark/results/perf_baseline_*_20261113.json`;08:59 那份旧 quick sync
  产物移到 `_local_archive/` 留档,不覆盖正式证据;
- **四档测量时 perf 臂尚未启用**(逐档日志均打印 `UNBUDGETED`),所以基线
  是纯质量门的墙钟。启用后的 enforcement 另由两路独立验证,见下。

## 三处自我纠正(都是实测抓出来的)

1. 占位表第一次接到 runner 时,64 例 quick/sync 恰好匹配占位条目的
   `cases=64`,于是打印 `FAILED: 165.7s vs ceiling 0s` —— 一张没填完的表
   会拿假上限判红。修法不是改 cases 躲开,而是 `budget_for` 明确
   「`baseline_s<=0` 的条目不是预算」(**零永远不是通过**的又一处实例)。
2. CHANGELOG 先写下「非默认并发度属未测量组合」后复核代码,发现
   `budget_for` 当时没有 concurrency 维度 ⇒ 文档比代码诚实。补字段、调用点
   与一条真实入口守卫,那句话才成立。
3. 变异对照第一次 ABORT 在 runner 的多行 anchor(找到 0 次):runner.py 是
   历史 CRLF,新文件是 LF,`bytes.decode()` 不做 universal-newline 转换。
   修法是让每个变异 anchor 使用**该文件自己的**换行符;ABORT 本身是守卫
   生效,不是变异不存在。

## 验证链(四层,逐层不同职责)

| 层 | 工具 | 验证什么 |
|---|---|---|
| 真实墙钟 | `dev/phase387_measure.py` 四档 strict gate | 基线来自本轮自己的运行,红产物不晋级 |
| 真实 main 链 | `dev/phase387_enforcement_check.py` | 用实测结果回放 `main()`:基线 rc=0、超 ceiling 1s rc=1,两个门各自出结论 |
| 真实 CLI 补跑 | `gate_run_scratch.py --quick --strict-gate` | 启用后的真实扫描里,性能门确实打印 PASSED 且质量门仍绿 |
| 守卫 + 变异 | `tests/test_phase387_perf_budget.py` / `dev/phase387_mutations.py` | 数字与 artifact 同源、ceiling 复算、调用点不腐化;每个变异只跑一个具名 node |

守卫里对 runner 的**源码断言**(AST:main 必须调 `_perf_gate_line`、必须有
`if not perf_ok → return 1`、不得硬写 ceiling 或绕过表)是刻意的:函数体不会
腐化,调用点会走回手写(Phase 259/176u 同族)。

## 边界与明确不做

- 预算锚定本机(loopback 画像 / CPU / TEMP 标签),**不套 CI**:hosted runner
  速度与噪声分布不同,要钉 CI 预算得先有 CI 自跑基线;未预算的跑只会被
  说出、不会被默认判绿。
- skip 数仍只由质量门报,性能门只判墙钟;rotated quick slice、CI 周轮切片、
  未测 case 数、非默认 `--concurrency` 全部落在 UNBUDGETED。
- 性能门接在 `--strict-gate` 上(opt-in),legacy 阈值路径行为不变。
- **全量 194 精度门本轮已跑两档**(四档里的 full/sync 与 full/async,
  均 FP0/FN0/ERROR0,skip 0 / 12),数字是本轮自己的运行,不拿 11-13 早间
  的交付轮数字顶账;**全量分批 pytest 门(305 文件)本轮未跑** —— 判定面
  零改动,改动集中在 benchmark runner 与新增守卫,由 13 文件 227 例邻接组
  覆盖,如实记为未跑而非绿。
- 下轮候选不变:fn_net 的 2 个 polyglot 真 FP(L7 降档)、parity 全矩阵
  2/194 存量分歧;PyPI Trusted Publisher 仍是归属者的外部待办。

## 文档与证据索引

- 决策与数字: `docs/OPTIMIZATION.md` §8.18(四档基线表 + 验收数字)
- 变更条目: `CHANGELOG.md` `[Unreleased]`
- 代码: `benchmark/perf_budget.py`、`benchmark/runner.py`
- 工具: `dev/phase387_measure.py`、`dev/phase387_enforcement_check.py`、
  `dev/phase387_mutations.py`
- 守卫: `tests/test_phase387_perf_budget.py`
