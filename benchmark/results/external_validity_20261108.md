# XSSentinel 外部效度：现有证据的可复核清单（2026-11-08）

> 目的：把散落在 `benchmark/results/` 的数字按**样本量、工具版本、口径、
> 不可比项**整理成第三方可复核的形式。
> **本报告不宣称"超越商业 XSS 工具"**。项目对外目标已由 README
> 「定位与诚实声明」收敛为"开源里检测维度最全"；这里只回答
> "目前究竟有什么证据、它们能支撑到哪一步"。
> 全部数字来自本仓产物，不引用外部评测、不补估算。

## 一、结论先行

| 分级 | 有什么 | 能支撑 | 不能支撑 |
|---|---|---|---|
| **强**：第三方靶 + 第三方答案键 + 官方评分器 | 官方 XSSMaze v0.3.0 全量（1013 例）多次跑分 | 靶场上的检出/误报、与两款免费工具同台比较 | 生产环境表现、商业工具比较 |
| **中**：第三方语料 + 自建目标 | Phase 196 三工具 60 例切片 | 载荷语义覆盖 | "别人出的题"只到位一半 |
| **自证**：自建目标 + 自建答案 | 194 例矩阵、range3–7、bWAPP 矩阵 | 回归防退化 | 任何外部效度结论 |
| **空白** | Burp Pro / Acunetix / Netsparker / ZAP / 真实授权目标 | — | 任何"超越商业工具"的结论 |

## 二、强证据：官方 XSSMaze v0.3.0

### 2.1 本轮全量（2026-11-08，当前未提交 WIP 树）

| 口径 | TP | FN | FP | Precision | Recall | F1 | 墙钟 | 产物 |
|---|---|---|---|---|---|---|---|---|
| 旧（GET-only，与历史同口径） | 975 | 38 | 0 | 100.0% | 96.2% | **0.981** | 1959.1s | `benchmark/results/xssmaze_full_20261108.{json,md}` |
| 新（POST-aware，opt-in） | 987 | 26 | 0 | 100.0% | 97.4% | **0.987** | 2039.6s | `benchmark/results/xssmaze_full_post_aware_20261108.{json,md}` |

- 计分 population **1013**（`--reach server`）；24 条 client-reach 不计分；
  **27 条 `exploitable=false` 控制例 FP 均为 0**。
- 两轮参数除 wrapper 的 POST 开关外完全相同：`--reach server`、
  `{URL}` per-URL wrapper、`--detect-json 'findings[].url'`、
  `XSSMAZE_TIMEOUT=110`、`--scanner-timeout 90`。
- **0.987 不是检测能力提升**：POST-only 端点终于拿到 body。逐例差集
  GAIN 14（headless-generator ×5、postmethod ×5、post / multipart /
  realworld_input / domsink-level7）、LOSS 2（`dom-level6`、
  `domsink-level3`，新 invlog 里连行都没有，单跑在两口径下都稳定
  1 finding / rc=0 ⇒ 环境超时伪影）。详见
  `benchmark/results/xssmaze_post_aware_20261108.md`。
- **两口径不可直接比较**，也不与下面 0.965 / 0.957 比较。

### 2.2 三工具同 scorer 对跑（Phase 342，2026-10-30）

同一官方靶 + 官方 runner + 逐例矩阵，产物
`benchmark/results/phase342_xssmaze/p342_meta.json`（README「外部效度」有摘要）：

| 工具 | TP | FN | FP | F1 | 墙钟 |
|---|---|---|---|---|---|
| XSSentinel | 944 | 69 | **0** | **0.965** | 5741s |
| dalfox | 757 | 256 | 4 | 0.853 | 4072s |
| nuclei | 731 | 282 | 4 | 0.836 | 406s |

**必须一起读的限定**：dalfox 是 Go 冻结分支 v2.13.0，现行 Rust v3
未对跑（本机取不到 release 资产）；其 chromedp headless 层在本机不稳而
`--skip-headless`（该层贡献另行抽样量化）；控制例 FP 我方 0、两竞品各 4；
nuclei 速度仍快一个量级。

### 2.3 早期终态（2026-10-24，README 记录）

| 群体 | TP | FN | FP | F1 |
|---|---|---|---|---|
| client（`--reach client --headless`） | 24 | 0 | **0** | **1.000** |
| server（`--reach server`） | 925 | 88 | **0** | **0.955** |

4 条 100s wrapper 超时单独复跑 10–12s 完成并命中，补齐口径
929 / 84 / 0（R 91.7% / F1 0.957）。server 的 88 条 FN 主体是 query
能力缺口，body/header/path 约 35 条与"官方 runner 只给 URL"的投递契约
有关——这正是 Phase 370 修的测量口径问题。

## 三、中证据：第三方语料 + 自建目标（Phase 196，2026-10-04）

产物 `benchmark/results/phase196_cross_tool.{json,md}`；60 例按
`(ground_truth, context)` 分层确定性切片，三工具拿到**完全相同**的目标
URL；引擎 build `78d65e6132f02ca0` 全程固定。

| 工具 | 版本 | TP | FP | TN | FN | ERR | F1 | 墙钟 |
|---|---|---|---|---|---|---|---|---|
| XSSentinel | builtin | 35 | 0 | 24 | 1 | 0 | **0.9859** | 346.4s |
| dalfox | v2.13.0 | 26 | 1 | 22 | 10 | 1 | 0.8254 | 1172.7s |
| nuclei-dast-xss | v3.9.0 + `dast/vulnerabilities/xss` | 26 | 0 | 23 | 10 | 1 | 0.8387 | 48.6s |

**限定**：判定语料（nuclei dast 模板、dalfox 载荷）是第三方的，
**目标仍是本项目自编 194 例矩阵的切片**——"别人出的题"只到位一半。
我方唯一 FN 是打分口径（XS-Leaks 层按设计给 low/firm，而"检出"定义为
high/medium/critical），不是判定错误。速度维度我方既不是最快也不是最慢。

## 四、自证（不计入外部效度）

- 194 例自编矩阵：sync 与 async 四档 strict gate 全绿（最近一次
  2026-11-08：quick 64 sync 0 SKIP / quick 64 async 1 SKIP /
  full 194 sync 0 SKIP / full 194 async 12 SKIP，全部 FP0/FN0/ERROR0）。
  **矩阵自己出题自己答，F1=1.0 只证明没写坏。**
- range3–range7 自建靶场、bWAPP 72 组矩阵、DVWA 页实测：同上，用于回归。
- PortSwigger cheat sheet 技术面覆盖对照（`benchmark/portswigger_corpus_coverage.py`）：
  字符串出现 ≠ 语义等价、覆盖 ≠ 能检出，脚本 docstring 已写明三条局限。

## 五、空白与阻塞

| 缺口 | 实测状态 |
|---|---|
| Burp Pro / Acunetix / Netsparker | **零对跑**，本机无安装/授权 |
| OWASP ZAP | 2026-11-03 real-world v2 的 13 例**全 BLOCKED / unavailable**，见 `benchmark/results/zap_unavailable_20261103.md` |
| 真实授权目标 / 生产流量 | **零样本**；Juice Shop / DVWA 属靶场，不是授权生产目标 |
| 性能 | 多个口径均比 nuclei 慢一个量级（48.6s vs 346.4s；406s vs 5741s） |
| 环境 | 2026-11-08 傍晚起本机 `wsl.exe` 被安全策略拦，Docker Desktop 后端起不来，**XSSMaze 复测当前无法进行** |

## 六、不可比项清单（引用任何数字前先读）

1. **POST-aware 0.987 与 GET-only 0.981 不可比**：测量口径变了，不是能力变了；
   差值来自 POST 端点拿到 body。
2. **2026-10-24 / 10-30 / 11-08 三个时点不可直接连成"进步曲线"**：
   代码树不同（当前 WIP 未提交）、Phase 364–371 改动混杂、wrapper 超时
   设置不同（100s / 30s 默认 / 90s）、本机 loopback 状态不同。
3. **dalfox 结果不可外推到现行版本**：对跑的是 Go 冻结分支 v2.13.0，
   且跳过了 headless 层；Rust v3 从未对跑。
4. **速度不能与精度互换**：nuclei 快一个量级但 F1 低；任何"性能优于同类"
   的说法都要按 §2.2 / §3 的墙钟校准。
5. **194 矩阵 F1=1.0 是自证**，不得与 XSSMaze 的 F1 并列展示为"两个满分"。
6. **controls FP=0 只说明靶场控制例**，不等于生产环境误报率。
7. **超时伪影**：本机间歇失稳已多次造成假 FN / `partial`；每轮都用
   单跑复现定性（见各轮报告），不得把未复现的偏差当成判定变化。
8. **本报告写于未发布树**：`__version__ 1.4.4`、CHANGELOG 1.4.4、
   远端 main 仍停在 `67a1a80`（Phase 358 时代），领先 9 个提交未推。
   这些数字**不是已发布 1.4.3 的成绩**。

## 七、补齐 E 需要什么（按依赖排序）

1. **无需外部条件、可立即做**：本报告；把口径限定写进 README 对比章节；
   给每个 historical 数字打上日期与代码树标签。
2. **需要环境恢复**：手动启动 Docker Desktop 或解除 `wsl.exe` 黑名单，
   恢复 XSSMaze 复测能力（当前连维持性复测都跑不了）。
3. **需要外部条件**：商业工具授权/安装、真实授权目标、换机器跑 ZAP。
   这一层不是编码能解的，别用靶场数字填格子。
4. **需要一次决定**：是否把 POST-aware 定为新的官方口径。一旦定，
   所有历史数字都要重跑或明确标注断点。

## 八、一句话

以"**开源里检测维度最全、工程最扎实**"论，§2 的第三方证据已足够；
以"**超越所有商业 XSS 工具**"论，**证据链尚不存在**，且 §5 的空白
不是再加几个靶场用例能补上的。README 的收敛是对的。
