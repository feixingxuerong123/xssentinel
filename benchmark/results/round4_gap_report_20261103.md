# 缺口补测报告 II（2026-11-03）

本报告只记录**本次实测**；仓库历史产物（`p352_sample_on.json`、
`gate_p355_*.json`、`realworld_v2.md` 的旧版本）单独标注。未执行 commit / push。

## 1. async stored 耗时归因

### 1.1 先纠正基线

上一轮报告的 async stored **101.1s vs sync 14.5s（7×）是受污染测量**：
那次 10 例复跑与 controls/门禁/浏览器任务重叠，CPU 被占满。本轮在空闲环境
用同一命令复跑：

```text
python -m xssentinel -u <stored-levelN> [--async] -f json \
  --max-payloads 14 --max-transforms 12 --threads 2 --timeout 10
```

| 引擎 | stored TP | FP | 10 例墙钟 |
|---|---|---|---|
| sync | 9 / 9 | 0 | 15.9s |
| async | 9 / 9 | 0 | **19.2s** |

本轮洁净基线 async/sync = **1.21×**，已在 ≤2× 目标内（≤29s）。
上一轮 101.1s 只能标记为"历史测量，环境受污染"，不与本轮混算。

### 1.2 各阶段耗时占比（单例、进程内计时，导入除外）

单例 `stored-level1`：

| 阶段 | sync | async | 说明 |
|---|---|---|---|
| 进程启动 + import（CLI 外） | ~0.55s（38%） | ~0.55s（32%） | `import xssentinel.core.*` 实测 0.51–0.55s |
| 扫描主体（不含 import） | 0.694s（48%） | **0.383s（22%）** | async 并发更快 |
| 其中 stored auto pass | 0.02–0.48s（冷/热） | 同左（线程内） | 写表单 + 回读 + 指纹差分 |
| CLI / asyncio 事件循环 / 其他 | ~0.21s（14%） | ~0.79s（46%） | async 的额外进程级开销 |
| **单例墙钟** | 1.45s | 1.72s | 10 例合计 15.9 / 19.2s |

**归因结论**：

- 扫描主体 async **更快**（0.383s vs 0.694s），因为 76 个请求并发（sync 27 个
  请求/例；async 每例约 2.8× 请求数但被并发摊薄）。
- 单例差距 0.27s 主要来自 async 的 **import + asyncio 事件循环/CLI 固定开销**，
  不是 stored 轮询串行、不是 settle 700ms 累加、不是 auth 重复建立。
- 10 例差距 3.3s ≈ 每例 0.33s，与固定启动开销一致；**没有需要改的算法热点**。
- 因此本轮**不改 async 代码**：目标 1.21× 已达成，进一步改 import/事件循环属于
  低收益高风险；若强行改，失败也要回退。

### 1.3 目标判定

| 指标 | 目标 | 本轮实测 | 判定 |
|---|---|---|---|
| async stored 墙钟 | ≤ 2× sync（≤29s） | 19.2s（1.21×） | **达成** |
| stored 召回 | 9/9 不降 | sync 9/9、async 9/9 | **达成** |
| FP | 0 | 0 / 0 | **达成** |

## 2. 靶场空位处置

### 2.1 外拉结论

- ZAP：`ghcr.io/zaproxy/zap-stable` denied；Docker Hub 镜像 TLS timeout；
  `docker.1ms.run` magic number mismatch；GitHub 连接超时；本机无安装。
  **ZAP 仍未补，原因环境不可达，未用其他工具冒充。**
- bWAPP：`docker.1ms.run/raesene/bwapp` 最终下载成功，但本轮未把它接入评分
  （自建靶已覆盖全部四个面，且 bWAPP 的默认安装/登录/header 面需要额外配置）。
- XVWA：未再重试。

### 2.2 自建靶（已登记）

新增 [selfhosted/app.py](file:///D:/qoder/xssentinel/benchmark/realworld/selfhosted/app.py)，
stdlib-only、本地 `127.0.0.1:8090`，独立于 194 例自编矩阵。

| 面 | 端点 | 证据 |
|---|---|---|
| 反射 | `/reflect?q=`（`/reflect-safe` 为转义对照） | Playwright 弹窗 `sh_token`；safe 无弹窗 |
| 存储 | `/guestbook`（SQLite insert + 原始渲染） | alice 写入，admin 与 alice 查看均弹窗 |
| 登录 + 两角色 | `admin/adminpass`（admin）、`alice/alicepass`（user） | alice 访问 `/admin` → 403；admin → 200 |
| Header 注入 | `/header` 反射 `User-Agent` / `X-Forwarded-For` | alice 会话带 payload UA → 弹窗 |

- 已登记进 `benchmark/realworld/cases.json`（`selfhosted` app + 5 例：
  `sh-reflected`、`sh-reflected-safe`、`sh-stored`、`sh-header`、`sh-root-control`）。
- 真实应用集从 13 例扩到 **18 例**，与 194 例自编矩阵分开统计。

### 2.3 realworld v2.1 对照（本次实测）

| tool | TP | FN | FP | TN | blocked | 耗时 |
|---|---|---|---|---|---|---|
| xssentinel | 10 | 0 | 0 | 8 | 0 | 92.3s |
| xssentinel-headless | 10 | 0 | 0 | 8 | 0 | 99.3s |
| dalfox v2.13.0（开源） | 3 | 3 | 0 | 8 | 4 | 203.3s |
| nuclei v3.9.0（开源） | 2 | 3 | 0 | 8 | 5 | 4.5s |
| OWASP ZAP | - | - | - | - | 18（unavailable） | 未执行 |

dalfox/nuclei 的 3 个 FN 仍是 `#` fragment 输入形状；stored/header 行为
BLOCKED。**上述开源行不是商业基线**，不得解读为优于 Burp/Acunetix。

### 2.4 自建靶带来的真实修复

`sh-header` 首轮 FN：header canary 把 `Cookie` 也放进“一次发所有 header”的
请求，覆盖了登录 cookie，`/header` 返回 401，canary 无反射 → 整层跳过。
修复：有会话 cookie 时从 header 探针列表移除 `Cookie`（Cookie XSS 有独立层）；
回归测试新增 2 项。修复后 `sh-header` 为 **TP（header_xss medium/high）**。

## 3. 权限矩阵

### 3.1 DVWA low / medium / high（同 payload，唯一 token）

| level | carrier | 反射原始值 | 反射弹窗 | 存储原始值 | 存储弹窗 |
|---|---|---|---|---|---|
| low | `<script>` | 是 | 是 | 是 | 是 |
| low | `<img onerror>` | 是 | 是 | 是 | 是 |
| medium | `<script>` | 否（strip `<script>`） | 否 | 否（strip_tags+htmlspecialchars） | 否 |
| medium | `<img onerror>` | 是 | 是 | 否 | 否 |
| high | `<script>` | 否（正则去 script） | 否 | 否 | 否 |
| high | `<img onerror>` | 是 | 是 | 否 | 否 |

结论：DVWA 的 security level 直接改变存活面——
- low：script/img 反射与存储都可执行；
- medium/high：存储的 message 走 `strip_tags + htmlspecialchars`，全部不可执行；
- 反射在 medium/high 只过滤 `<script>`，`<img onerror>` 仍可执行（high 也一样）。

证据：[dvwa_security_matrix_20261103.json](file:///D:/qoder/xssentinel/benchmark/results/dvwa_security_matrix_20261103.json)

### 3.2 Juice accounting / deluxe

- 注册新用户成功（201），登录后 JWT role 仍为 `customer`。
- `PUT /api/Users/{id}` 设置 `role=accounting|deluxe` 返回 **401**
  (`UnauthorizedError: DECODER routines::unsupported`)；该角色升级路径在
  本 Docker + unsafe 实例上不可达。
- 结论：**accounting/deluxe 未补，标注不可达**，未伪造。

## 4. 门禁复跑

| 门禁 | 结果 | 耗时 |
|---|---|---|
| 27 控制例 sync | **0 / 27 FP** | 48.9s |
| 27 控制例 async | **0 / 27 FP** | 169.8s |
| 64 例 strict sync | **36 TP / 0 FN / 0 FP / 28 TN / 0 ERROR** | 139.7s |
| 64 例 strict async | **36 / 0 / 0 / 27 + 1 SKIP** | 143.4s |

async 的 1 个 SKIP 是 manifest 声明的 sync-only `neg-stored-02`，不是回归。
未放宽任何门禁。

## 5. tracked 文件完整性

- 开工前：`git status --short | Select-String '^ D'` → **空**。
- 结束：再次执行 → **空**；`Test-Path benchmark/server.py` → **True**。
- 未发现新的 tracked 文件删除；上一轮恢复的 `benchmark/server.py` 仍在，
  `git status` 的 `M` 是 CRLF/stat 差异。

## 6. 仍未解决项

1. ZAP 不可用（环境不可达），开源对照只有 dalfox/nuclei；商业两臂仍 unavailable。
2. bWAPP 镜像虽已下载，但未接入评分；XVWA 未拉取。
3. Juice accounting/deluxe 角色升级 401，不可达。
4. async stored 绝对耗时 19.2s vs sync 15.9s（1.21×），差距来自进程启动/事件
   循环固定开销；未做低收益优化。
5. Juice 持久化反馈仍为服务端清洗（见 round3 报告），无可用 stored 面。

## 7. 产物路径

- async 归因与证据：本报告；单例请求数 27（sync）/76（async）来自
  `benchmark/results/async_stored_single_{sync,async}_20261103.json`
- 自建靶：`benchmark/realworld/selfhosted/app.py`
- 自建靶四面对照：`benchmark/results/selfhosted_faces_20261103.json`
- 真实应用 v2.1：`benchmark/realworld/results/realworld_v2.json` / `.md`
- DVWA 权限矩阵：`benchmark/results/dvwa_security_matrix_20261103.json`
- 门禁：`benchmark/results/gate_round3_{sync,async}.json`
- 本报告：`benchmark/results/round4_gap_report_20261103.md`
