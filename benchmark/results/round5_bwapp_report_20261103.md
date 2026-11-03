# bWAPP 接入与剩余缺口报告（2026-11-03）

本报告只记录**本次实测**；历史产物（`p352_sample_on.json`、`gate_p355_*`、
`realworld_v2.md` 旧版本）单独标注。未执行 commit / push。

## 1. bWAPP 接入结果

### 1.1 启动与安装

- 镜像：`docker.1ms.run/raesene/bwapp@sha256:2f41183e...2600ee`（bWAPP 2.2）
- 镜像自带 MySQL，但 DB `bWAPP` 初始不存在；页面返回
  `Connection failed: Unknown database 'bWAPP'`。
- 执行官方安装入口 `GET /install.php?install=yes` 后建库建表，页面恢复。
- 账号：`bee/bug`（admin=1）；通过官方 `user_new.php` 表单（`action=create`）
  创建普通用户 `bwuser/bwpass123`（admin=0，activated=1）。
- `security_level=0`（low）。

### 1.2 四个面（独立 Playwright 复核）

| 面 | 端点 | 证据 |
|---|---|---|
| 反射 | `/xss_get.php?firstname=<payload>&lastname=x&form=submit` | 弹窗 `bw_token` |
| 存储 | `/xss_stored_1.php`（Blog，写库） | 本人视图弹窗；bee 勾选 "Show all" 后跨会话弹窗 |
| 登录/角色 | `bee/bug`、`bwuser/bwpass123` | 两者均可登录；`bwuser` admin=0，`bee` admin=1 |
| Header 注入 | `/xss_user_agent.php` 反射 `User-Agent` | bee/bwuser 带 payload UA → 弹窗 |

存储面边界：bWAPP 默认只显示当前 owner 的 blog；bee 需要勾选 "Show all"
（POST `entry_all`）才能看到 bwuser 的条目，随后执行。这是靶的行为，不是
探针失败。

### 1.3 ground truth 对齐

bWAPP 自带 `bugs.txt` 官方漏洞清单，三条全部对齐：

| 用例 | 官方标签 |
|---|---|
| `bw-reflected` | Cross-Site Scripting - Reflected (GET), `xss_get.php` |
| `bw-stored` | Cross-Site Scripting - Stored (Blog), `xss_stored_1.php` |
| `bw-header` | Cross-Site Scripting - Reflected (User-Agent), `xss_user_agent.php` |

官方清单没有单独的 "safe" 页；控制例 `bw-portal-control` 用登录后的
`portal.php`（无攻击者输入）。

### 1.4 四工具对照（realworld v2.2，22 例）

同一命令：

```bash
python benchmark/realworld/run_realworld.py \
  --tools xssentinel,xssentinel-headless,dalfox,nuclei
```

| tool | TP | FN | FP | TN | blocked | recall | 耗时 |
|---|---|---|---|---|---|---|---|
| xssentinel | 13 | 0 | 0 | 9 | 0 | 1.000 | 95.8s |
| xssentinel-headless | 13 | 0 | 0 | 9 | 0 | 1.000 | 106.4s |
| dalfox v2.13.0（开源） | 4 | 3 | 0 | 9 | 6 | 0.571 | 133.7s |
| nuclei v3.9.0（开源） | 3 | 3 | 0 | 9 | 7 | 0.500 | 6.7s |

bWAPP 子集：xssentinel 3 TP / 0 FP / 1 TN；dalfox 1 TP（reflected）+ 2
blocked（stored/header）；nuclei 1 TP（reflected）+ 2 blocked。
dalfox/nuclei 的 3 个 FN 仍是 Juice `#` fragment 输入形状。

**开源行不是商业基线**；ZAP/Burp/Acunetix 不可用。

## 2. XVWA

只尝试一次：

```text
docker pull docker.1ms.run/sethsugar/xvwa:latest
→ not found
```

**放弃外拉，未启动，未计分。**

## 3. ZAP 最终处置

限定一轮，已用两个来源：

1. 本地 Java 方式：`java -version` = 1.8.0_202（JDK 存在）；PyPI
   `zaproxy==0.6.0` 可下载，但 wheel 只有 **74 KB**，是 API 客户端，不含
   ZAP 引擎/jar；GitHub release 仍不可达。
2. 其他镜像源：`ghcr.io` denied、Docker Hub 镜像 TLS timeout、
   `docker.1ms.run` magic number mismatch。

**永久标注 `unavailable`：环境不可达，不是工具能力问题。不再投入时间。**

## 4. Juice accounting / deluxe

- **deluxe 可达（合法应用路径）**：注册 customer → 登录 JWT role=customer →
  `POST /rest/deluxe-membership`（官方 `freeDeluxeChallenge` 路由）→ 200，
  新 JWT role=**deluxe**；随后 `GET /rest/deluxe-membership` 返回 400（已是
  deluxe）。没有改数据库、没有绕过鉴权。
- **accounting 不可达**：该版本没有 accounting 角色；
  `/rest/accounting`、`/api/Accounting` 返回 500，`/#/accounting` 只是 SPA
  路径，无角色门槛。
- 之前的 `PUT /api/Users/{id}` 401 未再使用；改用上述合法路径。

证据：`benchmark/results/juice_roles_20261103.json`

## 5. async 是否有动作

**没有动作。** 本轮洁净复测 async stored 19.2s vs sync 15.9s（1.21×），
已在 ≤2× 目标内；扫描主体 async 反而更快（0.383s vs 0.694s），差距是进程
启动/import/事件循环固定成本。没有 ≥1.5× 收益的可证明方案，故不动代码。

## 6. realworld 现状

- **22 个用例，5 个 app**：Juice Shop 匿名、Juice Shop unsafe、DVWA、bWAPP、
  self-hosted lab。
- 覆盖面：
  - 反射：Juice DOM/API、DVWA、selfhosted、bWAPP
  - 存储：DVWA guestbook、Juice 商品描述、selfhosted guestbook、bWAPP blog
  - 登录/角色：DVWA admin+user、Juice admin+customer/deluxe、bWAPP bee+bwuser、selfhosted admin+alice
  - Header：Juice `True-Client-IP`、selfhosted UA/XFF、bWAPP UA
- 与 194 例自编矩阵分开统计。

## 7. 门禁复跑

| 门禁 | 结果 | 耗时 |
|---|---|---|
| 27 控制例 sync | **0 / 27 FP** | 48.9s |
| 27 控制例 async | **0 / 27 FP** | 169.8s |
| 64 例 strict sync | **36 / 0 / 0 / 28 / 0 ERROR** | 139.7s |
| 64 例 strict async | **36 / 0 / 0 / 27 + 1 SKIP** | 143.4s |

async 的 1 个 SKIP 是 manifest 声明的 sync-only `neg-stored-02`，不是回归。
（门禁在 header Cookie 修复后复跑；bWAPP 接入只改 benchmark 文件，未改扫描器。）

## 8. 仍有空缺的格子

| 格子 | 状态 | 原因 |
|---|---|---|
| OWASP ZAP | 空缺 | 环境不可达（镜像/下载均失败），永久 `unavailable` |
| XVWA | 空缺 | 镜像源 not found，一次尝试后放弃 |
| Burp Pro / Acunetix | 空缺 | 无安装/授权 |
| Juice accounting | 空缺 | 该版本无此角色；合法路径 500 |
| Juice 持久化反馈 | 空缺 | 服务端 `sanitize-html` 入库即剥离，18 载体 0 可执行；不再投入 |
| async 绝对速度 | 部分 | 1.21× 已达标，但仍有 ~0.3s/例固定开销 |
| bWAPP medium/high | 未测 | 本轮只接 low（security_level=0），权限矩阵用 DVWA 三档覆盖 |

## 9. 本轮未提交改动清单

**修改**

- `xssentinel/core/layers/transport_layers.py`（认证会话下 header canary 排除 Cookie）
- `tests/test_phase355_transport_canary.py`（+2 回归测试）
- `benchmark/realworld/run_realworld.py`（bWAPP 登录、22 例 schema、ZAP 入口）
- `benchmark/realworld/cases.json`（v2.2，bWAPP app + 4 例）
- `benchmark/realworld/README.md`（bWAPP、22 例、ground truth）
- `tests/test_realworld_cases.py`（app 集合含 bwapp）
- `README.md`
- `benchmark/server.py`（从 HEAD 恢复，仅行尾/stat 差异）

**新增**

- `benchmark/results/round5_bwapp_report_20261103.md`
- `benchmark/results/bwapp_faces_20261103.json`
- `benchmark/results/bwapp_cross_role_20261103.json`
- `benchmark/results/juice_roles_20261103.json`
- `benchmark/realworld/results/realworld_v2.json` / `.md`（22 例重跑覆盖）
- `benchmark/results/gate_round3_{sync,async}.json`（重跑覆盖）

此前轮次全部改动保留；未执行 commit / push / git 配置修改。
