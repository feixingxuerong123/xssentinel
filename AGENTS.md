# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

定位:在开源工具中做到**检测维度最全、架构最干净、最易扩展**(见 README「定位与诚实声明」)。

**文档地图**(2026-10-31 起本文件只保留规则与状态,过程日志全部归档):

| 要找什么 | 去哪 |
|---|---|
| 逐 Phase 过程日志(176f–345,每项改动的归因、门禁证据、自我纠正) | `docs/archive/AGENTS_phase_log_to_20261031.md` |
| README 历史 Phase 叙事(基线演化、缺陷家族、自我纠正;2026-11-01 蒸馏出库) | `docs/archive/README_phase_log_to_20261101.md` |
| Phase 350–356 轮次报告(345 之后的逐轮实测数字与归因) | `benchmark/results/round2..round5_*_20261103.md`、`zap_unavailable_20261103.md` |
| 开发约定 / 回归靶场 / 架构约定 | `CONTRIBUTING.md` |
| 门禁体系如何运作 / Mixin 隐式契约 | `docs/ARCHITECTURE.md` |
| 优化 backlog(含明确不做清单) | `docs/OPTIMIZATION.md` |
| 安装、使用、能力清单 | `README.md` |
| 新维护者上手路径(第一周怎么跑) | `docs/ONBOARDING.md` |

## 规则约定

### 架构硬规则

- scanner.py 已 Mixin 拆分(2026-11-01 实测:核心 2246 行 + layers 936 + crawl 483 + stored 982 + findings 377):新增能力进对应 Mixin,不堆回主文件。**行数上限由 `tests/test_architecture_scale.py` 钉住**(核心 2400 / layers 1050 / crawl 550 / stored 1100 / findings 450);超限只有两条路——拆,或显式抬预算并在提交信息里写明理由。上一版(2026-10-05)的实测数字是 1869/769/406/579/216,即四周内核心涨了 20%、stored 涨了 70% 而无人报警,这就是把数字改成上限的理由:被测量的规则才是规则
- async_scanner.py 已同样 Mixin 化(2026-11-01 实测:核心 1434 行 + layers 2148 + crawl 588 + verify 119 + common 490,Phase 191):新增 async 能力进对应 Mixin,不堆回主文件;**搬代码与改逻辑绝不混在同一轮**。上限同由 `tests/test_architecture_scale.py` 钉住(1600 / 2350 / 650 / 145 / 520)
- fix_advice.py 数据化(2026-10-05 实测:127 行引擎 + JSON 语料):改建议优先改语料
- 多步检测优先写场景 DSL,而非过程式代码

### 工程纪律(从 300+ 个 Phase 的实测教训蒸馏;完整论证见归档对应段落)

**测量先行**

- 让判定有测量支撑,而不是让基准更好看;**没量过的东西不进门禁,量过是不需要的更不该进代码**。
- 引用门禁数字必须来自自己的运行;「最新的目录」不是「我的目录」,证据先确认归属;证据不存在时删掉佐证,不找现成的顶上(Phase 201 续十二)。
- 「绿」和「跑过」是两个词:引用门禁结果必须同时给出跳过数(`env_gated_tests`);整文件 skip 的门禁什么都不曾贡献(Phase 201 续十三)。
- 零永远不是通过:`passed==0 and failed==0` 必须单列成独立 verdict,不能落进 `failed==0` 的分支;没有摘要行 ≠ 没有失败(归档「五条新规则」)。

**测试与守卫**

- 变异对照:先断言文本存在再变异(找不到就 ABORT,绝不「跑一遍看看」),跑 baseline/mutated/restored 三遍,只有 mutated 红且 restored 绿才算数(Phase 201 续三)。
- 守卫空转的五种失效形状:测了表示没测被测物 / 对照集用并集 / 只测单向漂移 / 凭信念列名单 / 集合本身可增删无告警(Phase 201 续四~七)。
- 探针必须调**真实入口**,不是听起来合理的那个;替身保真度要量——替身能响应真实代码不可能发出的调用,是最危险的假绿(Phase 201 续二)。
- 清单分散在 N 处时,缺的不是细心,是把它们钉在一起的测试;判据收窄到「两边都认」,不引入豁免名单;反证要用真的检测函数跑(Phase 207「三条可复用规则」)。

**文档刻度**

- 文档里的数字必须与代码一致:`tests/test_quick_gate_slice.py` 钉住切片/矩阵数字,新增数字声明时同步加钉;历史数字允许留在带日期的记录里,不允许以现在时出现(Phase 190)。

**层注册**

- 新增检测层必须**同时**注册 `coverage.LAYERS` 与 `layer_coverage` 矩阵(Phase 187/192 两次被门禁抓到的同一课)。

## 当前状态(2026-11-04)

- 版本 1.3.0;最新 Phase 356。源码 135 文件 60,309 行 / 测试 274 文件 62,159 行
  (2026-11-04 复测)。Phase 350(`757e58f`)已提交;351–356 为 2026-11-03 至
  11-04 的一轮,过程记录在 `benchmark/results/round2..round5_*_20261103.md`
  与 `zap_unavailable_20261103.md`,本文件只留结论。门禁体系不变:Phase 347
  四门禁 + Phase 348 并行档(`--jobs 4`),机制见 `docs/ARCHITECTURE.md`。
- 本轮落地的能力(全部带回归,数字与归因见上列报告):
  - **Phase 352** 存储自动发现独立 Mixin(`scanner_stored_auto.py` +
    `stored_discovery.py`),官方靶 stored 自动发现 sync 9/9、async 9/9、FP 0;
    `--stored-auto` 为 sync 默认(显式 `--stored-inject` 时让位);行数走
    「拆新 Mixin」不走抬预算;死目标上熔断器正确早停(2026-11-04 门禁日志实测)。
  - **Phase 354** DOM 静态层精度收敛:AST 优先(esprima 跨语句污点链)、正则
    兜底;5 类真实框架写法(title/aria-label/.attr('title')/.val/appendChild)
    不再报 medium,真 sink(innerHTML/document.write/attr('href')/
    setAttribute('onclick'))保留;DVWA guestbook 页实测 120 low /
    0 medium-high,low 一律不进告警。边界明示不假装解决:计算属性名、跨语句
    对象身份、外部 bundle(归浏览器臂)。守卫:`tests/test_dom_static_precision.py`、
    `tests/test_dom_source_gate.py`。
  - **Phase 355** 认证会话下 header canary 排除 Cookie(`transport_layers.py`);
    `tests/test_phase355_transport_canary.py` 14 例。
  - **Phase 356** marker forms:同一注入点先按引号形态 fan-out,一发 plain 探针
    命中即返回(addslashes 杀单引号形态,杀不了裸/双引号/反引号);unquoted
    形态用 sha1 派生的 10 位数字别名(`verifier.numeric_alias`),stored 路径
    每个 (form, transform) 对发新 token。守卫:`tests/test_phase356_marker_forms.py`。
- 真实应用回归集 v2.2(22 例 / 5 app:Juice Shop 匿名+unsafe、DVWA、bWAPP、
  自建四面靶):xssentinel **13 TP / 0 FP / 9 TN,recall 1.000**;dalfox 0.571、
  nuclei 0.500(开源对照,3 FN 均为 Juice `#` fragment 形状;**非商业基线**)。
  bWAPP 双角色三面(官方 `bugs.txt` 对齐);多角色:DVWA 三档矩阵、Juice
  customer→deluxe 走官方 `freeDeluxeChallenge` 路由(合法可达;accounting 该
  版本不存在)。结论已定不再投入:Juice 持久化反馈(服务端 `sanitize-html`
  入库即剥离,18 载体 0 可执行)、ZAP(环境不可达,永久 `unavailable`)、
  XVWA(镜像源 not found,一次放弃)、async 提速(洁净复测 19.2s vs 15.9s
  = 1.21×,≤2× 达标不动代码;旧 101.1s/7× 为受污染测量,不混算)。
- 成熟度:`pyproject.toml` 降 **Beta**(理由注释在文件内);README 增
  「已具备/尚未具备/适用边界」实测口径声明。
- **门禁拦下的三件事(2026-11-04 全量门禁与单文件复跑实测)**:
  ① `test_architecture_scale.py`:scanner.py 2438>2400、scanner_stored.py
  1107>1100。按预算表自身约定(ceiling = 实测 + ~10%,历史校验
  2400/2246=+6.9%、1100/982=+12%)抬至 **2650 / 1200**,理由钉在 BUDGETS
  注释:marker-form fan-out 在 `_try_payload` 内部,方法的一半搬不走;
  `_detect_quote_escaping` 与 `_probe_reflection_profile` 同族同文件——拆半
  方法=改写本轮新逻辑,违反「搬代码与改逻辑绝不混在同一轮」。
  ② `test_layer_registry_parity.py` + `test_coverage_matrix_parity.py`:
  Phase 356 新层 `L1_marker_forms` 只注册了 `coverage.LAYERS`,漏了
  `benchmark/layer_coverage.py` 矩阵——Phase 187/192 同一课第三次触发,两处
  已同时注册。
  ③ `test_stored_matrix_cost.py`:stored 路径开始提交 numeric 别名形态
  (`alert(4856344953)`,无 `xssv_` 前缀)。核实该形态**可确认**——别名就是
  `stamp_form` 记录的 effective token,`verify_semantic` 子串匹配、浏览器臂
  对话通道(dom_engine Phase 226)都按数字匹配;是守卫的 `xssv_` 正则比新
  行为窄。守卫改为认「`xssv_` token 或 10 位数字别名」两种可确认形态,对
  mangled token 的牙齿不变(被改坏变体不会凭空出现 10 位数字串);总成本
  仍由同文件 ≤520 预算测试钉住。
- benchmark strict 64 例切片双引擎 F1=1.0(async 的 1 个 SKIP 是 manifest
  声明 sync-only 的 `neg-stored-02`);27 控制例双引擎 0/27 FP。
- 最近全量分批门禁(2026-11-04 凌晨,本树,`--jobs 4`;当晚机器持续抖动,
  四轮中以此轮为引用口径):**271/274 文件 in-gate 绿,exit 3**,1412s;
  **skip 69 个 / 18 文件**(5 个整文件零贡献)。3 红全是环境形态(TIMEOUT×2
  撞 per-file 1080s 预算 + fixture ReadTimeout),单文件复跑全绿且快:
  `test_phase196_csp_delivery` 21 passed/10.3s、`test_phase193` 10
  passed/17.9s、`test_sitemap_input` 9 passed/11.6s。合计 **274/274 文件绿**
  (271 in-gate + 3 单跑),引用时两组数一起报。前一轮 272/274 受 vuln-agent
  并发污染不引用;另有一轮 runner 本体无总结退出(exit 1、无 _timings,
  stderr 未捕获,当晚仅一次)。与 2026-11-02 的 268 文件/620s/13 skip
  **不是同一机器状态**,不作商引用。
- CI(`.github/workflows/ci.yml`):6 个 job 全部 ubuntu-latest —— tests(全量分批 + ruff)、drills(双引擎 strict 切片周轮转 + range2–6 门禁;range7 走 tests job 的 pytest 契约测试)、min-python(3.10)、benchmark-full、nightly-gate、dependency-audit;push 门 = 双引擎 strict 切片。
- 开放项:无。SECURITY.md 的举报渠道已定为 **GitHub 私密安全通告**(仓库 → Security →
  Report a vulnerability,流程与 72 小时时效已写在 SECURITY.md,无需额外邮箱即可生效);
  原「联系方式待仓库归属者填写」一项于 2026-11-01 关闭。如需增加邮箱等第三方渠道,
  由仓库归属者自行补充,不阻塞发布。产品级 backlog 无未决项
  (OPTIMIZATION.md §3.6 item 6 被动代理 drain 时间上限已于 2026-10-31 关闭;
  其余均为"有意不做/需外部条件"清单)。
- 环境事件(2026-11-04 凌晨):① 邻项目 `D:\qoder\vuln-agent` 同时段并发
  跑自己的测试批(污染一轮门禁,该轮不引用);② 负载抖动贯穿夜间——同一
  文件单跑 2.2s~176s、门禁内可 1080s×2 超时,skip 数 59→69→134 随 conftest
  探针摆动,失败一律按劣化期协议单文件复跑定论、不当回归(`test_batch_input`
  拒连红即此形态,复跑 5.4s 全绿);③ 出现一个外部迷你 runner(00:45 /
  02:23 两次,各 1s,只跑 `test_quick_gate_slice` + `test_doc_code_counts`,
  0 失败,来源未确认,疑似另一个会话的观察进程);④ runner 本体一次无总结
  退出(exit 1,见上条);⑤ `benchmark/server.py` 二度被外部进程删除后恢复,
  来源仍未确认,再现时用 `git show HEAD:benchmark/server.py` 恢复。

## 环境配置

- 本机装依赖走 **uv**(`uv pip install --python .venv/Scripts/python.exe ...`):
  2026-10-31 实测 pip 通路病态(TLS 已建立但近零吞吐,2MB 自升级 15min /
  461s CPU 空转,同址 curl 1s 可达;直连与清华镜像同病),uv 10s 完成。
  venv 建法照旧 `py -3.12 -m venv .venv`(默认 `python` 是 3.9,项目已弃)。

- 依赖: requirements.txt;测试: `python tests/run_all_batched.py --quiet`(裸跑单进程会卡死,
  必须分批;runner 对个别慢文件带 per-file 超时 override,失败/重试才写日志)。
  **日常全量门禁加 `--jobs 4`**:2026-11-02 实测 268 文件 616s(顺序档 1 保留为默认,
  两档逐文件 verdict 一致;并发只换墙钟,不改判定)。
  2026-10-31 实测 258 个 test_*.py 文件 / 59289 行;本机 loopback 劣化期的失败先单文件复跑,
  按「未验证」记账而不是当回归(2026-10-05 实测形态,归档 Phase 201 有完整归因)。

- benchmark: benchmark/ 目录;报告产物: report.html;strict 切片产物在 `benchmark/results/`。

- 三方对照(dalfox / nuclei)本机可跑:`go install github.com/hahwul/dalfox/v2@latest`
  经 goproxy.cn 构建到 `$GOPATH/bin`(本机为 `C:\GoWorkspace\bin`),nuclei v3.9.0 与
  `~/nuclei-templates/dast` 已在位;github.com 的 release 资产下载仍被拦(v3 Rust 版装不上)。
  跑法见 README「同类开源扫描器同靶跑分」一节;产物 `benchmark/results/phase196_cross_tool.json`。

- 本机 Windows 侧环境事实:端口走 **18xxx 段**(Windows 保留段 8810-9109 教训,Phase 179);
  测试 fixture 用 port 0;loopback 健康度由 `tests/conftest.py` 的 socketpair/loopback 探针
  决定(可用 `XSSENTINEL_FORCE_SOCKETPAIR=bad|good` 强制),劣化时测试按门禁跳过而非假绿。

- **完整性标签(Phase 346 实测)**:本工作区树带 **Low 强制完整性标签**
  (`icacls` 见 `Mandatory Label\Low Mandatory Level`,`.venv` 与其中全部 `.exe` 同),
  Windows 会把它传给子进程 —— **Low 进程写不进 Medium 的 `%TEMP%`**。三解释器对照:
  树外 `python.exe` = HIGH 可写;同一 exe 复制进树 = LOW 拒写;同副本
  `icacls /setintegritylevel Medium` = 可写。后果是 Playwright 的
  `tempfile.mkdtemp()` 全挂(真浏览器测试必红)。
  `tests/conftest.py` 因此装了**可写 TEMP 回退**(仅在 `%TEMP%` 真不可写时启用,
  落到 `tests/_pytest_tmp/`,已 ignore)。
  **探针有两个陷阱,都实测过**:`os.access(W_OK)` 答 ACL、看不见标签;
  `tempfile.gettempdir()` 不是 `%TEMP%`(Python 自己回退到 CWD,而 node driver 直接读
  `TEMP` 环境变量)。改这块前先读 `tests/test_temp_probe_contract.py` 的 docstring。
