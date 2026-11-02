# xssentinel

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

定位:在开源工具中做到**检测维度最全、架构最干净、最易扩展**(见 README「定位与诚实声明」)。

**文档地图**(2026-10-31 起本文件只保留规则与状态,过程日志全部归档):

| 要找什么 | 去哪 |
|---|---|
| 逐 Phase 过程日志(176f–345,每项改动的归因、门禁证据、自我纠正) | `docs/archive/AGENTS_phase_log_to_20261031.md` |
| README 历史 Phase 叙事(基线演化、缺陷家族、自我纠正;2026-11-01 蒸馏出库) | `docs/archive/README_phase_log_to_20261101.md` |
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

## 当前状态(2026-11-02)

- 版本 1.3.0;最新 Phase 349。源码 133 文件 59,076 行 / 测试 268 文件 61,216 行(接近 1:1;2026-11-02 复测)。
  Phase 347 新增四个门禁:`tests/test_architecture_scale.py`(Mixin 行数上限)、
  `tests/test_failure_reasons.py`(失败原因可见化)、
  `tests/test_temp_dir_fallback.py`(临时目录回退,11 例)、
  `tests/test_silent_except_ratchet.py`(宽泛吞异常棘轮,110 处/34 文件,只许降)。
  行数上限与吞异常棘轮两个做过变异对照(红→还原→绿),另两个靠真实入口实跑验证。
  Phase 348(2026-11-02,测试优化):分批 runner 新增 `--jobs N` 并行档(默认 1,
  顺序行为逐字节不变;每文件预算/重试/verdict/日志/耗时报告语义不变)。A/B 实测
  (11 文件头部权重抽样,2026-11-02):顺序 465s → jobs=4 124s(3.75×),逐文件
  verdict 与单文件耗时零漂移;全量投影 600–700s,**2026-11-02 全量实跑兑现 616s**
  (见下条门禁)。守卫:`tests/test_runner_parallel.py`(解析契约——畸形 `--jobs` 响亮报错——
  加双模式端到端 verdict 对比,真子进程不用替身)。`pyyaml>=6.0` 进 dev extras:
  `test_nuclei_import` 不再因缺 PyYAML 整文件跳过(单文件实跑 16 passed;
  运行期 [nuclei] extra 保持独立,那是扫描器功能不是测试依赖)。
- 最近全量分批门禁(2026-11-02,**HEAD `3b277e9`,工作树干净**):
  **268/268 文件绿,exit 0**,620s(`--jobs 4`);**skip 13 个 / 6 文件**
  (2 个整文件零贡献:`test_oracle_default_sent.py` 3、`test_stored_e2e_acceptance.py` 3)。
  引用时两个数一起报。同一工作内容的前一轮(616s)跑在未提交树上,数字相同、口径更弱;
  这一轮是提交后的复验,替换之。这是 Phase 348 并行档的首次全量实跑;
  与 Phase 346 的 258 文件 / 4554s **不是同一口径**(文件集不同、顺序 vs 并行),
  不能相除当倍数引用。
  跑之前拦下两件事,都记在这里因为它们是这次数字的前提:
  ① `benchmark/server.py` 与 `tests/vuln_server.py` 在批量清理 `benchmark/results/*`
  时被误删,6 个模块 `from server import ...` 全挂(首轮 98s 内 15 文件红,
  `ModuleNotFoundError: No module named 'benchmark.server'`),已从 HEAD 恢复;
  ② `test_scanner_parallel_checkpoint.py` 的 fixture 未传 `crawl=True`,且补上后默认
  `crawl_engine="auto"` 会派发到 `_crawl_spa()` 绕过 `_crawl` stub——四组配置对照实测
  后两参数一并补齐(只有 `crawl=True, crawl_engine="static"` 三端点才全部入账)。
- benchmark strict 64 例切片双引擎 F1=1.0。
- CI(`.github/workflows/ci.yml`):6 个 job 全部 ubuntu-latest —— tests(全量分批 + ruff)、drills(双引擎 strict 切片周轮转 + range2–6 门禁;range7 走 tests job 的 pytest 契约测试)、min-python(3.10)、benchmark-full、nightly-gate、dependency-audit;push 门 = 双引擎 strict 切片。
- 开放项:无。SECURITY.md 的举报渠道已定为 **GitHub 私密安全通告**(仓库 → Security →
  Report a vulnerability,流程与 72 小时时效已写在 SECURITY.md,无需额外邮箱即可生效);
  原「联系方式待仓库归属者填写」一项于 2026-11-01 关闭。如需增加邮箱等第三方渠道,
  由仓库归属者自行补充,不阻塞发布。产品级 backlog 无未决项
  (OPTIMIZATION.md §3.6 item 6 被动代理 drain 时间上限已于 2026-10-31 关闭;
  其余均为"有意不做/需外部条件"清单)。

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
