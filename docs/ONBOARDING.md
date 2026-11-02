# 新维护者上手路径(ONBOARDING)

> 为"第一次接手这个仓库的人"写——AGENTS/ARCHITECTURE 是为作者自己的记忆服务的,
> 本页补的是**顺序**。读完本页约 15 分钟,照做约半天。规则与状态看
> [AGENTS](../AGENTS.md),架构与门禁看 [ARCHITECTURE](ARCHITECTURE.md),
> 贡献流程看 [CONTRIBUTING](../CONTRIBUTING.md)。

## 0. 三条主线(先建立世界观)

1. **双流水线 + Mixin**:sync `Scanner` 与 async `AsyncScanner` 共享同一批判定件,
   能力按域进 Mixin;async 经 `_AsyncScannerShim` 复用 sync 的两个 Mixin(ARCHITECTURE §1)。
2. **门禁按"变化到被发现的距离"分层**(ARCHITECTURE §2):push 64 例切片 →
   nightly 全量分批 → 异形靶场 range3–7 → 外部效度(XSSMaze / 跨工具)。
3. **测量先行**:数字必须有测量支撑;文档数字要加钉;引用门禁数字必须来自自己的运行;
   「绿」和「跑过」是两个词(报结果必须连 skip 数一起报)。

## 1. 第 0 天:环境(Windows 本机口径)

```powershell
py -3.12 -m venv .venv                    # 本机默认 python 是 3.9,项目要求 >=3.10
uv pip install --python .venv/Scripts/python.exe -e ".[dev,async,ast,api,nuclei]"
uv pip install --python .venv/Scripts/python.exe cryptography playwright
.venv/Scripts/python.exe -m playwright install chromium   # L6 真浏览器确认
.venv/Scripts/python.exe -m xssentinel --help             # 能出帮助即算装好
```

- 为什么 uv:本机 pip 通路病态(TLS 已建立但近零吞吐),uv 实测 10s(见 AGENTS「环境配置」)。
- 不装 playwright 也能跑:DOM 层自动降级为静态启发式,不影响其他层——但**别在缺依赖的
  环境里下结论**(CI 的 nightly 曾因安装面比 push 少 cryptography/playwright/chromium
  连红三天而 push 全绿,2026-11-01 修复:同一入口的两次门禁必须同依赖面,否则量的是两套套件)。

## 2. 第 0 天:确认"规则还活着"(秒级自检)

```powershell
.venv/Scripts/python.exe -m pytest tests/test_architecture_scale.py tests/test_mixin_contracts.py tests/test_quick_gate_slice.py tests/test_doc_code_counts.py -q
```

全绿(<5s)说明结构契约、文档数字闸与行数预算都在工作。这不是冒烟测试,
是确认这个仓库的门禁体系没有被静默禁用。

## 3. 本机环境陷阱(动测试前必读,全部实测过)

- 端口走 **18xxx** 段(Windows 保留 8810–9109,Phase 179);测试 fixture 用 port 0。
- 本工作区带 **Low 强制完整性标签**:Low 进程写不进 Medium 的 `%TEMP%`,
  Playwright 的 `mkdtemp()` 会全挂——conftest 装了可写 TEMP 回退;探针的两个陷阱
  (`os.access` 答 ACL 看不见标签、`tempfile.gettempdir()` 不是 %TEMP%)
  见 `tests/test_temp_probe_contract.py` 的 docstring,**改这块前先读它**。
- loopback 劣化期:失败先单文件复跑,按「未验证」记账,不当回归;
  `XSSENTINEL_FORCE_SOCKETPAIR=bad|good` 可强制复现两态。

## 4. 第 1 周:跑一次真实门禁

- 全量分批:`python tests/run_all_batched.py --quiet`
  (裸跑单进程会卡死,必须分批;约 60–80 分钟;**结果必须连 skip 数一起读**,
  整文件 skip 的门禁什么都不曾贡献——runner 会把整文件 skip 标成
  "WHOLE FILE -- contributed nothing")。
- push 精度切片:`python -m benchmark.runner --quick`
  (64 例分层切片;CI 里是双引擎 + `--strict-gate` FP0/FN0/ERROR0,并按 ISO 周轮转)。
- 行为靶场:`python range3/runner.py --engine both`(26 例,ground truth 从服务器行为独立撰写)。

## 5. 改动 → 必跑什么

速查表在 ARCHITECTURE.md §2 末尾,别背,照表跑。最容易踩的三条:

- **搬代码与改逻辑绝不混在同一轮**(Mixin 之间的搬运有 AST 契约测试守着)。
- 新增检测层必须**同时**登记 `coverage.LAYERS` 与 `layer_coverage` 矩阵
  (Phase 187/192 两次被门禁抓到的同一课)。
- 文档里新增数字声明必须**同步加钉**(切片/矩阵进 `test_quick_gate_slice`,
  REGISTRY 计数进 `test_doc_code_counts`,行数上限进 `test_architecture_scale`;
  会持续增长的清单用"去数字化"表述,没有数字就没有数字可腐烂)。

## 6. 历史去哪查

- 逐 Phase 过程日志:`docs/archive/AGENTS_phase_log_to_20261031.md`。
- README 历史叙事(基线演化/缺陷家族/自我纠正):`docs/archive/README_phase_log_to_20261101.md`。
- 优化 backlog(含「明确不做」清单):`docs/OPTIMIZATION.md`(§7 是 2026-11-01 外部评审回灌记录)。
- `benchmark/results/`:**只保留被文档引用的证据与被脚本读取的输入**;
  历史产物在 `_local_archive/`(gitignored,仅本机留档)。

## 7. 三个"为什么"(读懂它们,就读懂了这个项目的脾气)

- 为什么退出码 0 和 3 必须分开——「没测到」不能伪装成「测了没问题」:QUICKSTART §3。
- 为什么行数上限是 ceiling 而不是精确值——精确值会让门禁一周内被禁用,
  而禁用的门禁与没有门禁无法区分:`tests/test_architecture_scale.py` docstring。
- 为什么 Mixin 契约要用 AST 钉——「名字接得上」是纯机械事实,不该等运行时
  (而且是到达那条路径时)才暴露:`tests/test_mixin_contracts.py` docstring。
