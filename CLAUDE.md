# xssentinel

本文件是 `AGENTS.md` 的薄镜像,只保留工具无关的最小规则副本,供只读 CLAUDE.md 的智能体使用。**规则以 AGENTS.md 为唯一权威源**;逐 Phase 过程日志在 `docs/archive/AGENTS_phase_log_to_20261031.md`。

## 项目说明

XSS 漏洞自动化扫描器:双流水线架构(scanner Mixin 化 + advanced_layers 域拆分)、场景 DSL(Nuclei 风格声明式多步检测流)、CSP nonce 泄露自动利用链;附 benchmark 跑分与 HTML 报告。

## 硬规则(工程纪律全文见 AGENTS.md「规则约定」)

- scanner.py 已 Mixin 拆分:新增能力进对应 Mixin,不堆回主文件
- async_scanner.py 已同样 Mixin 化:新增 async 能力进对应 Mixin;**搬代码与改逻辑绝不混在同一轮**
- fix_advice.py 数据化:改建议优先改语料
- 多步检测优先写场景 DSL,而非过程式代码

## 指针

- 开发约定 / 回归靶场: `CONTRIBUTING.md`
- 优化 backlog(含明确不做清单): `docs/OPTIMIZATION.md`
- 测试: `python tests/run_all_batched.py --quiet`(裸跑单进程会卡死,必须分批)
- benchmark: benchmark/ 目录;报告产物: report.html
