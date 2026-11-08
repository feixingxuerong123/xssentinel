# XSSMaze 抽样重跑（2026-11-07）

## 结论

**Phase 364 的 110 例抽样集，用当前树重跑：TP 107 / FN 2 / TN 1 / FP 0，
与基线逐例对比 0 差异（无回归、无新增）。**

两个 FN 是**既有漏报**，不是本轮引入：`basic/level7`、`bugbounty/level7`
在 Phase 364 的 TSV 里同样是 0 findings。

## 先更正一条错误归因（重要）

前两轮我曾把"跑不起来"归因为 **agent 沙箱 FS shim 降级**，并写进了项目记忆。
**那是错的。** 真因是**模块名拼写**：

| 写法 | 结果 |
|---|---|
| `python -m xsssentinel`（10 字符，xss+entinel） | **正常**，`xssentinel 1.4.4` |
| `python -m xsssentinel`（11 字符，多一个 s） | `No module named xsssentinel` |

`pyproject.toml` 的 `name = "xssentinel"` 与目录名都是 10 字符。前两轮的
"`isdir` False / `cd` 失败 / 四种父进程全失败"全部是**在错误的模块名上做的诊断**，
不是环境问题。诊断过程中还发现一个**真实但次要**的问题：Python 的
`sitecustomize` 会报 `No usable temporary directory`，把 `TEMP`/`TMP` 指向
`C:\Users\Administrator\.cache\xssentinel\tmp` 即可消除；它不是 import 失败的原因。

## 评分口径（决定数字怎么读）

XSSMaze 官方 runner 的检测契约是 `--detect-json 'findings[].url'`：
**只要该 endpoint 上有 finding，就算检出**，不看 severity、不排除审计类。
本次按这个口径评分，与基线可比。

另有 4 例"advisory-only"——有 finding 但只有审计/低置信类：

| URL | 当前 findings |
|---|---|
| `/apidom/level6/?q=a` | `trusted_types_no_policy`（medium） |
| `/browser-state/level3/?seed=a` | `trusted_types_taint_flow` + `trusted_types_no_policy` |
| `/callback/level1/?callback=myFunc` | `reflected`（low） |
| `/callback/level2/?callback=myFunc` | `reflected`（low） |

按官方口径它们算 TP；若改用"仅 XSS-level（high/medium/critical 且非
`csp_`/`trusted_types_`）"的严格口径，这 4 例会变成 FN（TP 103 / FN 6）。
**两种口径都记录在此，引用时必须说明用的是哪一种。**

## 环境与复现

```bash
cd /d/qoder/xssentinel
export NO_PROXY=127.0.0.1,localhost
export TEMP='C:\Users\Administrator\.cache\xssentinel\tmp'
export TMP="$TEMP"
export PYTHONPATH='D:\qoder\xssentinel'
# 逐 URL（基线的 110 例，约 6 分钟，110/110 rc=0）
bash <TEMP>/xmz_run.sh benchmark/results/xssmaze_baseline_p364_20261106.tsv \
     <raw.txt> <err.txt>
# 评分（官方口径，并与基线逐例对比）
.venv/Scripts/python.exe <TEMP>/xmz_parse.py <raw.txt> \
     benchmark/results/xssmaze_baseline_p364_20261106.tsv
```

- XSSMaze 容器：`ghcr.io/hahwul/xssmaze:main`，`127.0.0.1:3001`，Up。
  `/map/json` 实测 **1064 endpoints / server reach 1013 / client 24 / controls 27**。
- 本次只跑 **110 例抽样**（Phase 364 同集），**不是全量 1013 例**。
  全量历史基线仍是 `xssmaze_baseline_p363final_20261106.json`：
  recall 0.956565 / f1 0.977800（1013 例）；全量单次实测约 95 分钟。
- 原始产物：`xmz_raw3.txt`（1.34MB）/ `xmz_raw3.err`，在
  `C:/Users/Administrator/AppData/Local/Temp/xss_agent_e2e_20261107/`。
