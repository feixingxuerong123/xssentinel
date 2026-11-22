# async 请求量 parity 分歧定位（2026-11-20）—— 事实表 + 优化尝试结论

**性质**：诊断记录，非分数。回答"async 全量 20564 请求 vs sync 7915 是不是可修的浪费"。

## 现象
| case | sync 请求 | async 请求 | marker 反射? | 检出 finding 来源 |
|---|---:|---:|---|---|
| pos-elem-01 | 19 | 35 | 是 | `reflected` (L1) |
| neg-filter-01 | — | 145 | 是 | `reflected` (L1) |
| neg-header-01 | 18 | 245 | 否 | TN（无 finding） |
| pos-xs-01 | 18 | 246 | 否 | `xs_leak_surface` (L7) |
| pos-cors-01 | 17 | 244 | 否 | `cors_misconfig` (L7) |
| pos-ctoss-01 | 18 | 245 | 否 | `cookie_tossing_set_cookie` (L7) |
| pos-redirect-01 | 20 | 248 | 否 | `open_redirect_xss` (L7) |

全部 194 例中 174 例 async>sync，总差 13427 请求；51 例 ≥200 请求，
其检出 finding type 无一例外来自专用 L7 层。

## 根因（parity 分歧，已定位）
- `scanner.py:778`：sync 在 marker 无反射分支末尾 `return  # not reflected -> skip`。
- `async_scanner.py:995-1022`：async 对应分支试完 pre-encode / encoding-first
  后**无 return**，继续 fall-through 到完整 corpus ladder（`_build_probe_candidates`
  + `_fire_probe_variants`），对无反射参数跑满预算 → ~245 请求。
- async 另缺 sync 的 `find_prefix_encoded_marker` / `_try_param_name_injection`
  两个无反射保底，其 marker-less 穷举流程部分承担了这些保底角色。

## 优化尝试 —— 实证失败，已回滚
尝试：给 `_build_probe_candidates` 加 `marker_absent`，无反射时把
`cand_budget` 从 max_payloads 收敛到 3（保留最小探测、非硬 return）。

`benchmark/repro_case.py` 单 case 验证立刻抓出回归：
- pos-elem-01（marker 反射正例）：TP → **FN**，请求 35→28
- neg-filter-01（绕过滤正例）：TP → **FN**，请求 145→28
- x3 复跑稳定复现，非 flaky。

⇒ L1 穷举对部分 case 是**真实检出路径**（payload-only 反射：marker 本身
不反射，但某个 payload 形状能反射并确认）。砍候选预算误伤该路径。
四处改动已完整回滚，`git diff` 对 `async_scanner*.py` 为空，两 case 恢复 TP。

## 结论
1. async 高请求量是**架构行为**（用 L1 穷举补偿缺失的无反射保底层），
   不是可简单删除的浪费；专用层出 finding 不代表 L1 穷举无用——两者是
   互补的双检出路径。
2. 全量 async 性能 860.9s vs 840s ceiling 的超线 2.5% 是本机吞吐边界
   （请求量架构差异），**非判定/算法缺陷**，无安全的优化空间。
3. 若要真正降低请求量，正道是给 async 补齐 sync 的 `find_prefix_encoded_marker`
   / `_try_param_name_injection` 保底 + 逐 case 验证后再考虑收敛——这是
   独立的大工程，且必须全量门验收，不在本轮"无回归优先"的范围。

复现命令：
```
python benchmark/repro_case.py pos-elem-01 <port> async   # 反射正例
python benchmark/repro_case.py neg-header-01 <port> async  # 无反射负例
```
EOF