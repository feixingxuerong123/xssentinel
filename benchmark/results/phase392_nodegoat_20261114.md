# Phase 392 / M3:OWASP NodeGoat(官方应用 + 官方种子 + 源码答案键)

OWASP NodeGoat master(官方 zip,ghfast 镜像)在 127.0.0.1 运行,官方种子账号(artifacts/db-reset.js),答案键 = 官方源码引用 + 本机 Chromium load 态对话框实测。事实表,不是 F1 跑分;不与 XSSMaze / 194 矩阵 / bWAPP / Juice Shop 并列。

| key | 投递页 | 字段 | oracle(load 态) | 预期 | 对话框 | 源码依据 |
|---|---|---|---|---|---|---|
| V1-lastname-attr-breakout | /profile | lastName | exec | exec | ['841'] | server.js:135-137 autoescape:false + app/views/profile.html:45 value="{{lastName}}" |
| V2-ssn-attr-breakout | /profile | ssn | exec | exec | ['842'] | app/views/profile.html:49 value="{{ssn}}" (same autoescape:false) |
| V3-bankacc-attr-breakout | /profile | bankAcc | exec | exec | ['843'] | app/views/profile.html:57 value="{{bankAcc}}" |
| V4-address-attr-breakout | /profile | address | exec | exec | ['844'] | app/views/profile.html:66 value="{{address}}" |
| V5-updateerror-reflection | (POST response) | lastName(Reflect) | exec | exec | ['841'] | app/routes/profile.js invalid-bankRouting path re-renders user input + app/views/profile.html:24 {{updateError}}; fields re-rendered raw |
| V6-memos-marked | /memos | memo | inert | adjudicate | - | app/views/memos.html {{ marked(doc.memo) }} + server.js:126-129 marked sanitize:true -- survival is measured, not assumed |
| V7-firstname-href-jsuri | /profile | firstName | inert | activation-load-inert | - | app/routes/profile.js:21-25 official FIXME: HTML-encoded in URL context -> javascript: survives; needs click (activation) |

## 控制页

- ctl-profile-benign: oracle=inert
- ctl-memos-benign: oracle=inert

## XSSentinel 端到端(rc=0,6.6s)

| url | layer | severity | evidence |
|---|---|---|---|
| http://127.0.0.1:20506/profile | dom | medium |  |
| http://127.0.0.1:20506/profile | trusted_types_no_policy | medium |  |
| http://127.0.0.1:20506/profile | svg_xss_svg_script | medium |  |
| http://127.0.0.1:20506/memos | dom | medium |  |
| http://127.0.0.1:20506/memos | trusted_types_no_policy | medium |  |

## 第三方工具事实表(只记事实,不算分)

| tool | page | detected | hits | seconds | error |
|---|---|---|---|---|---|
| dalfox | /profile | False | 0 | 1.7 |  |
| dalfox | /memos | False | 0 | 1.5 |  |
| nuclei | /profile | False | 0 | 0.6 |  |
| nuclei | /memos | False | 0 | 0.4 |  |

边界:FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 rule): third-party tools got a cookie, not an execution-level oracle, and budgets differ.

## 不可比项

- 本表不与 XSSMaze(官方靶+官方 scorer,唯一 F1 来源)、194 矩阵、bWAPP、Juice Shop 的任何数字并列;population 只有 7 个投递形状,不构成任何率
- V6 的 marked sanitize 存活与否是测量结论,官方文档自认 sanitize 不充分——不据此宣称 marked 有/无洞
- V7 是 activation 形状(load 态必然 inert),不计入未检出
- 第三方工具行是事实表:dalfox/nuclei 拿到的是会话 cookie,不是执行级 oracle,预算也不同(Phase 380 规则)
- 本轮向靶场写入 1 条 memo(不可删)+ 多次 profile 覆写,状态已披露

