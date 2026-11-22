# 竞品测试载荷 -> 我方判定保真度（事实表，非 F1）

- tree: `3b2d105` / 生成: 2026-11-20 14:48:31
- question: 第三方扫描器自己发布的 XSS 载荷，在真实 Chromium 里**实际执行**的，我方 verify-gate 分类器是否也判 live？
- pages: 1884 (157 向量 × 12 上下文)

> 只读事实表：不是 recall/F1，不与自建 194 矩阵、XSSMaze 分数并列。外部语料≠官方答案键，oracle 只看 load 态对话框。

## 控制页（oracle/判定器自检）

| id | oracle | sandbox |
|---|---|---|
| ctl-svg-onload | exec | live |
| ctl-img-onerror | exec | live |
| ctl-script-plain | exec | unknown |
| ctl-autofocus | exec | live |
| ctl-srcdoc | exec | live |
| ctl-attr-breakout | exec | live |
| ctl-benign-text | inert | inert |
| ctl-benign-attr | inert | inert |
| ctl-benign-script | inert | unknown |

## 总览

| direction | count |
|---|---:|
| agree_live | 145 |
| missed | 0 |
| overstated | 2 |
| activation_inert | 56 |
| agree_inert | 1518 |
| unknown_on_exec | 45 |
| unknown_on_inert | 118 |
| oracle_error | 0 |
| sandbox_error | 0 |

- understatement (exec 但我方 inert): 0.0 （分母 oracle_exec=190）
- overstatement (inert 但我方 live): 0.0012 （分母 oracle_inert=1638）

## 按竞品

| 竞品 | exec | agree_live | missed | unknown_on_exec | overstated | inert |
|---|---:|---:|---:|---:|---:|---:|
| dalfox | 154 | 119 | 0 | 35 | 0 | 655 |
| nuclei | 0 | 0 | 0 | 0 | 0 | 24 |
| xsser | 17 | 11 | 0 | 6 | 0 | 456 |
| xsstrike | 19 | 15 | 0 | 4 | 2 | 503 |

## 抽样与归属

- **dalfox**: candidates=69, selected=69
    - `dalfox:src/payload/xss_html.rs@9bc028930ce2`
    - transform: {JS}->alert(941); {CLASS|ID}->x
- **nuclei**: candidates=2, selected=2
    - `nuclei-templates:dast/vulnerabilities/xss/dom-xss.yaml@bb1a55098137`
    - `nuclei-templates:dast/vulnerabilities/xss/reflected-xss.yaml@f2b84b2f0585`
    - transform: rand_int/first -> 951
- **w3af-tests**: candidates=0, selected=0
    - note: unit-test file references external moth/WAVSEP targets; no inline payload literals to feed a reflection harness
- **xsser**: candidates=1399, selected=40
    - `XSSer:core/fuzzing/vectors.py@b43d70de8fb1`
    - transform: PAYLOAD -> alert(931)
- **xsstrike**: candidates=46, selected=46
    - `XSStrike:core/config.py@c26c302c125c`
    - transform: verbatim

## 边界与不可比

- w3af 的 test_xss.py 单元测试引用外部 moth/WAVSEP 靶站,本机无该靶场 -> 无可内联 payload 可喂反射 harness,仅记录为资产形态差异
- nuclei CSP-bypass 模板的多数 payload 依赖外部 CDN (angularjs.org 等),oracle harness 路由屏蔽外网 -> 这类向量不计入一致性分母
- XSSer 大量向量明确标注 IE6/IE7 专属,在 Chromium 148 天然 inert; oracle=inert + sandbox=inert 是正确一致,不代表向量无价值
- 竞赛单元测试代码(Java/Python/Rust)测的是竞品自身实现,不能在本项目执行;只做契约对照,不产出我方分数

## 逐例（missed / overstated，最多 30 行）

| id | ctx | esc | vector (前 90 字符) | oracle | sandbox |
|---|---|---|---|---|---|
| xsstrike-007__text | text | False | `<iMg sRc=x:confirm`` oNlOad=eval(src)>` | inert | live |
| xsstrike-007__iframe_srcdoc | iframe_srcdoc | False | `<iMg sRc=x:confirm`` oNlOad=eval(src)>` | inert | live |
