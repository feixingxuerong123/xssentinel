# DVWA 全等级打穿实测（2026-11-18）

## 结论先行

**打穿了**：DVWA 的 low / medium / high 三档，XSSentinel 每档都至少检出
一个高危 XSS 面；扫描器给出的 7 个 XSS finding 的**自身载荷**全部在真实
Chromium 中复现弹窗（7/7），零 XSS 误报。medium/high 已死的
`mtxMessage` 面没有被误报。

两个必须同时说明的限定：

1. 默认扫描（不带 `--headless`）的 finding 证据等级是
   `browser-unavailable`——扫描器自己没验证执行，执行确认来自本轮的
   独立 Playwright 回验。
2. 带 `--headless` 反而把同一真阳性标成 `browser-refuted`（low）。根因是
   扫描器 headless 重放**没有把会话 Cookie 注入浏览器上下文**（详见 §5）。
   这是产品缺口，不是靶场结论。

## 1. 靶场（真 DVWA，不是自建替身）

- 源码：`C:/pentest-targets/DVWA`（git `d45ba3c4`，2026-05-30）
- Web：`http://127.0.0.1:8080`，phpStudy Apache 2.4.39 + PHP 7.3.4
- DB：phpStudy MySQL 5.7.26，库 `dvwa`，登录 `admin/password`
- 新增站点配置：`D:/phpstudy_pro/Extensions/Apache2.4.39/conf/vhosts/dvwa_8080.conf`
- 修复旧配置：`C:/pentest-targets/DVWA/config/config.inc.php` 原文件缺
  `MYSQL`/`SQLITE` 常量与 `SQLI_DB`，新版代码登录时报 undefined constant；
  按官方 `config.inc.php.dist` 重建（root/root、default low），原文件备份为
  `config.inc.php.bak`（仍是旧版内容，未覆盖）。
- 切档通过真实 `security` cookie（已用 `security.php` 页面的
  `Security level is currently: <em>…</em>` 逐档确认生效）。

Docker daemon 未运行、WSL 被本机安全策略拉黑，因此没有用容器版；这里是
真 DVWA PHP 源码 + 官方数据库结构，不是模拟靶。

## 2. 独立真值（不依赖扫描器）

`benchmark/realworld/dvwa_live_probe.py` 逐档注入唯一 token 的
`<script>` 与 `<img onerror>` 载荷，HTTP 检查原文回显 + Playwright 监听
dialog；每个存储用例先清空 guestbook 避免历史 payload 污染。事实表：
`benchmark/results/dvwa_live_groundtruth_20261118.json`。

| 档 | 反射 `name` | 存储 `mtxMessage` | 存储 `txtName` |
|---|---|---|---|
| low | script ✅ / img ✅ | script ✅ / img ✅ | script ✅ / img ✅ |
| medium | script ❌ / img ✅ | script ❌ / img ❌ | script ❌ / img ✅ |
| high | script ❌ / img ✅ | script ❌ / img ❌ | script ❌ / img ✅ |

medium/high 的 `mtxMessage` 走 `strip_tags + htmlspecialchars`，确实死了；
但 `txtName` 只过滤 `<script>`（high 用正则去 script），渲染时原样输出，
所以 `<img onerror>` 仍可执行。**历史报告
`round4_gap_report_20261103.md` 的"medium/high 存储全灭"只测了
`mtxMessage`，漏了 `txtName`**，本轮修正。

## 3. 扫描结果

命令形状（每档每面一次，`security=<level>; PHPSESSID=<sid>` 经 `-b` 传入）：

```bash
python -m xssentinel -u "http://127.0.0.1:8080/vulnerabilities/xss_r/?name=xssprobe" \
  -f json -o REPORT --progress none --log-level error \
  --max-payloads 14 --max-transforms 12 --threads 2 --timeout 10
# 存储面另加 --stored-inject/--stored-view/--stored-method POST \
#   --stored-param {mtxMessage|txtName} --stored-extra …
```

| 档 / 面 | XSS finding | 载体 / 参数 | 独立回验 |
|---|---|---|---|
| low 反射 | 1 × high | `<img/src="x"/onerror=…>` @ `name` | ✅ dialog |
| medium 反射 | 1 × high | 同上 @ `name` | ✅ dialog |
| high 反射 | 1 × high | 同上 @ `name` | ✅ dialog |
| low 存储 message | 1 × high | @ `mtxMessage` | ✅ dialog |
| low 存储 name | 1 × high | @ `txtName` | ✅ dialog |
| medium 存储 message | **0** | 死面，正确不报 | — |
| medium 存储 name | 1 × high | @ `txtName` | ✅ dialog |
| high 存储 message | 0 个 XSS | 仅 1 条 `trusted_types_no_policy`(medium) | — |
| high 存储 name | 1 × high | @ `txtName` | ✅ dialog |

报告：`benchmark/results/dvwa_scan_{low,medium,high}_{reflected,stored_*}_20261118.json`。
回验事实表：`benchmark/results/dvwa_live_finding_replay_20261118.json`（7/7 dialog=true）。

`trusted_types_no_policy` 是可达性提示类审计项，不是 XSS finding，按项目
detection contract 不计入 TP/FP。

## 4. 载荷自证（不是只信 severity）

`benchmark/realworld/dvwa_finding_replay.py` 从每份扫描 JSON 里读出
`findings[].payload` 原样重放（反射走 `poc.url`，存储先清空留言板再
POST），带同一认证会话，用真实 Chromium 监听 dialog：

```
low    reflected  param=name         dialog=True ['xssv_e3ecac42']
low    stored_mtxMessage param=mtxMessage dialog=True ['2928012899']
low    stored_txtName    param=txtName    dialog=True ['8146476675']
medium reflected  param=name         dialog=True ['xssv_22dabcc1']
medium stored_txtName  param=txtName    dialog=True ['2322871109']
high   reflected  param=name         dialog=True ['xssv_dd234eda']
high   stored_txtName  param=txtName    dialog=True ['2227714830']
```

## 5. 真缺口：`--headless` 对认证靶场假阴性

`dvwa_scan_high_reflected_headless_20261118.json` 中同一高危 finding 的
`headless` 字段是 `{available: True, confirmed: False, outcome: "not-fired",
detail: "no dialog"}`，`evidence_class` 降为 `browser-refuted`。

对照实验（同一 URL、同一 payload
`<img/src="x"/onerror=alert('xssv_58f47aff')//>`）：

| 条件 | 结果 |
|---|---|
| 注入 `security=high` + `PHPSESSID` 的浏览器上下文 | dialog `['xssv_58f47aff']`，HTML 见 `<pre>Hello <img src="x" onerror="alert(…)"></pre>` |
| 不注入 cookie | 被重定向到 `login.php`，dialog `[]` |

根因定位：`xssentinel/core/verifier.py:1584` 的 `verify_headless()` 签名里
**没有 cookies 参数**；调用方（`core/scanner.py:1468/2319/2442`）只传
`headers=dict(session.headers)`，而 requests 的会话 Cookie 存在
`session.cookies`、不在 `session.headers` 里。浏览器 `browser.new_page()`
拿到的是无会话上下文。同一族问题："同一契约手写两遍"——HTTP 侧有
认证，浏览器重放侧没有。

修法方向（本轮**未改产品代码**，不擅自扩大改动面）：给
`verify_headless()` 增加 cookies 入参，在 `new_page()` 后用
`page.context.add_cookies([...])` 注入 `session.cookies`；补守卫断言三个
调用点都传了 cookies，且用带登录门槛的真实靶场做 headless 回归。

## 6. 本轮未做

- 未跑 async 引擎（只跑 sync）；未跑 64/192 strict gate / 全量分批门——
  本轮没有改产品代码，只新增靶场探针脚本与证据文件。
- 未测 DVWA `impossible` 档（不是"全等级"通常指的三档；该档按 DVWA 设计
  应不可利用，另轮可做对照）。

## 7. 产物

- 本报告：`benchmark/results/dvwa_all_levels_20261118.md`
- 真值：`benchmark/results/dvwa_live_groundtruth_20261118.json`
- 载荷回验：`benchmark/results/dvwa_live_finding_replay_20261118.json`
- 扫描报告：`benchmark/results/dvwa_scan_*_20261118.json`（9 份）
- 脚本：`benchmark/realworld/dvwa_live_probe.py`、
  `benchmark/realworld/dvwa_finding_replay.py`
- 会话：`benchmark/results/dvwa_live_cookie_20261118.txt`（仅本机靶场会话）
