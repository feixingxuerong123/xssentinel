# Phase 369：链接 scheme 契约收敛（2026-11-08）

> 本轮起点是「继续修复上一轮列出的未修缺口」。第一件事是**纠正那份清单**：
> 其中大半不是缺口。以下先给更正，再给真正修掉的东西。

## 一、上一轮清单的更正（重要）

| 上一轮列为"待接线" | 实测结论 |
|---|---|
| `upload_probe.py:147/257`、`async_scanner_layers.py:930/1012` | **不是缺口**。上游 `_first_url_with()`（`upload_probe.py:69`）已有前缀白名单 `("/", "http://", "https://", "./", "../")`，危险 scheme 根本进不了 `urljoin`。接线是纯装饰。 |
| `async_scanner_crawl.py:531` | `scan_url = urljoin(link, fu.path or "/")`，只用路径部分，安全。 |
| `client_layers.py:339` | 已有 `http(s)://` / `/` 前缀白名单，其余跳过。 |
| `verify_fix.py:230-243` | 用 `quote()` 拼进原 http URL 的 path，安全。 |
| `async_scanner_common.py:507` 黑名单 | 下游 `async_scanner_crawl.py:290` 有 `netloc != origin` 兜底；`scanner_crawl.py:296` 同理。危险 scheme 的 netloc 为空会被挡。 |

**教训**：那份清单来自静态扫描，没验证上下游已有防线。接线前必须读完整
调用链，否则就是"为修而修"——正好是前几轮批评过的空转守卫。

## 二、真正的缺陷：两侧各写一份黑名单且已漂移

```
sync  scanner_crawl.py:294        skip ("#", "javascript:", "mailto:", "tel:", "data:")
async async_scanner_common.py:507 skip ("#", "javascript:", "mailto:")
async form action (:512)          skip ("javascript:", "mailto:")   ← 连 "#" 都不挡
```

- async 漏 `tel:` / `data:`；两侧都漏 `vbscript:` / `blob:` / `file:` /
  `about:` 以及大小写、Tab 变形。
- 这是**「同一契约手写两遍」**家族的又一处，与 Phase 367/368 同源。

### 修法：一个定义 + 白名单

`xssentinel/core/url_safety.py` 新增 `is_crawlable_link(base_url, href)`：
复用 `is_safe_redirect` 的「先 `urljoin` 再白名单 `{http, https}` + netloc」，
另显式排除空 href 与纯 `#fragment`（两个引擎原本都跳过）。

三处调用点全部改为调它，**黑名单字面量清零**：

| 文件 | 改动 |
|---|---|
| `xssentinel/core/url_safety.py` | `+ is_crawlable_link` |
| `xssentinel/core/scanner_crawl.py` | import + 1 处过滤 |
| `xssentinel/core/async_scanner_common.py` | import + 2 处过滤（a href / form action） |
| `tests/test_link_scheme_contract.py` | 新增 39 例 |

对合法链接（相对、绝对、协议相对、`?query`、`#` 之外的片段）行为不变；
新挡的是原本只能靠下游 `netloc` 隐式兜底的危险 scheme。

## 三、证据链

| 环节 | 结果 |
|---|---|
| 红测（修前） | **12 failed**：8 个危险 href 真的进了 async 爬队列 + 4 个源码断言 |
| 修后 | **39 passed** |
| 变异对照 | 变异**调用点**（async 过滤改回旧黑名单）⇒ **红 9 例**；restored 39、字节哈希一致 ⇒ PASS |
| 回归组 | **211 passed**（含 `test_async_deep.py` 原有 link 测试、SPA/爬取、egress、Phase 368 守卫等 14 个文件） |
| ruff | `All checks passed` |
| 四档门禁 | quick sync 64 / quick async 64 / full sync 194 / full async 194 **全部 exit 0，FP0 FN0 ERROR0**（SKIP 0 / 1 / 0 / 12） |

源码断言钉住：两侧都调 `is_crawlable_link`、都**不再**硬写
`javascript:` / `mailto:` / `tel:` / `data:` / `vbscript:` 字面量，
且调用点集合不许静默缩减。

## 四、async `NonHttpUrlRedirectClientError` 缺口：实测后决定不修

上一轮记录 aiohttp 对 `Location: javascript:` 抛该异常（直连实测）。本轮
在真实批量扫描里找它的可见症状：

- 86 例 `--batch --async` 挂掉，stderr 是 `OSError: [WinError 64] 指定的
  网络名不再可用` + `ProactorEventLoop self pipe`，`grep -i NonHttpUrl` = **0**
  ⇒ 本机 loopback 抖动，不是产品缺陷。
- 10 例小样本重跑：**rc=0 / 10 rows / 0 failed / 9s**，正常。
- 194 门 async 全绿，官方 scorecard 走 sync（wrapper 不带 `--async`）。

⇒ 理论缺口存在，但**未观测到可见症状**。修它需要 `allow_redirects=False`
+ 自管重定向，会动 `AsyncRequester` 的 PLAIN 方法契约（历史实测：把 async
包装改成 `async def` 曾让 findings 从 4 掉到 0）。**风险远大于收益，本轮不动**，
留作已知边界。

## 五、仍未处理（WIP 既有，非本轮引入）

- `test_architecture_scale`：`scanner.py 2793 > 2650`（用户 Phase 364 WIP）。
- `test_doc_gate_parity`：CHANGELOG 1.4.3 vs `__version__` 1.4.4。
- 本轮未提交 commit，未触碰用户 Phase 364 WIP 的其他部分。

## 六、取舍

- 链接契约已收敛到**一个定义**，不建议再加 scheme 相关的守卫。
- 下一步若还要动"同族"，先读完整调用链再判断，别照静态清单接线。
- 真正还能改数字的是官方 scorecard 里 `postmethod 0/6` + `post 0/2`：
  runner 只喂 URL、wrapper 用 GET，POST 端点拿不到 body。这属于**跑分口径**，
  要动得单独决策并明确标注口径变化。
