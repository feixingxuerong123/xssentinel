# 五分钟上手

这份文档只回答一个问题:**怎么在五分钟内拿到一个我能判断真假的结果**。
完整能力清单在 [README](../README.md),检测原理在「检测架构」一节——
那些是参考,不是上手路径。

---

## 1. 安装

```bash
py -3.12 -m venv .venv                 # 本机默认 python 是 3.9,项目要求 >=3.10
.venv/Scripts/activate                 # POSIX: source .venv/bin/activate

# 依赖走 uv(本机 pip 通路病态,实测 uv 10s 完成、pip 超时)
uv pip install --python .venv/Scripts/python.exe -e ".[dev,async,ast,api,nuclei]"

# 可选:真浏览器确认(L6)、HTTPS 拦截、API 服务
uv pip install --python .venv/Scripts/python.exe -e ".[headless,mitm]"
python -m playwright install chromium
```

装完先跑自检,它不联网(起本地靶场 + 跑全部检测层):

```bash
python -m xssentinel --self-test
```

**它是慢的**(分钟级,默认上限 900s,可用 `XSSentinel_SELFTEST_TIMEOUT` 调),
不是冒烟测试。只想确认装好了,`python -m xssentinel --version`(输出单行版本号,
便于脚本判断装的是哪一版)或 `--help` 就够了。`--self-test` 会自己挑空闲端口
(默认优先 8899,被占用时自动改);需要固定端口就设 `XSSENTINEL_SELFTEST_PORT`。

---

## 2. 三条命令

```bash
# ① 扫一个 URL(最常用)
xssentinel -u "https://target.example/search?q=1"

# ② 让爬虫自己找端点和表单(含无参数的纯 DOM 页面)
xssentinel -u "https://target.example/" -c --crawl-depth 2

#    默认同源;要放开到某个前缀(比如同站的另一条路径)才用 --scope
xssentinel -u "https://target.example/app/" -c --scope "https://target.example/app/"

# ③ 要机器可读的结果 + 真浏览器确认
xssentinel -u "https://target.example/search?q=1" \
           -f sarif -o out.sarif --headless
```

`-f` 支持 `html / json / csv / sarif / junit / markdown / burp / nuclei`。
管道里要机器可读结果时用 `-o -`（摘要走 stderr，stdout 只有报告）:

```bash
httpx -l targets.txt | xssentinel --batch-stdin -o - -f json | jq -c '.findings[]'
```

批量 URL 列表接受 UTF-8/UTF-16 BOM、GBK 与 CRLF；退出码 `0/1/2/3` 分别为
成功 / 崩溃 / 用法错误 / 扫描不完整。
不确定预算时用档位而不是手调参数:

```bash
xssentinel -u URL --scan-policy quick     # 冒烟:最少请求
xssentinel -u URL --scan-policy deep      # 深扫:预算拉满
```

批量(一行一个 URL,`#` 注释)与流量导入:

```bash
xssentinel --batch urls.txt -o reports/
xssentinel --har capture.har            # 浏览器 DevTools / Burp 导出
xssentinel --openapi spec.json          # 声明面,含从未被访问的路由
xssentinel --raw-request captured.txt   # Burp "copy as raw"
```

---

## 3. 退出码:这是本项目最该先看懂的东西

| 码 | 含义 | 你该做什么 |
|---|---|---|
| **0** | 扫完了。**0 个 finding 也是 0** | 结合下面第 4 节确认这次扫描真的到达了目标 |
| **1** | 只有加了 `--exit-code N` 且命中数 ≥ N 才出现(默认关闭) | CI 门禁用,`--exit-code 1` 即「有洞就红」 |
| **2** | 用法错误(argparse) | 看报错 |
| **3** | **扫描不完整,这个结果不能用来下"没有漏洞"的结论** | 看 `[!] Why:` 那一行 |

**0 和 3 的区别是刻意的。** 目标连不上、代理吃掉流量、TLS 没握上手,
这三种情况的报告都是 0 个 finding;把它们和"扫完且干净"合成一个退出码,
就等于把"没测到"伪装成"测了没问题"。所以后者单独给 3。

CI 里正确的写法是:

```bash
xssentinel -u "$URL" -f sarif -o out.sarif --exit-code 1
case $? in
  0) echo "clean" ;;
  1) echo "vulnerable" ; exit 1 ;;
  3) echo "INCONCLUSIVE - do not merge on this" ; exit 1 ;;
esac
```

---

## 4. 四个会让人误读结果的环境陷阱

**① 环境代理。** `requests` 默认尊重 `HTTP(S)_PROXY`。若宿主机设了全局代理,
发往内网/loopback 的请求会被代理接管,你拿到的是**代理的**回答。
本工具现在会在启动时打印一行提示;要直连就 `NO_PROXY=127.0.0.1,localhost`
或临时 `unset HTTP_PROXY`。

**② `%TEMP%` 不可写。** 某些加固环境(Low 完整性标签、容器只读挂载)里
`tempfile.gettempdir()` 会静默回退到当前目录,第三方库会在你的工作目录里
留垃圾文件。CLI 启动时已做可写性探测并重定向,移动时会打印
`[*] System temp dir not writable; using ...`——看到这行说明发生了重定向,
不是报错。

**③ 单进程跑全量测试会卡死。** 这不是性能问题:某个 async/DOM 测试绑定
事件循环后,后续 sync Playwright 调用全部报 "Sync API inside the asyncio loop"。
必须用分批 runner:

```bash
python tests/run_all_batched.py --quiet              # 顺序档,本机约 60–75 分钟
python tests/run_all_batched.py --quiet --jobs 4     # 并行档,2026-11-02 实测 268 文件 616s
```

两档逐文件 verdict 一致,`--jobs` 只换墙钟不改判定;引用结果时**跳过数必须一起报**
(整文件 skip 的门禁什么都不曾贡献)。

**④ 本机 loopback 劣化。** 部分安全软件会间歇掐断 loopback TCP,表现为
随机失败。先单文件复跑;复跑通过就按「未验证」记账,不要当回归。

---

## 5. 拿到结果之后

```bash
xssentinel -u URL --poc-dir poc/     # 每个确认漏洞一份可执行 PoC + curl
xssentinel --diff before.json after.json   # 修复前后对比
xssentinel --verify-fix URL          # 复验某个修复
xssentinel --serve                   # REST API 微服务模式
xssentinel --mcp                     # MCP server,接进 AI 工作流
# 客户端配置:{"command":"python","args":["-m","xssentinel","mcp"]}
# 现代 MCP(2026-07-28)无需 initialize,直接发 server/discover;旧版握手照旧
```

一个 finding 该不该信,看两个字段:

- `confidence` — `high` 表示有语义确认或浏览器实执行证据;`low` 是线索,不是结论
  (例如 `dom_sink_reachability`:数据到达了 sink 但没观测到执行)。
- `context` — 反射落在哪种上下文。同一个 payload 在 `html_body` 和在
  `script_string` 里的结论完全不同。

---

## 出问题先看哪里

| 症状 | 先看 |
|---|---|
| 0 findings 但你知道站点有洞 | 退出码是不是 3?有没有 `[!] Why:`?代理有没有生效? |
| 报告写不出来 | 输出目录权限;POSIX 上报告以 0600 写出 |
| 浏览器相关层全部跳过 | `python -m playwright install chromium`;`%TEMP%` 可写性 |
| 想加一个检测能力 | [`CONTRIBUTING.md`](../CONTRIBUTING.md),新层必须同时注册 `coverage.LAYERS` 与 `layer_coverage` 矩阵 |
