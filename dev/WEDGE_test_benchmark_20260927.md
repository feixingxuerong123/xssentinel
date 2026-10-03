# 已结案(2026-10-03):BASE/BENCH_PORT 漂移 —— 不是玄学,是扫描器瞄错了端口

> 原诊断记录保留在下方(其中"已排除"一节的多数结论仍然成立,但根因不在它们
> 排除过的任何一项)。结案结论:

## 根因

Phase 179 把 fixture 服务器从 8899 迁到 18899(Windows 保留段杀伤区)时,
`tests/benchmark.py` 的 `BENCH_PORT` 更新了,但同文件第 60 行的
`BASE = "http://127.0.0.1:8899"` **漏改**。于是:

  * fixture 服务器在 18899 上健康监听(本文档"已排除"一节全部属实);
  * 扫描器(`BASE + path`)全速连向 **8899** —— 一个无人监听的端口;
  * 本机安全软件对死端口的 SYN 静默丢弃(而不是回 RST),connect 因此挂起
    且**绕过 settimeout** —— 正是原假说 2 的机制,只是触发条件是"连错端口";

原 py-spy 看到 `sock.connect` 挂起、18899 却零流量、"对独立进程 4-20ms 响应",
三条证据在"扫描器瞄错端口"下全部自洽。

## 修复与验证

  * `tests/benchmark.py`:BASE 改为从 BENCH_PORT 派生(结构上不可能再漂移);
  * 同族问题 range3 起靶 wedge 同日另案修复:HTTP/1.1 keep-alive 下
    `_send` 缺 Content-Length,read-to-EOF 客户端(requests)必挂
    (range3/server.py c0cbb45);
  * 验证:`pytest tests/test_benchmark.py` **35 passed in 13.86s**
    (此前每次 540s×2 超时);range3 runner sync TP20/FP0/TN6/FN0 +
    async TP18/FP0/TN6/FN0/SKIP2,全部案例约 1s。

## 经验

connect 挂起 + "服务器健康却零流量" = 先查**客户端连的是不是这个服务器**
(netstat 看进程的连接指向),再谈安全软件。端口迁移类改动必须让
`BASE` 这类派生值从端口常量计算,而不是并存两份字面量。

---

# 原始诊断(2026-09-27,已由上述结案取代)


## 现象
`pytest tests/test_benchmark.py` 的 `benchmark_result` fixture(tests/benchmark.py:254
的 `run_benchmark`)里,Scanner 的 L1 marker 探针(scanner.py:527)在
`sock.connect` 上挂起,**远超** urllib3 应有的 10 秒 settimeout——py-spy 两次采样
(间隔 120 秒)都在同一帧,主线程零 CPU。

## 已排除
* fixture 服务器 accept 循环活着(py-spy: `serve_forever` 正常轮询);
* 服务器对**独立进程**的请求 4-20ms 响应(18899 端口健康);
* 端口保留段已迁出(18777/18899/18991/18999 实测可绑,见 cd360ff);
* `_send` 显式传 `timeout=self.timeout`(requester.py:313/326),shim 的
  Requester 是 `Requester(timeout=10)`(tests/benchmark.py:237)。

## 矛盾点(下次会话的切入)
settimeout(10) 的 connect 不可能挂 600 秒——除非:
1. 超时在 requests→urllib3 的某条路径上丢失(HTTPAdapter(max_retries=2)
   的 Retry 链是否重建了无超时连接?);或
2. 安全软件对该进程(今日已发数千连接)做了逐进程的连接拦截/限速,
   且其拦截发生在绕过 socket 超时的层(TDI/WFP 重定向);
3. 同进程内 ThreadingHTTPServer(keep-alive 常驻线程)与客户端池之间的
   某种 GIL/握手死锁——但 connect 阶段双方都应释放 GIL。

## 建议复现路径
1. 最小化:单进程起 ThreadingHTTPServer(protocol_version="HTTP/1.1")+
   requests.Session 发 5000 个请求,观察 TIME_WAIT 与后续 connect 延迟;
2. 若复现:py-spy dump 前后对比 + `netsh trace` 抓 loopback SYN;
3. 若不复现:门禁跑满一轮后立即重跑 test_benchmark(进程态相关性)。

## 关联
* 三个 fixture 服务器已启用 HTTP/1.1 keep-alive(cd360ff 之后的未提交改动,
  正确性独立成立:响应都带 Content-Length);
* 本机安全软件今日行为:SYN 黑洞(每次 connect 吃满 10 秒)、部分端口
  10013 拒绝、间歇 10053/10054 重置——与健康窗口交替出现。

## 同一家族的第二种形态(2026-09-28,Range4 首轮实测)

sync 引擎跑 `r4-neg-vue-vtext`(一个本该 9 秒的用例)耗时 **5080.2s**,
runner 的 per-case `timeout=180` 触发 `subprocess.TimeoutExpired` 把它杀了,
但 **JSON 报告已经落盘** ⇒ `score()` 照常给出 TN,判定有效,只是慢了 84 分钟。

形态差异:上一篇是 **connect 阶段**卡死(零 CPU);这一次是**扫描已完成、
进程收尾不退出**——报告写出来了,进程没回到 exit。

对 runner 的启示:**
`subprocess.run(timeout=N)` 超时 ≠ 这次用例失败。**报告存在就以报告为准,
把 `err` 单独记下来**(range4/runner.py 已经这么做了:`verdict` 只在
`err and report is None` 时才判 ERROR)。否则会把环境挂起误记成检测回归。。