# bWAPP security_level 矩阵（low / medium / high × 面 × 载体 × 角色）

生成时间：2026-11-03T22:59:50　靶：bWAPP 2.2 @ http://127.0.0.1:8081

## 1. 档位切换确认

| 档 | bee 页面 Current | bwuser 页面 Current | 生效 |
|---|---|---|---|
| low | low | low | 是 |
| medium | medium | medium | 是 |
| high | high | high | 是 |

## 2. 主矩阵（72 组：3 档 × 3 面 × 4 载体 × 2 角色）

回显：`Y/Y`=完整 payload 原样保留且标签存活；`N/Y`=标签存活但完整 payload 被改（medium addslashes 给 `"` 加反斜杠）；`N/N`=已实体化。

| 档 | 面 | 载体 | 角色 | 回显 | 浏览器执行 | 扫描默认 | 扫描 headless | 归类(默认) | 行级一致(默认) |
|---|---|---|---|---|---|---|---|---|---|
| low | reflected | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | attr-escape | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | attr-escape | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | attr-escape | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | reflected | attr-escape | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | header | attr-escape | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| low | stored | attr-escape | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | script | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | script | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | img | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | img | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | svg | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | svg | bwuser | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | attr-escape | bwuser | N/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | attr-escape | bwuser | N/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | attr-escape | bwuser | N/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | script | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | script | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | img | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | img | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | svg | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | svg | bee | Y/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | attr-escape | bee | N/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | header | attr-escape | bee | N/Y | 执行 | 未报 | 未报 | FN | 否 |
| medium | stored | attr-escape | bee | N/Y | 执行 | 报 | 报 | TP | 是 |
| high | reflected | script | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | script | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | script | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | img | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | img | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | img | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | svg | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | svg | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | svg | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | attr-escape | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | attr-escape | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | attr-escape | bwuser | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | script | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | script | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | script | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | img | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | img | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | img | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | svg | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | svg | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | svg | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | reflected | attr-escape | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | header | attr-escape | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |
| high | stored | attr-escape | bee | N/N | 未执行 | 未报 | 未报 | TN | 是 |

## 3. 存储型跨角色（bee 查看 bwuser 的低权限条目）

| 档 | 不勾 Show all 可见 bwuser 条目 | 勾 Show all 可见 | Show all 弹窗 | 执行到的 bwuser 标记 |
|---|---|---|---|---|
| low | 无 | script,img,svg,attr-escape | 51, 61, 81, 71, 11, 51, 21, 81, 41, 61, 71, 31 | 11,21,31,41 |
| medium | 无 | script,img,svg,attr-escape | 51, 61, 81, 71, 11, 51, 21, 41, 81, 61, 31, 71 | 11,21,31,41 |
| high | 无 | script,img,svg,attr-escape | 无 | 无 |

说明：`Show all 弹窗` 包含两次页面加载 —— 首次 GET 触发 bee 自己的 4 条（51/61/71/81），勾选 Show all 提交后触发 8 条（bee 4 + bwuser 4）。`执行到的 bwuser 标记` 只统计 11/21/31/41。三档下“不勾 Show all 看不到 bwuser 条目”的行为一致；条目在 high 仍可见但被实体化、不执行。

## 4. 扫描器原始判定（面级）

| 档 | 面 | 角色 | 默认 detected | 默认 findings(type/param/confidence) | headless detected | headless findings |
|---|---|---|---|---|---|---|
| low | reflected | bwuser | 是 | reflected/firstname/high; reflected/lastname/high | 是 | reflected/lastname/low; reflected/firstname/low |
| low | stored | bwuser | 是 | stored/entry/high | 是 | stored/entry/low |
| low | header | bwuser | 是 | header_xss/(header:User-Agent)/high | 是 | header_xss/(header:User-Agent)/low |
| low | reflected | bee | 是 | reflected/lastname/high; reflected/firstname/high | 是 | reflected/lastname/low; reflected/firstname/low |
| low | stored | bee | 是 | stored/entry/high | 是 | stored/entry/low |
| low | header | bee | 是 | header_xss/(header:User-Agent)/high | 是 | header_xss/(header:User-Agent)/low |
| medium | reflected | bwuser | 否 | - | 否 | - |
| medium | stored | bwuser | 是 | stored/entry/high | 是 | stored/entry/low |
| medium | header | bwuser | 否 | - | 否 | - |
| medium | reflected | bee | 否 | - | 否 | - |
| medium | stored | bee | 是 | stored/entry/high | 是 | stored/entry/low |
| medium | header | bee | 否 | - | 否 | - |
| high | reflected | bwuser | 否 | - | 否 | - |
| high | stored | bwuser | 否 | - | 否 | - |
| high | header | bwuser | 否 | - | 否 | - |
| high | reflected | bee | 否 | - | 否 | - |
| high | stored | bee | 否 | - | 否 | - |
| high | header | bee | 否 | - | 否 | - |

## 5. 统计

扫描器的 verdict 是**面级**（该面是否存在 XSS）；行级归类 = 该载体的 Playwright 真值 × 面级 verdict。

| 粒度 | TP | FN | FP | TN | 合计 |
|---|---|---|---|---|---|
| 面级（3 档 × 3 面 × 2 角色） | 8 | 4 | 0 | 6 | 18 |
| 行级（3 档 × 3 面 × 4 载体 × 2 角色） | 32 | 16 | 0 | 24 | 72 |

- **FP 方向：0**。high 档 6/6 个面、24/24 个载体行均未报 —— 靶在 high 确实不可利用（htmlspecialchars 全实体化），扫描器没有误报。
- **FN 方向：medium 档 4/8 个可利用面级格漏报、16/24 个行漏报**；low 档 6/6 面、24/24 行全部报出；medium stored 2/2 面报出。
- `--headless` 与默认模式 18/18 判定完全一致，没有修正任何一条 FN。

## 6. 扫描器误判清单

全部为 **FN**（漏报），无 FP。

| # | 档 | 面 | 载体 | 角色 | 判定 | 根因（一句话） |
|---|---|---|---|---|---|---|
| 1 | medium | reflected | script | bwuser | FN | marker 固定为 `alert('xssv_…')`，addslashes 把 `'` 转成 `\'` → JS 语法错误；无引号变体未生成 |
| 2 | medium | reflected | script | bee | FN | 同上 |
| 3 | medium | reflected | img | bwuser | FN | 同上 |
| 4 | medium | reflected | img | bee | FN | 同上 |
| 5 | medium | reflected | svg | bwuser | FN | 同上 |
| 6 | medium | reflected | svg | bee | FN | 同上 |
| 7 | medium | reflected | attr-escape | bwuser | FN | 同上（`"` 另被转义，但 `<img>` 标签仍存活并执行） |
| 8 | medium | reflected | attr-escape | bee | FN | 同上 |
| 9 | medium | header | script | bwuser | FN | 同 #1（User-Agent 走同一个 xss()/addslashes 分支） |
| 10 | medium | header | script | bee | FN | 同上 |
| 11 | medium | header | img | bwuser | FN | 同上 |
| 12 | medium | header | img | bee | FN | 同上 |
| 13 | medium | header | svg | bwuser | FN | 同上 |
| 14 | medium | header | svg | bee | FN | 同上 |
| 15 | medium | header | attr-escape | bwuser | FN | 同上 |
| 16 | medium | header | attr-escape | bee | FN | 同上 |

## 7. 根因证据（独立于扫描器输出）

扫描器在 low 报出的 payload 形如 `<svg/onload=alert('xssv_7b66ac3c')>`；在 medium 完全不报。用同一形态手工复核：

| 档 | 回显 | Playwright dialog |
|---|---|---|
| low | `Welcome <svg/onload=alert('xssv_abc123')> x`（原样） | `xssv_abc123`（执行） |
| medium | `Welcome <svg/onload=alert(\'xssv_abc123\')> x`（addslashes 加反斜杠） | 无（JS 语法错误） |
| high | `Welcome &lt;svg/onload=alert(&#039;xssv_abc123&#039;)&gt; x` | 无（实体化） |

补充实验：用 `--custom-payloads` 提供无引号 `<svg/onload=alert(999)>`，low 仍报、medium 仍 0 hit —— 扫描器会把自定义 payload 的 alert 参数改写成自己的带引号 marker，因此绕过不了这个失效点。

## 8. 证据质量问题（非误判，但需记录）

medium 档 `stored` 判为 TP（结论正确：该面确实可利用，Playwright 4 载体全部执行），但扫描器给出的具体 payload `%00<svg%00/onload=alert(%00'xssv_…%00')%00>` 独立复核**不执行**（low 与 medium 下均只触发我们另写的一条 `alert(777)`）。该 finding 的 `detail` 是 "token reflected inside `<script>` element text"，属上下文误判；`evidence_class=browser-unavailable`。本轮因为靶本身存在真实可利用点，结论未变成 FP，但该证据链不可信。

## 9. 约束核对

- 靶源码未改：只读 `docker exec cat`；未修改任何 PHP 文件。
- 数据库未直接改：stored 条目全部经 `xss_stored_1.php` 表单写入，用应用自带 Delete 清理；每档结束两个角色均清空。
- 未跳过过滤器：三档均以 cookie `security_level` 真实切换，`portal.php` 的 `Current: <b>…</b>` 逐档确认（见第 1 节）。
- 复用了既有账号：bee/bug（admin）、bwuser/bwpass123（admin=0），未新建账号。
- 证据：72 行真值 + 3 档跨角色均带 Playwright dialog/DOM 记录（`bwapp_matrix_truth.json`），扫描器原始 findings 在 `bwapp_matrix_scan.json`。
- `git status --short | Select-String '^ D'` 开始/结束计数均为 0。

## 10. 结论：这轮是否发现需要修的扫描器问题

**是，发现 1 个主问题 + 1 个次问题。**

1. 主问题（需要修）：**addslashes 场景（bWAPP medium）下反射/header 系统性 FN**。扫描器把验证 marker 固定注入为 `alert('xssv_…')`；`'` 被 addslashes 转义后 payload 变成语法错误，扫描器据此判定不可利用。靶面用无引号 payload（`alert(51)` 等）在 medium 下 16/16 行全部执行，因此这是明确的漏报。影响面：medium 档 reflected 与 header 两面、两个角色、四种载体全部漏报；`--headless` 也无法修正。
   修复方向（本轮未改代码，仅记录）：在 payload 生成阶段增加 addslashes 兼容变体 —— 无引号 `alert(数字)`、反引号、`String.fromCharCode`、字符串拼接；或在 marker 注入时不强制加引号，并对 `\'` 场景做专门的存活判定。

2. 次问题（建议修）：**stored 上下文的 executable 判定会把 `%00` 分隔 payload 误判为可执行**。medium stored 的 finding 结论正确（面确实可利用），但它给出的具体 payload 独立复核不执行；若换成一个只在 `%00` 形态上“看起来反射”的靶，这条逻辑可能变成 FP。建议对该类 payload 增加浏览器复核或收紧上下文分类。

3. 没有发现 high 档误报：htmlspecialchars 完全实体化时，扫描器 6/6 面、24/24 行全部正确不报，FP=0。


