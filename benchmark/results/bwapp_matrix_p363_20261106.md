# bWAPP security_level 矩阵（low / medium / high × 面 × 载体 × 角色）

生成时间：2026-11-06T08:41:30　靶：bWAPP 2.2 @ http://127.0.0.1:8081

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
| medium | reflected | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | script | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | img | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | svg | bwuser | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | attr-escape | bwuser | N/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | attr-escape | bwuser | N/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | attr-escape | bwuser | N/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | script | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | img | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | stored | svg | bee | Y/Y | 执行 | 报 | 报 | TP | 是 |
| medium | reflected | attr-escape | bee | N/Y | 执行 | 报 | 报 | TP | 是 |
| medium | header | attr-escape | bee | N/Y | 执行 | 报 | 报 | TP | 是 |
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
| low | 无 | script,img,svg,attr-escape | 51, 61, 81, 71, 11, 51, 61, 21, 41, 81, 31, 71 | 11,21,31,41 |
| medium | 无 | script,img,svg,attr-escape | 51, 61, 81, 71, 11, 51, 41, 81, 61, 21, 31, 71 | 11,21,31,41 |
| high | 无 | script,img,svg,attr-escape | 无 | 无 |

## 4. 扫描器原始判定（面级）

| 档 | 面 | 角色 | 默认 detected | 默认 findings(type/param/confidence) | 默认请求数 | 默认耗时(s) | headless detected | headless findings |
|---|---|---|---|---|---|---|---|---|
| low | reflected | bwuser | 是 | reflected/lastname/high; reflected/firstname/high | 50 | 1.3 | 是 | reflected/lastname/low; reflected/firstname/low |
| low | stored | bwuser | 是 | stored/entry/high | 27 | 1.2 | 是 | stored/entry/low |
| low | header | bwuser | 是 | header_xss/(header:User-Agent)/high | 25 | 1.1 | 是 | header_xss/(header:User-Agent)/low |
| low | reflected | bee | 是 | reflected/lastname/high; reflected/firstname/high | 50 | 1.3 | 是 | reflected/firstname/low; reflected/lastname/low |
| low | stored | bee | 是 | stored/entry/high | 27 | 1.2 | 是 | stored/entry/low |
| low | header | bee | 是 | header_xss/(header:User-Agent)/high | 25 | 1.1 | 是 | header_xss/(header:User-Agent)/low |
| medium | reflected | bwuser | 是 | reflected/firstname/high; reflected/lastname/high | 68 | 1.6 | 是 | reflected/firstname/low; reflected/lastname/low |
| medium | stored | bwuser | 是 | stored/entry/high | 47 | 1.5 | 是 | stored/entry/low |
| medium | header | bwuser | 是 | header_xss/(header:User-Agent)/high | 25 | 1.2 | 是 | header_xss/(header:User-Agent)/low |
| medium | reflected | bee | 是 | reflected/firstname/high; reflected/lastname/high | 68 | 1.6 | 是 | reflected/lastname/low; reflected/firstname/low |
| medium | stored | bee | 是 | stored/entry/high | 47 | 1.5 | 是 | stored/entry/low |
| medium | header | bee | 是 | header_xss/(header:User-Agent)/high | 25 | 1.1 | 是 | header_xss/(header:User-Agent)/low |
| high | reflected | bwuser | 否 | - | 64 | 1.6 | 否 | - |
| high | stored | bwuser | 否 | - | 237 | 5.8 | 否 | - |
| high | header | bwuser | 否 | - | 95 | 1.4 | 否 | - |
| high | reflected | bee | 否 | - | 64 | 1.6 | 否 | - |
| high | stored | bee | 否 | - | 237 | 5.7 | 否 | - |
| high | header | bee | 否 | - | 95 | 1.5 | 否 | - |
