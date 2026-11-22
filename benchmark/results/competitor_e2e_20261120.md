# 竞品载荷注入我方扫描器（端到端事实表）

- tree: `3b2d105` / 2026-11-20 14:49:37
- budget: 14 payloads / 12 transforms
- 这是**竞品载荷作为我方输入**的对照，不是竞品在跑，也不是 F1。

| 载荷来源 | TP | FN | FP | TN | ERR |
|---|---:|---:|---:|---:|---:|
| baseline | 7 | 0 | 0 | 3 | 0 |
| xsstrike | 7 | 0 | 0 | 3 | 0 |
| dalfox | 6 | 1 | 0 | 3 | 0 |
| xsser | 6 | 1 | 0 | 3 | 0 |

baseline 之外任一臂若 FN/FP 上升或出现 ERR，逐例见 JSON。
