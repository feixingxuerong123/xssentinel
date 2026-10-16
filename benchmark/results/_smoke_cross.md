# Cross-tool XSS comparison (third-party corpus)

Generated: 2026-09-10 21:29:55  
Targets: http://127.0.0.1:8896  
Cases: 2 (same targets for every tool)

| tool | TP | FP | TN | FN | errors | time (s) |
|---|---|---|---|---|---|---|
| XSSentinel | 1 | 0 | 1 | 0 | 0 | 38.4 |

## Per-case matrix

| case | ground truth | XSSentinel |
|---|---|---|
| pos-elem-01 | vulnerable | yes |
| neg-escape-01 | safe | no |

## Disagreements with ground truth

(none)