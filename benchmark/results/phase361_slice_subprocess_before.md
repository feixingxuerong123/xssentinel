# Cross-tool XSS comparison (third-party corpus)

Generated: 2026-11-06 02:16:03  
Targets: http://127.0.0.1:18896  
Cases: 18 (same targets for every tool)  
Engine build: `db632f88e96d62bb` (stable across the run)  
Tool builds: XSSentinel = builtin

| tool | TP | FP | TN | FN | errors | precision | recall | f1 | time (s) |
|---|---|---|---|---|---|---|---|---|---|
| XSSentinel | 12 | 0 | 6 | 0 | 0 | 1.0 | 1.0 | 1.0 | 54.1 |

## Per-case matrix

| case | context | ground truth | XSSentinel |
|---|---|---|---|
| pos-elem-01 | html_element | vulnerable | yes |
| pos-attr-01 | html_attribute_dq | vulnerable | yes |
| pos-attr-05 | html_attribute_dq | vulnerable | yes |
| pos-script-01 | script_string_dq | vulnerable | yes |
| pos-script-03 | script_block | vulnerable | yes |
| pos-comment-01 | html_comment | vulnerable | yes |
| pos-url-01 | url_javascript | vulnerable | yes |
| pos-dom-01 | dom_xss | vulnerable | yes |
| pos-svg-01 | svg_context | vulnerable | yes |
| pos-polyglot-01 | html_element | vulnerable | yes |
| neg-rcdata-01 | html_element | vulnerable | yes |
| neg-filter-01 | html_element | vulnerable | yes |
| neg-escape-01 | html_element | safe | no |
| neg-comment-01 | html_comment | safe | no |
| neg-attr-01 | html_attribute_dq | safe | no |
| neg-csp-01 | html_element | safe | no |
| neg-jsonp-01 | script_block | safe | no |
| neg-rcdata-05 | html_element | safe | no |

## Disagreements with ground truth

(none)