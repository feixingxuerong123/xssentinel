# Cross-tool XSS comparison (third-party corpus)

Generated: 2026-10-09 20:10:41  
Targets: http://127.0.0.1:18896  
Cases: 60 (same targets for every tool)  
Engine build: `8a409f26d026babf` (stable across the run)  
Tool builds: XSSentinel = builtin

| tool | TP | FP | TN | FN | errors | precision | recall | f1 | time (s) |
|---|---|---|---|---|---|---|---|---|---|
| XSSentinel | 35 | 0 | 24 | 1 | 0 | 1.0 | 0.9722 | 0.9859 | 328.2 |

## Per-case matrix

| case | context | ground truth | XSSentinel |
|---|---|---|---|
| pos-dangle-01 | attribute | vulnerable | yes |
| pos-blind-01 | blind_oob | vulnerable | yes |
| pos-cdata-01 | cdata | vulnerable | yes |
| pos-attr-08 | css_context | vulnerable | yes |
| pos-proto-01 | dom_prototype | vulnerable | yes |
| pos-dom-01 | dom_xss | vulnerable | yes |
| pos-attr-07 | event_handler | vulnerable | yes |
| pos-graphql-01 | graphql | vulnerable | yes |
| pos-ctoss-01 | header | vulnerable | yes |
| pos-hdr-01 | header_reflection | vulnerable | yes |
| pos-markdown-01 | html_attribute | vulnerable | yes |
| pos-attr-01 | html_attribute_dq | vulnerable | yes |
| pos-attr-03 | html_attribute_noquote | vulnerable | yes |
| pos-attr-02 | html_attribute_sq | vulnerable | yes |
| pos-comment-01 | html_comment | vulnerable | yes |
| pos-elem-01 | html_element | vulnerable | yes |
| pos-importmap-01 | import_map | vulnerable | yes |
| pos-math-01 | math_context | vulnerable | yes |
| pos-url-03 | meta_refresh | vulnerable | yes |
| pos-redirect-01 | redirect | vulnerable | yes |
| pos-xs-01 | response_headers | vulnerable | no ! |
| pos-sanitizer-01 | sanitizer | vulnerable | yes |
| pos-script-03 | script_block | vulnerable | yes |
| pos-script-01 | script_string_dq | vulnerable | yes |
| pos-script-02 | script_string_sq | vulnerable | yes |
| pos-script-04 | script_template | vulnerable | yes |
| pos-sw-01 | service_worker | vulnerable | yes |
| pos-sri-01 | sri | vulnerable | yes |
| pos-svg-01 | svg_context | vulnerable | yes |
| pos-tpl-01 | template_angular | vulnerable | yes |
| pos-tb-01 | time_based_css_import | vulnerable | yes |
| pos-tt-01 | trusted_types | vulnerable | yes |
| pos-attr-04 | url_href | vulnerable | yes |
| pos-url-01 | url_javascript | vulnerable | yes |
| pos-worker-01 | web_worker | vulnerable | yes |
| pos-ws-01 | websocket | vulnerable | yes |
| neg-dangle-01 | attribute | safe | no |
| neg-blind-01 | blind_oob | safe | no |
| neg-cssi-01 | css_context | safe | no |
| neg-proto-01 | dom_prototype | safe | no |
| neg-dom-07 | dom_xss | safe | no |
| neg-graphql-01 | graphql | safe | no |
| neg-ctoss-01 | header | safe | no |
| neg-header-01 | header_reflection | safe | no |
| neg-markdown-01 | html_attribute | safe | no |
| neg-escape-02 | html_attribute_dq | safe | no |
| neg-escape-06 | html_attribute_noquote | safe | no |
| neg-escape-03 | html_attribute_sq | safe | no |
| neg-comment-01 | html_comment | safe | no |
| neg-stored-02 | html_element | safe | no |
| neg-importmap-01 | import_map | safe | no |
| neg-url-03 | meta_refresh | safe | no |
| neg-redirect-01 | redirect | safe | no |
| neg-xs-01 | response_headers | safe | no |
| neg-sanitizer-01 | sanitizer | safe | no |
| neg-jsonp-01 | script_block | safe | no |
| neg-escape-04 | script_string_dq | safe | no |
| neg-sw-01 | service_worker | safe | no |
| neg-sri-01 | sri | safe | no |
| neg-tb-01 | time_based_css_import | safe | no |

## Disagreements with ground truth

- `pos-xs-01` (response_headers): **XSSentinel** missed-a-real-XSS