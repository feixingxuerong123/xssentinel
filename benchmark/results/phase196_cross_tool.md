# Cross-tool XSS comparison (third-party corpus)

Generated: 2026-10-04 19:19:28  
Targets: http://127.0.0.1:18896  
Cases: 60 (same targets for every tool)  
Engine build: `78d65e6132f02ca0` (stable across the run)  
Tool builds: XSSentinel = builtin, dalfox = v2.13.0, nuclei-dast-xss = v3.9.0

| tool | TP | FP | TN | FN | errors | precision | recall | f1 | time (s) |
|---|---|---|---|---|---|---|---|---|---|
| XSSentinel | 35 | 0 | 24 | 1 | 0 | 1.0 | 0.9722 | 0.9859 | 346.4 |
| dalfox | 26 | 1 | 22 | 10 | 1 | 0.963 | 0.7222 | 0.8254 | 1172.7 |
| nuclei-dast-xss | 26 | 0 | 23 | 10 | 1 | 1.0 | 0.7222 | 0.8387 | 48.6 |

## Per-case matrix

| case | context | ground truth | XSSentinel | dalfox | nuclei-dast-xss |
|---|---|---|---|---|---|
| pos-dangle-01 | attribute | vulnerable | yes | yes | yes |
| pos-blind-01 | blind_oob | vulnerable | yes | yes | yes |
| pos-cdata-01 | cdata | vulnerable | yes | yes | yes |
| pos-attr-08 | css_context | vulnerable | yes | yes | yes |
| pos-proto-01 | dom_prototype | vulnerable | yes | no ! | no ! |
| pos-dom-01 | dom_xss | vulnerable | yes | no ! | no ! |
| pos-attr-07 | event_handler | vulnerable | yes | yes | yes |
| pos-graphql-01 | graphql | vulnerable | yes | no ! | no ! |
| pos-ctoss-01 | header | vulnerable | yes | no ! | no ! |
| pos-hdr-01 | header_reflection | vulnerable | yes | no ! | no ! |
| pos-markdown-01 | html_attribute | vulnerable | yes | yes | yes |
| pos-attr-01 | html_attribute_dq | vulnerable | yes | yes | yes |
| pos-attr-03 | html_attribute_noquote | vulnerable | yes | yes | yes |
| pos-attr-02 | html_attribute_sq | vulnerable | yes | yes | yes |
| pos-comment-01 | html_comment | vulnerable | yes | yes | yes |
| pos-elem-01 | html_element | vulnerable | yes | yes | yes |
| pos-importmap-01 | import_map | vulnerable | yes | yes | yes |
| pos-math-01 | math_context | vulnerable | yes | yes | yes |
| pos-url-03 | meta_refresh | vulnerable | yes | yes | yes |
| pos-redirect-01 | redirect | vulnerable | yes | no ! | no ! |
| pos-xs-01 | response_headers | vulnerable | no ! | no ! | no ! |
| pos-sanitizer-01 | sanitizer | vulnerable | yes | yes | yes |
| pos-script-03 | script_block | vulnerable | yes | yes | yes |
| pos-script-01 | script_string_dq | vulnerable | yes | yes | yes |
| pos-script-02 | script_string_sq | vulnerable | yes | yes | yes |
| pos-script-04 | script_template | vulnerable | yes | yes | yes |
| pos-sw-01 | service_worker | vulnerable | yes | no ! | no ! |
| pos-sri-01 | sri | vulnerable | yes | yes | yes |
| pos-svg-01 | svg_context | vulnerable | yes | yes | yes |
| pos-tpl-01 | template_angular | vulnerable | yes | yes | yes |
| pos-tb-01 | time_based_css_import | vulnerable | yes | yes | yes |
| pos-tt-01 | trusted_types | vulnerable | yes | yes | yes |
| pos-attr-04 | url_href | vulnerable | yes | yes | yes |
| pos-url-01 | url_javascript | vulnerable | yes | yes | yes |
| pos-worker-01 | web_worker | vulnerable | yes | no ! | no ! |
| pos-ws-01 | websocket | vulnerable | yes | no ! | no ! |
| neg-dangle-01 | attribute | safe | no | no | no |
| neg-blind-01 | blind_oob | safe | no | no | no |
| neg-cssi-01 | css_context | safe | no | no | no |
| neg-proto-01 | dom_prototype | safe | no | no | no |
| neg-dom-07 | dom_xss | safe | no | no | no |
| neg-graphql-01 | graphql | safe | no | no | no |
| neg-ctoss-01 | header | safe | no | no | no |
| neg-header-01 | header_reflection | safe | no | no | no |
| neg-markdown-01 | html_attribute | safe | no | no | no |
| neg-escape-02 | html_attribute_dq | safe | no | no | no |
| neg-escape-06 | html_attribute_noquote | safe | no | no | no |
| neg-escape-03 | html_attribute_sq | safe | no | no | no |
| neg-comment-01 | html_comment | safe | no | no | no |
| neg-stored-02 | html_element | safe | no | err | err |
| neg-importmap-01 | import_map | safe | no | no | no |
| neg-url-03 | meta_refresh | safe | no | no | no |
| neg-redirect-01 | redirect | safe | no | no | no |
| neg-xs-01 | response_headers | safe | no | no | no |
| neg-sanitizer-01 | sanitizer | safe | no | no | no |
| neg-jsonp-01 | script_block | safe | no | no | no |
| neg-escape-04 | script_string_dq | safe | no | yes ! | no |
| neg-sw-01 | service_worker | safe | no | no | no |
| neg-sri-01 | sri | safe | no | no | no |
| neg-tb-01 | time_based_css_import | safe | no | no | no |

## Disagreements with ground truth

- `pos-proto-01` (dom_prototype): **dalfox** missed-a-real-XSS
- `pos-proto-01` (dom_prototype): **nuclei-dast-xss** missed-a-real-XSS
- `pos-dom-01` (dom_xss): **dalfox** missed-a-real-XSS
- `pos-dom-01` (dom_xss): **nuclei-dast-xss** missed-a-real-XSS
- `pos-graphql-01` (graphql): **dalfox** missed-a-real-XSS
- `pos-graphql-01` (graphql): **nuclei-dast-xss** missed-a-real-XSS
- `pos-ctoss-01` (header): **dalfox** missed-a-real-XSS
- `pos-ctoss-01` (header): **nuclei-dast-xss** missed-a-real-XSS
- `pos-hdr-01` (header_reflection): **dalfox** missed-a-real-XSS
- `pos-hdr-01` (header_reflection): **nuclei-dast-xss** missed-a-real-XSS
- `pos-redirect-01` (redirect): **dalfox** missed-a-real-XSS
- `pos-redirect-01` (redirect): **nuclei-dast-xss** missed-a-real-XSS
- `pos-xs-01` (response_headers): **XSSentinel** missed-a-real-XSS
- `pos-xs-01` (response_headers): **dalfox** missed-a-real-XSS
- `pos-xs-01` (response_headers): **nuclei-dast-xss** missed-a-real-XSS
- `pos-sw-01` (service_worker): **dalfox** missed-a-real-XSS
- `pos-sw-01` (service_worker): **nuclei-dast-xss** missed-a-real-XSS
- `pos-worker-01` (web_worker): **dalfox** missed-a-real-XSS
- `pos-worker-01` (web_worker): **nuclei-dast-xss** missed-a-real-XSS
- `pos-ws-01` (websocket): **dalfox** missed-a-real-XSS
- `pos-ws-01` (websocket): **nuclei-dast-xss** missed-a-real-XSS
- `neg-escape-04` (script_string_dq): **dalfox** false-positive