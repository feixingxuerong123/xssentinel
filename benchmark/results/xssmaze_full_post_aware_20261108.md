# XSSMaze Scanner Benchmark Report

**Target:** http://127.0.0.1:3001  
**Catalog:** 1064 endpoints, 175 categories  
**Controls:** 27 with exploitable=false (a detection there is a FALSE POSITIVE, never a miss)  
**Exploitable reach:** 24 client, 1013 server  
**Scoring mode:** --reach server  
**Scored population:** 1013 exploitable endpoints (reach: server)  
**Not scored:** 24 client-reach, plus 27 controls — hits there are listed separately, never as TP or FN  

> Endpoints with `exploitable: false` are deliberate true negatives and are excluded from the denominator; a detection on one is a false positive. Endpoints outside the scored `reach` are excluded too — a request-only scanner cannot deliver a payload to a browser-only channel.

## Summary

| Scanner | TP | FN | FP | Precision | Recall | F1 | Time |
|---------|----|----|----|-----------|--------|----|------|
| xssentinel-post-aware | 987 | 26 | 0 | 100.0% | 97.4% | 0.987 | 2039.6s |

## Detailed Results

### xssentinel-post-aware

- **Reported findings:** 987
- **True positives:** 987/1013
- **False negatives:** 26/1013
- **False positives:** 0 (0 on controls, 0 on non-maze paths)
- **Precision / Recall / F1:** 100.0% / 97.4% / 0.987

**By Vulnerability Class:**

| Key | Detected | Missed | Total | Rate |
|-----|----------|--------|-------|------|
| `reflected-html` | 452 | 14 | 466 | 97.0% |
| `dom` | 168 | 6 | 174 | 96.6% |
| `reflected-attr` | 254 | 4 | 258 | 98.4% |
| `reflected-js` | 94 | 1 | 95 | 98.9% |
| `stored` | 9 | 1 | 10 | 90.0% |
| `csti` | 5 | 0 | 5 | 100.0% |
| `prototype-pollution` | 5 | 0 | 5 | 100.0% |

**By Category:**

| Key | Detected | Missed | Total | Rate |
|-----|----------|--------|-------|------|
| `dom` | 22 | 3 | 25 | 88.0% |
| `headerinj` | 3 | 3 | 6 | 50.0% |
| `sanitizer` | 9 | 2 | 11 | 81.8% |
| `domsink` | 6 | 2 | 8 | 75.0% |
| `multipart` | 2 | 2 | 4 | 50.0% |
| `modern` | 29 | 1 | 30 | 96.7% |
| `bugbounty` | 8 | 1 | 9 | 88.9% |
| `basic` | 6 | 1 | 7 | 85.7% |
| `realworld_input` | 6 | 1 | 7 | 85.7% |
| `edgefilter` | 5 | 1 | 6 | 83.3% |
| `obfuscation` | 5 | 1 | 6 | 83.3% |
| `postmethod` | 5 | 1 | 6 | 83.3% |
| `url` | 5 | 1 | 6 | 83.3% |
| `cspbypass` | 4 | 1 | 5 | 80.0% |
| `domsource` | 4 | 1 | 5 | 80.0% |
| `header` | 3 | 1 | 4 | 75.0% |
| `nonce` | 2 | 1 | 3 | 66.7% |
| `post` | 1 | 1 | 2 | 50.0% |
| `jf` | 0 | 1 | 1 | 0.0% |
| `realworld` | 15 | 0 | 15 | 100.0% |
| `waf` | 14 | 0 | 14 | 100.0% |
| `prototype` | 10 | 0 | 10 | 100.0% |
| `hidden` | 9 | 0 | 9 | 100.0% |
| `ctxescape` | 8 | 0 | 8 | 100.0% |
| `edge` | 8 | 0 | 8 | 100.0% |
| `filterchain` | 8 | 0 | 8 | 100.0% |
| `html5` | 8 | 0 | 8 | 100.0% |
| `multireflect` | 8 | 0 | 8 | 100.0% |
| `regexbypass` | 8 | 0 | 8 | 100.0% |
| `scanbounty` | 8 | 0 | 8 | 100.0% |
| `sink` | 8 | 0 | 8 | 100.0% |
| `specialtag` | 8 | 0 | 8 | 100.0% |
| `encoding` | 7 | 0 | 7 | 100.0% |
| `websocket` | 7 | 0 | 7 | 100.0% |
| `advanced` | 6 | 0 | 6 | 100.0% |
| `api` | 6 | 0 | 6 | 100.0% |
| `apidom` | 6 | 0 | 6 | 100.0% |
| `ariaattr` | 6 | 0 | 6 | 100.0% |
| `attr` | 6 | 0 | 6 | 100.0% |
| `attrctx` | 6 | 0 | 6 | 100.0% |
| `booleanattr` | 6 | 0 | 6 | 100.0% |
| `casemanip` | 6 | 0 | 6 | 100.0% |
| `chain` | 6 | 0 | 6 | 100.0% |
| `charlimit` | 6 | 0 | 6 | 100.0% |
| `clientstate` | 6 | 0 | 6 | 100.0% |
| `cmspattern` | 6 | 0 | 6 | 100.0% |
| `commentinj` | 6 | 0 | 6 | 100.0% |
| `complexpage` | 6 | 0 | 6 | 100.0% |
| `condreflect` | 6 | 0 | 6 | 100.0% |
| `css` | 6 | 0 | 6 | 100.0% |
| `ctxv2` | 6 | 0 | 6 | 100.0% |
| `ctype` | 6 | 0 | 6 | 100.0% |
| `customtag` | 6 | 0 | 6 | 100.0% |
| `dashboard` | 6 | 0 | 6 | 100.0% |
| `dataattr` | 6 | 0 | 6 | 100.0% |
| `domctx` | 6 | 0 | 6 | 100.0% |
| `doublereflect` | 6 | 0 | 6 | 100.0% |
| `ecommerce` | 6 | 0 | 6 | 100.0% |
| `email` | 6 | 0 | 6 | 100.0% |
| `embedctx` | 6 | 0 | 6 | 100.0% |
| `encodingedge` | 6 | 0 | 6 | 100.0% |
| `errhandling` | 6 | 0 | 6 | 100.0% |
| `errpage` | 6 | 0 | 6 | 100.0% |
| `formelement` | 6 | 0 | 6 | 100.0% |
| `fragment` | 6 | 0 | 6 | 100.0% |
| `fwoutput` | 6 | 0 | 6 | 100.0% |
| `globalattr` | 6 | 0 | 6 | 100.0% |
| `headless` | 6 | 0 | 6 | 100.0% |
| `import` | 6 | 0 | 6 | 100.0% |
| `inattr` | 6 | 0 | 6 | 100.0% |
| `injs` | 6 | 0 | 6 | 100.0% |
| `inlinestyle` | 6 | 0 | 6 | 100.0% |
| `inputtransform` | 6 | 0 | 6 | 100.0% |
| `jsctx` | 6 | 0 | 6 | 100.0% |
| `jsescape` | 6 | 0 | 6 | 100.0% |
| `jsonctx` | 6 | 0 | 6 | 100.0% |
| `latereflect` | 6 | 0 | 6 | 100.0% |
| `linkcontext` | 6 | 0 | 6 | 100.0% |
| `listiteration` | 6 | 0 | 6 | 100.0% |
| `markdown` | 6 | 0 | 6 | 100.0% |
| `mediacontext` | 6 | 0 | 6 | 100.0% |
| `microdata` | 6 | 0 | 6 | 100.0% |
| `misc` | 6 | 0 | 6 | 100.0% |
| `mixedmethod` | 6 | 0 | 6 | 100.0% |
| `multicontext` | 6 | 0 | 6 | 100.0% |
| `multiline` | 6 | 0 | 6 | 100.0% |
| `multiparam` | 6 | 0 | 6 | 100.0% |
| `multipleoutput` | 6 | 0 | 6 | 100.0% |
| `multivector` | 6 | 0 | 6 | 100.0% |
| `nestedctx` | 6 | 0 | 6 | 100.0% |
| `nestedfilter` | 6 | 0 | 6 | 100.0% |
| `numericcontext` | 6 | 0 | 6 | 100.0% |
| `partialencode` | 6 | 0 | 6 | 100.0% |
| `pathxss` | 6 | 0 | 6 | 100.0% |
| `payloadfilt` | 6 | 0 | 6 | 100.0% |
| `pdiff` | 6 | 0 | 6 | 100.0% |
| `polyctx` | 6 | 0 | 6 | 100.0% |
| `recfilt` | 6 | 0 | 6 | 100.0% |
| `redirectxss` | 6 | 0 | 6 | 100.0% |
| `regexfilt` | 6 | 0 | 6 | 100.0% |
| `replacementfilter` | 6 | 0 | 6 | 100.0% |
| `respheader` | 6 | 0 | 6 | 100.0% |
| `rwpattern` | 6 | 0 | 6 | 100.0% |
| `scriptgadget` | 6 | 0 | 6 | 100.0% |
| `semantictag` | 6 | 0 | 6 | 100.0% |
| `seoctx` | 6 | 0 | 6 | 100.0% |
| `social` | 6 | 0 | 6 | 100.0% |
| `specialchar` | 6 | 0 | 6 | 100.0% |
| `storedpat` | 6 | 0 | 6 | 100.0% |
| `svg` | 6 | 0 | 6 | 100.0% |
| `svgctx` | 6 | 0 | 6 | 100.0% |
| `tablecontext` | 6 | 0 | 6 | 100.0% |
| `tagattrmix` | 6 | 0 | 6 | 100.0% |
| `taintflow` | 6 | 0 | 6 | 100.0% |
| `template` | 6 | 0 | 6 | 100.0% |
| `timing` | 6 | 0 | 6 | 100.0% |
| `tplinject` | 6 | 0 | 6 | 100.0% |
| `truncation` | 6 | 0 | 6 | 100.0% |
| `unicode` | 6 | 0 | 6 | 100.0% |
| `wafv2` | 6 | 0 | 6 | 100.0% |
| `whitespace` | 6 | 0 | 6 | 100.0% |
| `wrappercontext` | 6 | 0 | 6 | 100.0% |
| `xmlctx` | 6 | 0 | 6 | 100.0% |
| `browser` | 5 | 0 | 5 | 100.0% |
| `codeexec` | 5 | 0 | 5 | 100.0% |
| `csti` | 5 | 0 | 5 | 100.0% |
| `dialog` | 5 | 0 | 5 | 100.0% |
| `encmix` | 5 | 0 | 5 | 100.0% |
| `eventhandler` | 5 | 0 | 5 | 100.0% |
| `jquery` | 5 | 0 | 5 | 100.0% |
| `mutfilter` | 5 | 0 | 5 | 100.0% |
| `mxss` | 5 | 0 | 5 | 100.0% |
| `querymethod` | 5 | 0 | 5 | 100.0% |
| `reparse` | 5 | 0 | 5 | 100.0% |
| `shadow` | 5 | 0 | 5 | 100.0% |
| `srcdoc` | 5 | 0 | 5 | 100.0% |
| `trustedtypes` | 5 | 0 | 5 | 100.0% |
| `attrname` | 4 | 0 | 4 | 100.0% |
| `callback` | 4 | 0 | 4 | 100.0% |
| `channel` | 4 | 0 | 4 | 100.0% |
| `clipboard` | 4 | 0 | 4 | 100.0% |
| `dataurl` | 4 | 0 | 4 | 100.0% |
| `dblenc` | 4 | 0 | 4 | 100.0% |
| `decode` | 4 | 0 | 4 | 100.0% |
| `dragdrop` | 4 | 0 | 4 | 100.0% |
| `formaction` | 4 | 0 | 4 | 100.0% |
| `hpp` | 4 | 0 | 4 | 100.0% |
| `htmlunsafe` | 4 | 0 | 4 | 100.0% |
| `inframe` | 4 | 0 | 4 | 100.0% |
| `json` | 4 | 0 | 4 | 100.0% |
| `mobserver` | 4 | 0 | 4 | 100.0% |
| `navsink` | 4 | 0 | 4 | 100.0% |
| `noscript` | 4 | 0 | 4 | 100.0% |
| `path` | 4 | 0 | 4 | 100.0% |
| `racecon` | 4 | 0 | 4 | 100.0% |
| `rsplit` | 4 | 0 | 4 | 100.0% |
| `slot` | 4 | 0 | 4 | 100.0% |
| `srcset` | 4 | 0 | 4 | 100.0% |
| `tplel` | 4 | 0 | 4 | 100.0% |
| `worker` | 4 | 0 | 4 | 100.0% |
| `csp` | 3 | 0 | 3 | 100.0% |
| `mathml` | 3 | 0 | 3 | 100.0% |
| `metarefresh` | 3 | 0 | 3 | 100.0% |
| `polyglot` | 3 | 0 | 3 | 100.0% |
| `popover` | 3 | 0 | 3 | 100.0% |
| `stored` | 3 | 0 | 3 | 100.0% |
| `stream` | 3 | 0 | 3 | 100.0% |
| `history` | 2 | 0 | 2 | 100.0% |
| `opener` | 2 | 0 | 2 | 100.0% |
| `referrer` | 2 | 0 | 2 | 100.0% |
| `service` | 2 | 0 | 2 | 100.0% |
| `storage` | 2 | 0 | 2 | 100.0% |
| `manifest` | 1 | 0 | 1 | 100.0% |

