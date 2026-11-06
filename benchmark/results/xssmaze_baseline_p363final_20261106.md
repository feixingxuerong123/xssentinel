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
| XSSentinel | 969 | 44 | 0 | 100.0% | 95.7% | 0.978 | 1588.4s |

## Detailed Results

### XSSentinel

- **Reported findings:** 969
- **True positives:** 969/1013
- **False negatives:** 44/1013
- **False positives:** 0 (0 on controls, 0 on non-maze paths)
- **Precision / Recall / F1:** 100.0% / 95.7% / 0.978

**By Vulnerability Class:**

| Key | Detected | Missed | Total | Rate |
|-----|----------|--------|-------|------|
| `reflected-html` | 436 | 30 | 466 | 93.6% |
| `reflected-attr` | 252 | 6 | 258 | 97.7% |
| `dom` | 170 | 4 | 174 | 97.7% |
| `reflected-js` | 92 | 3 | 95 | 96.8% |
| `stored` | 9 | 1 | 10 | 90.0% |
| `csti` | 5 | 0 | 5 | 100.0% |
| `prototype-pollution` | 5 | 0 | 5 | 100.0% |

**By Category:**

| Key | Detected | Missed | Total | Rate |
|-----|----------|--------|-------|------|
| `postmethod` | 0 | 6 | 6 | 0.0% |
| `headless` | 1 | 5 | 6 | 16.7% |
| `headerinj` | 3 | 3 | 6 | 50.0% |
| `multipart` | 1 | 3 | 4 | 25.0% |
| `modern` | 28 | 2 | 30 | 93.3% |
| `dom` | 23 | 2 | 25 | 92.0% |
| `sanitizer` | 9 | 2 | 11 | 81.8% |
| `realworld_input` | 5 | 2 | 7 | 71.4% |
| `noscript` | 2 | 2 | 4 | 50.0% |
| `post` | 0 | 2 | 2 | 0.0% |
| `realworld` | 14 | 1 | 15 | 93.3% |
| `bugbounty` | 8 | 1 | 9 | 88.9% |
| `domsink` | 7 | 1 | 8 | 87.5% |
| `edge` | 7 | 1 | 8 | 87.5% |
| `html5` | 7 | 1 | 8 | 87.5% |
| `edgefilter` | 5 | 1 | 6 | 83.3% |
| `encodingedge` | 5 | 1 | 6 | 83.3% |
| `obfuscation` | 5 | 1 | 6 | 83.3% |
| `url` | 5 | 1 | 6 | 83.3% |
| `cspbypass` | 4 | 1 | 5 | 80.0% |
| `domsource` | 4 | 1 | 5 | 80.0% |
| `callback` | 3 | 1 | 4 | 75.0% |
| `header` | 3 | 1 | 4 | 75.0% |
| `nonce` | 2 | 1 | 3 | 66.7% |
| `jf` | 0 | 1 | 1 | 0.0% |
| `waf` | 14 | 0 | 14 | 100.0% |
| `prototype` | 10 | 0 | 10 | 100.0% |
| `hidden` | 9 | 0 | 9 | 100.0% |
| `ctxescape` | 8 | 0 | 8 | 100.0% |
| `filterchain` | 8 | 0 | 8 | 100.0% |
| `multireflect` | 8 | 0 | 8 | 100.0% |
| `regexbypass` | 8 | 0 | 8 | 100.0% |
| `scanbounty` | 8 | 0 | 8 | 100.0% |
| `sink` | 8 | 0 | 8 | 100.0% |
| `specialtag` | 8 | 0 | 8 | 100.0% |
| `basic` | 7 | 0 | 7 | 100.0% |
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
| `errhandling` | 6 | 0 | 6 | 100.0% |
| `errpage` | 6 | 0 | 6 | 100.0% |
| `formelement` | 6 | 0 | 6 | 100.0% |
| `fragment` | 6 | 0 | 6 | 100.0% |
| `fwoutput` | 6 | 0 | 6 | 100.0% |
| `globalattr` | 6 | 0 | 6 | 100.0% |
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

