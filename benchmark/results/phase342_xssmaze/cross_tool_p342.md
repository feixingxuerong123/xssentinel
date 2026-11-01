# Phase 342 — cross-tool on the XSSMaze official target

| tool | TP | FN | FP(controls) | P | R | F1 | wall |
|---|---|---|---|---|---|---|---|
| XSSentinel | 944 | 69 | 0 | 1.000 | 0.932 | 0.965 | 5741s |
| dalfox | 757 | 256 | 4 | 0.995 | 0.747 | 0.853 | 4072s |
| nuclei | 731 | 282 | 4 | 0.995 | 0.722 | 0.836 | 406s |

## Per class (detected / population)

| class | XSSentinel | dalfox | nuclei |
|---|---|---|---|
| csti | 5/5 | 3/5 | 3/5 |
| dom | 170/174 | 75/174 | 50/174 |
| prototype-pollution | 5/5 | 3/5 | 3/5 |
| reflected-attr | 246/258 | 221/258 | 209/258 |
| reflected-html | 427/466 | 377/466 | 394/466 |
| reflected-js | 89/95 | 78/95 | 72/95 |
| stored | 2/10 | 0/10 | 0/10 |

## Control endpoints claimed (FP side)

- **XSSentinel**: 0
- **dalfox**: 4 → ['csp-bypass-level3', 'cspbypass-level3', 'nonce-level2', 'waf-bypass-level3']
- **nuclei**: 4 → ['csp-bypass-level3', 'csp-bypass-level4', 'cspbypass-level3', 'nonce-level2']

## Fingerprints & contracts

```json
{
  "phase": "342",
  "date": "2026-10-30",
  "tree_head": "1073ec4 (detection surface byte-identical to 8e6bce5 = p341 baseline; 8e6bce5..1073ec4 touches evidence JSON only)",
  "target": {
    "image": "ghcr.io/hahwul/xssmaze:main",
    "image_digest": "sha256:35bb3c7d314f6287f05cc60a71165e4ac824475fb0268fcd0c30b35595d67086",
    "container_started": "2026-10-29T10:28:20Z",
    "base_url": "http://127.0.0.1:3001",
    "version": "v0.3.0"
  },
  "runner": {
    "file": "dev/_xssmaze/benchmark.py (vendored hahwul/xssmaze@main scripts/benchmark.py)",
    "mode": "--reach server, per-URL custom-scanner, one invocation per endpoint, no retries",
    "detect_contract": "--detect-json 'findings[].url'",
    "scanner_timeout": 180,
    "scoring": "official runner is the authoritative scorer; xsleak = correct silence (contract 322d, benchmark/xssmaze_scoring.py cross-check)"
  },
  "arms": {
    "XSSentinel": {
      "source": "reused official p341 scorecard (server_p341.json); NOT re-run",
      "reason": "zero detection-surface commits between the p341 run tree and this tree",
      "wrapper": "wrapper.py (XSSMAZE_TIMEOUT=100, sync, no --headless)"
    },
    "dalfox": {
      "version": "v2.13.0 (C:/GoWorkspace/bin/dalfox.exe)",
      "wrapper": "wrapper_dalfox.py (XSSMAZE_TIMEOUT=100)",
      "cmd": "dalfox url <url> --format json --silence --skip-headless; stdin=DEVNULL",
      "deviations": [
        "--skip-headless: chromedp headless layer host-unstable (panic close-of-closed-channel allocate.go:233; teardown hangs; ~50% of invocations; on plain localhost too). 5/5 stable with skip. Headless-layer contribution quantified separately on a sample.",
        "default workers (no --worker 1): worker=1 serialized the ~2000-query battery into 60-100s+/case on multi-param XSSMaze pages (level1 hit the 100s cap, level2 74.7s); default workers complete the same pages in 1-2s.",
        "stdin=DEVNULL: dalfox treats a non-terminal stdin as a piped URL list and blocks (measured: 60s wrapper timeouts in-wrapper vs 1.1s `[{}]` under a bash pipe vs 5.8s real scan with DEVNULL).",
        "forward V/found entries only: dalfox v2.13.0 emits R entries (Reflected Payload in HTML, message_id 464, severity Medium) carrying payload fields; counting them would score every reflection candidate as detection (level3 measured R:507 vs V:1). TSV types column keeps the full census for offline re-scoring under any contract."
      ]
    },
    "nuclei": {
      "version": "v3.11.1 (~/go/bin/nuclei.exe)",
      "wrapper": "wrapper_nuclei.py (XSSMAZE_TIMEOUT=100)",
      "cmd": "nuclei -u <url> -dast -t ~/nuclei-templates/dast/vulnerabilities/xss -jsonl -silent -no-color -timeout 10 -retries 1 -duc -nc; stdin=DEVNULL",
      "deviations": [
        "per-URL custom-scanner mode instead of the runner's built-in batch nuclei (batch = one 900s subprocess for all 1040 URLs, no per-case timing or attribution)",
        "hit = JSONL line with info.severity medium/high/critical (the 196b contract; info-level reflection detections are not vulnerability claims)",
        "-duc/-nc load-bearing: template-update probe hangs the full ceiling on this proxied host (196b)"
      ]
    }
  },
  "population": {
    "server": 1013,
    "controls": 27
  }
}
```
