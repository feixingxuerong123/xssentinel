# range6 gate status: RED by design (known defect, measured)

Last run: `python range6/runner.py --engine both` (2026-10-13, post-fix)

```
sync  r6-pos-dompurify-207   TP   6 findings
sync  r6-neg-dompurify-3417  FP   4 findings
async r6-pos-dompurify-207   TP   6 findings
async r6-neg-dompurify-3417  FP   4 findings
=> TP1 FP1 TN0 FN0 ERR0 (both engines)
```

The safe twin's four findings, all measured on the current tree:

```
high dom_dynamic                     <- the ONE remaining cause (P1, below)
low  trusted_types_taint_flow        <- fixed (graded by sanitizer mediation)
low  trusted_types_no_policy         <- fixed (same)
low  sanitizer_output_to_innerhtml   <- fixed (version-graded)
```

The red has converged from THREE causes to ONE. The gate is **not** wired
into CI while it is red; the P1 fix is the commit that switches it on. It is
kept here, with the measurement, because a red gate that nobody can see is a
gate that does not gate; the runner and the manifest are the instrument, and
this file is the reason it is not yet switched on.

## Why the negative case is red

Three independent causes; two are fixed, one is not.

### Fixed (Phase 225) — `sanitizer_output_to_innerhtml` was version-blind

The note fired at **medium** on every sanitize()->innerHTML flow, so the
canonical correct usage (a current sanitizer whose output goes to innerHTML)
was reported as a medium "mXSS risk" on a page whose CVE-2020-26870 payload
is provably stripped. It is now graded by evidence: a recognised version
outside every vulnerable range -> low; unknown version or a vulnerable
version present -> medium (unchanged).

### Fixed (Phase 225, continuation) — the TT pair claimed exploitability the page refutes

`trusted_types_taint_flow` ("a concrete DOM-XSS finding" per the layer's own
comment) and `trusted_types_no_policy` ("trivially exploitable") both fired
at **medium** on the safe twin. The project had dodged this shape twice
rather than grading it -- `benchmark/server.py`'s `m_sanitizer_safe` uses
textContent because "the layer flags any sanitise->innerHTML flow", and the
Phase 128b fixture note says the innerHTML family "would make the SAFE twin
emit trusted_types_no_policy (medium), turning a correct case into a red
gate" (so it used DOMParser). The dodges are why it stayed invisible.

Now graded by sanitizer mediation: a recognised sanitizer between source and
sink (the vocabulary imported from the sanitizer layer) keeps the flow
reported -- the write IS still TT-unprotected, which is this layer's subject
-- but at **low**, naming the sanitizer; `policy.createHTML` still drops the
flow entirely; one unmediated write path keeps the medium claim (reverse
guard tested).  Tests: `tests/test_tt_sanitizer_mediation.py` (8 cases, two
counterproofs).  The same round also fixed an attribution weakness the new
tests exposed: `find_taint_flows` took the FIRST taint source in the window
instead of the one nearest the sink, so two adjacent statements could credit
a raw write's flow to the other statement's `sanitize()` call.

### NOT fixed — `dom_dynamic` claims execution it never measured

The negative twin reports:

```
high  dom_dynamic  evidence_class=browser-executed  headless.outcome=fired
"DOM XSS CONFIRMED in real browser: attacker-controlled source
 'location.search' reached executable sink 'Element.innerHTML'
 (marker executed)."
```

The browser says otherwise. `dev/_r6_fp_probe.py` replays the engine's own
recorded value (`payload: xssentinel_dom_<hex>`, a bare taint token) on both
twins:

```
/safe?q=xssentinel_dom_d94d341b
   #out.innerHTML = 'xssentinel_dom_d94d341b'   (plain text)
   marker in DOM  = True      dialogs = []      silent
/safe?q=<img src=x onerror=alert('EXEC')>
   #out.innerHTML = '<img src="x">'             dialogs = []      silent
```

No dialog, no live element, on either page. The mechanism:

1. probes inject a **bare marker**, not an executable payload;
2. `_init_script`'s `hit()` records a hit whenever the marker appears in any
   hooked sink's input **and then calls `alert(MARKER)` itself**;
3. `analyze()` turns every hit into `dom_dynamic` / high / high
   "… (marker executed)";
4. `scanner_layers.py:197` (async: `async_scanner_layers.py:233`) hardcodes
   `{"confirmed": True, "outcome": "fired", "detail": "marker executed in
   real browser sink"}`.

So `browser-executed`, `fired` and high/high are constants, and the "hard
proof" is the instrument's own dialog. The page's sanitizer is invisible to
this reasoning: sanitized taint reaches the sink exactly like unsanitized
taint does.

Fixing it means changing what the DOM engine claims to know (probe corpus +
grading), i.e. a judgement-semantics change with the full acceptance set;
it is recorded as the next phase rather than bolted on here.

## What is already locked

`tests/test_range6.py` (7 cases, green, in CI) proves everything about this
range that does not depend on the defect above:

* construct validity: served bytes are query-independent, attacker string
  absent from server bytes;
* the twins differ in exactly one place (the vendored version);
* vendor integrity + `integrity.txt` pins (tarball URL + sha512);
* gate/manifest semantics, including the rule that a demoted low mXSS note
  is not a false positive;
* **the live pair**: the PoC really executes through 2.0.7 (dialog) and is
  really stripped by 3.4.17 (no live element, no dialog).

The last one is what makes "vulnerable"/"safe" measured labels rather than
labels copied out of an advisory table.
