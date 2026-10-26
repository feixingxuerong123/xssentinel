# range6 gate status: GREEN

Last run: `python range6/runner.py --engine both --out range6/results.json`
(2026-10-19, Phase 265)

```
sync  r6-pos-dompurify-207   TP   2 high dom_dynamic + 4 low/medium static
sync  r6-neg-dompurify-3417  TN   4 low only
async r6-pos-dompurify-207   TP   2 high dom_dynamic + 4 low/medium static
async r6-neg-dompurify-3417  TN   4 low only
=> TP1 FP0 TN1 FN0 ERR0 (both engines; exit 0)
```

## Why it is green now

Phase 225 found two independent defects on the safe twin:

1. `sanitizer_output_to_innerhtml` was version-blind (fixed in Phase 225);
2. `dom_dynamic` claimed execution it never measured (the self-alert was
   circular), and delivery-only rows were still emitted as `high` with the
   bare probe marker in `proof`.

Phase 226 removed the self-alert, so `executed` became a real measurement.
Phase 261 unified the two engines' emit contract. Phase 265 closed the
remaining class problem:

* `executed=True` -> `dom_dynamic` / high / proof = sink snippet;
* `executed=False` -> `dom_sink_reachability` / low / **no proof**.  This is
  a separate finding class (report, SARIF, fix advice, compliance and the
  console all know it), not a high XSS with a lowered confidence.

The safe twin therefore reports four `low` rows and no high/medium finding.

## The positive still earns browser-executed evidence

The generic html/js/url carriers cannot survive DOMPurify.  Phase 265 added
the range6-measured form/math/mglyph mXSS carrier to `_CARRIER_SHAPES`; the
page's own `alert(token)` is observed on 2.0.7 and is stripped by 3.4.17.
Without that carrier the positive page would only have had a low delivery
hint (the static sanitizer version finding still scored it TP), so this is
measured both ways.

## What is locked

* `tests/test_range6.py` (7 cases, green): construct validity, twin
  difference, vendor integrity, gate semantics, live pair.
* `tests/test_dom_dynamic_evidence.py`: the class chooser, the evidence
  contract, both call sites, and the new type's report/advice/compliance
  wiring.
* CI now runs this gate (`Range #6 sanitizer drill`) on every push, after
  range4/range5.  A regression on either twin fails the job.
