"""Compare two benchmark runner JSONs case by case (Phase 211 groundwork).

Purpose: make "this refactor changed nothing" a measurement instead of a
claim.  Summary counters (TP/FP/FN) can stay identical while per-case
verdicts, request counts or finding types shift underneath -- Phase 208b
proved the point in reverse: the summary was bit-identical to the Phase 206
baseline AND there was still exactly one intended difference
(/r/url03 reclassified).  Only a per-case diff shows that.

    python dev/_p211_compare_baseline.py OLD.json NEW.json

Exit status: 0 = identical (or only white-listed fields differ), 1 = differs.
"""
import json
import sys

# Fields compared per case.  Deliberately excludes timing and anything
# engine-run dependent: wall time on this host swings 8x on its own.
FIELDS = ("verdict", "detected", "findings_count", "error")


def _finding_shape(fd):
    """Normalised finding fingerprint: type/severity/confidence/param/payload.

    Payload carries a per-run random marker, so it is compared by SHAPE
    (length + whether it is a polyglot), not verbatim.
    """
    out = []
    for f in (fd or []):
        payload = str(f.get("payload") or "")
        out.append((
            f.get("type"),
            f.get("severity"),
            f.get("confidence"),
            f.get("param"),
            f.get("context"),
            len(payload),
            "<svg" in payload or "onerror" in payload,
        ))
    return sorted(out)


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    old, new = load(sys.argv[1]), load(sys.argv[2])
    o_cases = {c["case_id"]: c for c in old.get("cases", [])}
    n_cases = {c["case_id"]: c for c in new.get("cases", [])}

    only_old = sorted(set(o_cases) - set(n_cases))
    only_new = sorted(set(n_cases) - set(o_cases))
    diffs = []
    payload_heavy = []
    no_detail = 0

    for cid in sorted(set(o_cases) & set(n_cases)):
        o, n = o_cases[cid], n_cases[cid]
        for f in FIELDS:
            if o.get(f) != n.get(f):
                diffs.append((cid, f, o.get(f), n.get(f)))
        # Older result files (e.g. the Phase 206 full matrix) do not carry
        # finding_details at all.  Absence is NOT "no findings" -- compare
        # only when both sides have the field, and say so otherwise.
        o_det, n_det = o.get("finding_details"), n.get("finding_details")
        if o_det is None or n_det is None:
            no_detail += 1
        else:
            os_, ns_ = _finding_shape(o_det), _finding_shape(n_det)
            if os_ != ns_:
                diffs.append((cid, "finding_details", os_, ns_))
        # Request count is a real behavioural signal but is noisy on this
        # host (a dropped loopback connection changes it).  Report, don't fail.
        if abs((o.get("requests") or 0) - (n.get("requests") or 0)) > 0:
            payload_heavy.append(
                (cid, o.get("requests"), n.get("requests")))

    print(f"cases: old={len(o_cases)} new={len(n_cases)}")
    print(f"summary old: TP{old.get('tp')} FP{old.get('fp')} "
          f"TN{old.get('tn')} FN{old.get('fn')} ERR{old.get('errors')}")
    print(f"summary new: TP{new.get('tp')} FP{new.get('fp')} "
          f"TN{new.get('tn')} FN{new.get('fn')} ERR{new.get('errors')}")

    if only_old:
        print(f"only in OLD ({len(only_old)}): {only_old[:10]}")
    if only_new:
        print(f"only in NEW ({len(only_new)}): {only_new[:10]}")

    if no_detail:
        print(f"finding-level comparison SKIPPED for {no_detail} cases "
              f"(one or both files lack 'finding_details')")
    print(f"per-case differences: {len(diffs)}")
    for cid, field, ov, nv in diffs[:20]:
        print(f"  {cid} :: {field}")
        print(f"     old={ov}")
        print(f"     new={nv}")

    print(f"request-count differences (informational): {len(payload_heavy)}")
    for cid, ov, nv in payload_heavy[:10]:
        print(f"  {cid}: {ov} -> {nv}")

    return 0 if not diffs and not only_old and not only_new else 1


if __name__ == "__main__":
    sys.exit(main())
