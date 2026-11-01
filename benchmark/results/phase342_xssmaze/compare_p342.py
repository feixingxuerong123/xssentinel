#!/usr/bin/env python3
"""Three-way cross-tool comparison on the XSSMaze official scorecards (p342).

Reads the OFFICIAL runner JSON for each arm (the runner stays the only
scorer -- this script never re-scores a URL; it joins what the runner
already printed) and emits a comparison table + JSON:

  python compare_p342.py XSSentinel=server_p341.json \
      dalfox=server_dalfox_p342.json nuclei=server_nuclei_p342.json \
      --meta p342_meta.json --out cross_tool_p342

Arm names before `=` are free-form labels.  Every scorecard must come from
the same reach mode and the same catalog (checked).  Per-class rows use the
runner's own by_class; a class a tool never saw is rendered 0/- not omitted.
"""
import argparse
import json
import sys


def load_scanner(path):
    doc = json.load(open(path, encoding="utf-8"))
    scan = doc["scanners"][0]
    if scan.get("skipped"):
        raise SystemExit(f"{path}: scanner skipped: {scan.get('skip_reason')}")
    return scan


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("arms", nargs="+", help="Label=path/to/runner.json")
    ap.add_argument("--meta", help="p342_meta.json for the fingerprint block")
    ap.add_argument("--out", help="output basename: writes .md and .json")
    args = ap.parse_args()

    arms = []
    for spec in args.arms:
        label, path = spec.split("=", 1)
        scan = load_scanner(path)
        arms.append((label, path, scan))

    reach = set(arms[0][2]["by_reach"])
    for label, _, scan in arms[1:]:
        if set(scan["by_reach"]) != reach:
            print(f"WARNING: {label} by_reach keys differ from the first arm",
                  file=sys.stderr)

    meta = json.load(open(args.meta, encoding="utf-8")) if args.meta else {}

    # ---- headline -------------------------------------------------------
    lines = []
    lines.append("# Phase 342 — cross-tool on the XSSMaze official target\n")
    lines.append("| tool | TP | FN | FP(controls) | P | R | F1 | wall |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for label, _, s in arms:
        lines.append(
            f"| {label} | {s['true_positives']} | {s['false_negatives']} | "
            f"{s['false_positives_on_controls']} | {s['precision']:.3f} | "
            f"{s['recall']:.3f} | {s['f1']:.3f} | {s['execution_time']:.0f}s |")
    lines.append("")

    # ---- per-class ------------------------------------------------------
    classes = sorted({c for _, _, s in arms for c in s["by_class"]})
    lines.append("## Per class (detected / population)\n")
    lines.append("| class | " + " | ".join(label for label, _, _ in arms) + " |")
    lines.append("|---|" + "---|" * len(arms))
    for c in classes:
        row = []
        for _, _, s in arms:
            d = s["by_class"].get(c) or {}
            row.append(f"{d.get('detected', 0)}/{d.get('total', 0)}")
        lines.append(f"| {c} | " + " | ".join(row) + " |")
    lines.append("")

    # ---- controls -------------------------------------------------------
    lines.append("## Control endpoints claimed (FP side)\n")
    for label, _, s in arms:
        lines.append(f"- **{label}**: {len(s['detected_controls'])}"
                     + (f" → {s['detected_controls']}"
                        if s["detected_controls"] else ""))
    lines.append("")

    # ---- fingerprints ---------------------------------------------------
    lines.append("## Fingerprints & contracts\n")
    lines.append("```json")
    lines.append(json.dumps(meta, ensure_ascii=False, indent=2))
    lines.append("```")

    report = "\n".join(lines) + "\n"
    print(report)

    if args.out:
        with open(args.out + ".md", "w", encoding="utf-8") as fh:
            fh.write(report)
        data = {
            "meta": meta,
            "arms": {
                label: {
                    "runner_json": path,
                    "population": s["population"],
                    "tp": s["true_positives"],
                    "fn": s["false_negatives"],
                    "fp_controls": s["false_positives_on_controls"],
                    "fp_unmatched": s["false_positives_unmatched"],
                    "precision": s["precision"],
                    "recall": s["recall"],
                    "f1": s["f1"],
                    "wall_s": s["execution_time"],
                    "by_class": s["by_class"],
                    "detected_controls": s["detected_controls"],
                    "missed": s["missed"],
                }
                for label, path, s in arms
            },
        }
        with open(args.out + ".json", "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print(f"wrote {args.out}.md and {args.out}.json")


if __name__ == "__main__":
    main()
