"""Dump FP/FN details from the latest benchmark result."""
import json, sys, os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)

results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
files = sorted([f for f in os.listdir(results_dir) if f.startswith("benchmark_") and f.endswith(".json") and "_summary" not in f], reverse=True)
if not files:
    print("No results found")
    sys.exit(1)

path = os.path.join(results_dir, files[0])
print(f"Reading: {path}\n")
data = json.load(open(path, "r", encoding="utf-8"))

fps = [c for c in data["cases"] if c["verdict"] == "FP"]
fns = [c for c in data["cases"] if c["verdict"] == "FN"]

print(f"=== FALSE POSITIVES ({len(fps)}) ===")
for c in fps:
    print(f"\n  {c['case_id']} | mode={c['mode']} | ctx={c['context']}")
    for d in c.get("finding_details", []):
        print(f"    payload: {d.get('payload','')[:80]}")
        print(f"    context: {d.get('context','')} | severity: {d.get('severity','')} | confidence: {d.get('confidence','')}")

print(f"\n=== FALSE NEGATIVES ({len(fns)}) ===")
for c in fns:
    print(f"  {c['case_id']} | mode={c['mode']} | ctx={c['context']} | diff={c['difficulty']}")
