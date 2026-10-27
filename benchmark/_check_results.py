"""Check latest benchmark results."""
import json
import glob
import sys
import os
sys.stdout = open(sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1)
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

files = sorted(glob.glob('benchmark/results/benchmark_*.json'))
if not files:
    print("No results found")
    sys.exit(1)

f = files[-1]
print(f"File: {f}")
d = json.load(open(f))
print(f"TP={d['tp']} FP={d['fp']} TN={d['tn']} FN={d['fn']}")
print(f"Recall={d['recall']:.2%} FPR={d['fpr']:.2%} Precision={d['precision']:.4f} F1={d['f1']:.4f}")
print()

# Show FP details
fps = d.get('false_positives', [])
print(f"=== FALSE POSITIVES ({len(fps)}) ===")
for c in fps:
    cid = c if isinstance(c, str) else c.get('id', c)
    print(f"  {cid}")

# Show FN details
fns = d.get('false_negatives', [])
print(f"\n=== FALSE NEGATIVES ({len(fns)}) ===")
for c in fns:
    cid = c if isinstance(c, str) else c.get('id', c)
    print(f"  {cid}")
