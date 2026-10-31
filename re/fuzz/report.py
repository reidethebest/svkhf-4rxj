"""Summarise fuzz/results: verdict counts per family and every non-matching case with its first difference."""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
rows = []
for vp in sorted((ROOT / "fuzz" / "results").glob("*/verdict.json")):
    try:
        rows.append(json.loads(vp.read_text(encoding="utf-8")))
    except ValueError:
        pass
fam = Counter((r.get("family") or "?", r["verdict"]) for r in rows)
print("total", len(rows), dict(Counter(r["verdict"] for r in rows)))
for (f, v), n in sorted(fam.items()):
    print(f"  {f:14} {v:18} {n}")
for r in rows:
    if r["verdict"].startswith("match"):
        continue
    print(f"\n{r['case']}: {r['verdict']} oracle={r['oracle']} go={r['go']} diff@{r['first_diff']} "
          f"stmts {r['oracle_statements']}/{r['go_statements']} det={r.get('oracle_deterministic')}")
    print("   desc:", (r.get("desc") or "")[:200])
    if r.get("oracle_at_diff") or r.get("go_at_diff"):
        print("   O:", (r.get("oracle_at_diff") or "")[-230:])
        print("   G:", (r.get("go_at_diff") or "")[-230:])
    print("   od:", r.get("oracle_detail"), "| gd:", r.get("go_detail"))
