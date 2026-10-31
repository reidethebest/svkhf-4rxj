"""Statement-level differential check: the original's SQL stream (oracle sql.jsonl) vs a candidate trace.

  python trace_diff.py --oracle runs/X/sql.jsonl --cand trace.jsonl [--context 3]

The candidate trace is JSONL, one {"sql": ...} object per statement in execution order (the Go port's -trace
output). Only data-changing statements are compared: insert/update/delete on LogFile and the
TimeZone insert. Reports the first divergence with context. Exit code 0 only when both streams are identical.
--mask-time LSN: time literals in statements for that LSN are not compared (provably nondeterministic in the original).
"""
import argparse
import json
import re
import sys

TIME_LIT = re.compile(r"'-?\d{4,5}-\d\d-\d\d \d\d:\d\d:\d\d'")


def masked(sql, mask):
    m = re.search(r"values\((\d+),", sql) or re.search(r"LSN\s*=\s*'?(\d+)", sql)
    return TIME_LIT.sub("'<nondet>'", sql) if m and int(m.group(1)) in mask else sql


PREFIXES = ("insert into LogFile", "update LogFile", "delete from LogFile", "insert into TimeZone")


def oracle_stream(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:  # last line cut short when the original died mid-write
            continue
        if e["ev"] != "prepare16":
            continue
        sql = e.get("sql")
        if sql is None:  # hex code units (the statement holds lone surrogates)
            u = e["sql16"]
            raw = b"".join(int(u[i:i + 4], 16).to_bytes(2, "little") for i in range(0, len(u), 4))
            sql = raw.decode("utf-16-le", "surrogatepass")
        if sql.startswith(PREFIXES):
            out.append(sql)
    return out


def cand_stream(path):
    out = []
    for line in open(path, encoding="utf-8", errors="replace"):
        try:
            sql = json.loads(line)["sql"]
        except json.JSONDecodeError:
            continue
        if sql.startswith(PREFIXES):
            out.append(sql)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--cand", required=True)
    ap.add_argument("--context", type=int, default=3)
    ap.add_argument("--mask-time", type=int, action="append", default=[])
    a = ap.parse_args()
    mask = set(a.mask_time)
    o = [masked(x, mask) for x in oracle_stream(a.oracle)]
    c = [masked(x, mask) for x in cand_stream(a.cand)]
    first = next((i for i, (x, y) in enumerate(zip(o, c)) if x != y), None)
    if first is None and len(o) == len(c):
        print(json.dumps({"identical": True, "statements": len(o)}))
        return 0
    if first is None:
        first = min(len(o), len(c))
    lo = max(0, first - a.context)
    print(json.dumps({"identical": False, "oracle_statements": len(o), "cand_statements": len(c), "first_diff": first}))
    for i in range(lo, first + a.context + 1):
        mark = ">>" if i == first else "  "
        print(f"{mark} [{i}] oracle: {o[i] if i < len(o) else '<end>'}")
        print(f"{mark} [{i}] cand  : {c[i] if i < len(c) else '<end>'}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
