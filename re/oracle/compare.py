"""Compare a candidate run against a reference run of NTFS Log Tracker ($LogFile path only).

  python compare.py --ref-db A.db --cand-db B.db [--ref-csv A.csv --cand-csv B.csv] [--json report.json]

DB: LogFile table compared row by row on LSN, every column and the rowid, plus the TimeZone table.
CSV: byte comparison; on mismatch reports the first differing line and column.
Exit code 0 only when everything is identical.

--mask-time LSN (repeatable): the four time columns of that row are not compared (DB and CSV). Only for rows where
the original is provably nondeterministic (AdjustTimeString on an uninitialised FILETIME).
--long-field-units N: a CSV field whose candidate text has N or more bytes is compared on its first N bytes only.
The original reads each value back through a buffer in a dead stack frame whose tail is overwritten with stack
garbage before the copy (SPEC 8.5, U10); two runs of the original differ there (vhd2-018, vhd2-041).
"""
import argparse
import csv
import io
import json
import sqlite3
import sys

TIME_COLS = ("CreateTime", "ModifiedTIme", "MFT_ModifiedTime", "AccessTime")
COLS = ["LSN", "EventTime", "Event", "Detail", "FileName", "FullPath", "CreateTime", "ModifiedTIme",
        "MFT_ModifiedTime", "AccessTime", "RedoInfo", "TargetVCN", "MFT_ClusterIndex"]


def rows(path):
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    data = {r[0]: r for r in c.execute(f"select {', '.join(COLS)}, rowid from LogFile")}
    tz = c.execute("select UTC, DST from TimeZone").fetchall()
    return data, tz


def compare_db(ref, cand, report, limit, mask):
    r, rtz = rows(ref)
    c, ctz = rows(cand)
    report["db"] = {"ref_rows": len(r), "cand_rows": len(c), "timezone_equal": rtz == ctz, "ref_tz": rtz, "cand_tz": ctz}
    missing = sorted(set(r) - set(c))
    extra = sorted(set(c) - set(r))
    col_diffs = {k: 0 for k in COLS[1:] + ["rowid"]}
    examples = []
    for lsn in sorted(set(r) & set(c)):
        if r[lsn] != c[lsn]:
            for i, k in enumerate(COLS[1:] + ["rowid"], 1):
                if r[lsn][i] != c[lsn][i] and not (lsn in mask and k in TIME_COLS):
                    col_diffs[k] += 1
                    if len(examples) < limit:
                        examples.append({"lsn": lsn, "column": k, "ref": r[lsn][i], "cand": c[lsn][i]})
    report["db"].update({
        "missing_in_cand": len(missing), "missing_examples": missing[:limit],
        "extra_in_cand": len(extra), "extra_examples": extra[:limit],
        "column_mismatches": {k: v for k, v in col_diffs.items() if v}, "examples": examples,
    })
    return not missing and not extra and not any(col_diffs.values()) and rtz == ctz


def mask_csv(data, mask):
    if not mask:
        return data
    lines = data.split(b"\r\n")
    for i, l in enumerate(lines):
        f = l.split(b",")
        lsn = f[0].strip(b'"')
        if len(f) > 9 and lsn.isdigit() and int(lsn) in mask:
            f[6:10] = [b"<nondet>"] * 4
            lines[i] = b",".join(f)
    return b"\r\n".join(lines)


def mask_long_fields(a, b, n):
    """Cut both files' fields at n bytes wherever the candidate field has n or more bytes (lines aligned)."""
    la, lb = a.split(b"\r\n"), b.split(b"\r\n")
    if not n or len(la) != len(lb):
        return a, b, 0
    count = 0
    for i, (x, y) in enumerate(zip(la, lb)):
        fx, fy = x.split(b'","'), y.split(b'","')
        if len(fx) != len(fy) or not any(len(f) >= n for f in fy):
            continue
        for j, f in enumerate(fy):
            if len(f) >= n:
                fx[j], fy[j] = fx[j][:n] + b"<U10>", f[:n] + b"<U10>"
                count += 1
        la[i], lb[i] = b'","'.join(fx), b'","'.join(fy)
    return b"\r\n".join(la), b"\r\n".join(lb), count


def compare_csv(ref, cand, report, mask, long_units=0):
    a, b = mask_csv(open(ref, "rb").read(), mask), mask_csv(open(cand, "rb").read(), mask)
    a, b, masked = mask_long_fields(a, b, long_units)
    out = {"ref_bytes": len(a), "cand_bytes": len(b), "identical": a == b, "masked_long_fields": masked}
    if a != b:
        la, lb = a.split(b"\r\n"), b.split(b"\r\n")
        for i, (x, y) in enumerate(zip(la, lb)):
            if x != y:
                fx = next(csv.reader(io.StringIO(x.decode("latin-1"))), [])
                fy = next(csv.reader(io.StringIO(y.decode("latin-1"))), [])
                col = next((j for j, (p, q) in enumerate(zip(fx, fy)) if p != q), min(len(fx), len(fy)))
                out["first_diff"] = {"line": i + 1, "field": col, "ref": x[:400].decode("latin-1"), "cand": y[:400].decode("latin-1")}
                break
        else:
            out["first_diff"] = {"line": min(len(la), len(lb)) + 1, "note": "one file is a prefix of the other"}
        out["ref_lines"], out["cand_lines"] = len(la), len(lb)
    report["csv"] = out
    return a == b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref-db", required=True)
    ap.add_argument("--cand-db", required=True)
    ap.add_argument("--ref-csv")
    ap.add_argument("--cand-csv")
    ap.add_argument("--json")
    ap.add_argument("--examples", type=int, default=20)
    ap.add_argument("--mask-time", type=int, action="append", default=[])
    ap.add_argument("--long-field-units", type=int, default=0)
    a = ap.parse_args()
    report = {}
    ok = compare_db(a.ref_db, a.cand_db, report, a.examples, set(a.mask_time))
    if a.ref_csv and a.cand_csv:
        ok = compare_csv(a.ref_csv, a.cand_csv, report, set(a.mask_time), a.long_field_units) and ok
    report["identical"] = ok
    report["masked_time_lsns"] = sorted(a.mask_time)
    text = json.dumps(report, indent=1)
    if a.json:
        open(a.json, "w", encoding="utf-8").write(text)
    print(text)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
