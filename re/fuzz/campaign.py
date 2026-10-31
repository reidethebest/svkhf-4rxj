"""Differential campaign: run the original (Frida oracle) and the Go port on every generated case and classify.

  python re/fuzz/campaign.py [--filter S] [--max-seconds N] [--go-only] [--rerun] [--oracle-timeout 240]
                             [--worker K --workers N]

Case layout (written by the generators):  fuzz/cases/<id>/$LogFile, optional fuzz/cases/<id>/$MFT,
fuzz/cases/<id>/case.json = {"utc": int, "dst": bool, "mft": bool, "family": str, "desc": str}.

Results: fuzz/results/<id>/{oracle/, oracle2/, cand.*, verdict.json}; fuzz/summary.json.
Each worker K of N takes every N-th case and runs its own instance of the original in fuzz/work/wK (own log.txt);
a lock file per worker keeps one instance per slot. Resumable: cases with a
verdict are skipped unless --rerun. --go-only re-checks the port against the stored oracle outputs (regression).
Divergent cases get a second oracle run (oracle2) to tell nondeterminism in the original from port bugs.
"""
import argparse
import json
import msvcrt
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES, RESULTS = ROOT / "fuzz" / "cases", ROOT / "fuzz" / "results"
GO = ROOT / "re" / "bin" / "ntfslog.exe"
ORACLE = ROOT / "re" / "oracle" / "oracle.py"
sys.path.insert(0, str(ROOT / "re" / "oracle"))
from trace_diff import cand_stream, masked, oracle_stream  # noqa: E402

PY = sys.executable


WORKER = 0


class OracleLock:
    def __enter__(self):
        self.f = open(ROOT / "fuzz" / f"oracle.lock.{WORKER}", "a+")
        while True:
            try:
                msvcrt.locking(self.f.fileno(), msvcrt.LK_NBLCK, 1)
                return self
            except OSError:
                time.sleep(1)

    def __exit__(self, *exc):
        self.f.seek(0)
        msvcrt.locking(self.f.fileno(), msvcrt.LK_UNLCK, 1)
        self.f.close()


def kill_spawned(out):
    """Kill the original instance this run spawned (pid.txt), never any other process. PIDs are reused, so the PID
    must still name an NTFS Log Tracker process created within 30 s of pid.txt being written."""
    pidf = out / "pid.txt"
    try:
        pid, written = pidf.read_text().strip(), pidf.stat().st_mtime
    except OSError:
        return
    if not pid.isdigit():
        return
    info = subprocess.run(["wmic", "process", "where", f"processid={pid}", "get", "name,creationdate",
                           "/format:list"], capture_output=True, text=True).stdout
    kv = dict(l.strip().split("=", 1) for l in info.splitlines() if "=" in l)
    if not kv.get("Name", "").startswith("NTFS") or len(kv.get("CreationDate", "")) < 14:
        return
    created = time.mktime(time.strptime(kv["CreationDate"][:14], "%Y%m%d%H%M%S"))
    if abs(created - written) < 30:
        subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True)


def workdir():
    d = ROOT / "fuzz" / "work" / f"w{WORKER}"
    d.mkdir(parents=True, exist_ok=True)
    return d


def clear_dir(out):
    out.mkdir(parents=True, exist_ok=True)
    for _ in range(30):
        kill_spawned(out)
        try:
            for f in out.iterdir():
                f.unlink()
            return
        except PermissionError:
            time.sleep(1)
    raise RuntimeError(f"cannot clear {out}")


def parse_started(out):
    """True once the Parse Setting dialog was confirmed (its folder browse is answered just before OK)."""
    p = out / "sql.jsonl"
    return p.exists() and '"ev":"browse_folder"' in p.read_text(encoding="utf-8", errors="replace")


def run_oracle(case, cj, out, timeout):
    clear_dir(out)
    cmd = [PY, str(ORACLE), "--logfile", str(case / "$LogFile"), "--out", str(out), "--utc", str(cj["utc"]),
           "--timeout", str(timeout), "--cwd", str(workdir())]
    if cj.get("dst"):
        cmd.append("--dst")
    if cj.get("mft"):
        cmd += ["--mft", str(case / "$MFT")]
    with OracleLock():
        t0 = time.time()
        # Output goes to files, not pipes: the spawned original inherits the handles and would keep a pipe open.
        with open(out / "oracle.stdout.txt", "wb") as so, open(out / "oracle.stderr.txt", "wb") as se:
            try:
                rc = subprocess.run(cmd, stdout=so, stderr=se, timeout=timeout + 90).returncode
            except subprocess.TimeoutExpired:
                rc = None
        err = (out / "oracle.stderr.txt").read_text(encoding="utf-8", errors="replace")
        if rc is None:
            err += "\ndriver timeout"
        kill_spawned(out)
        (out / "pid.txt").unlink(missing_ok=True)  # a stale PID could later name an unrelated process
        secs = round(time.time() - t0, 1)
    tail = err.strip().splitlines()[-1] if err and err.strip() else ""
    done = (out / "oracle.stdout.txt").read_text(encoding="utf-8", errors="replace").strip().startswith('{"out"')
    if rc == 0 or done:
        status = "ok"
    elif "ProcessDied" in err or "original terminated" in err:
        status = "died"
    elif (rc is None or "TimeoutError" in err) and parse_started(out):
        status = "timeout"  # the original was parsing (or exporting) and never finished
    else:
        status = "harness-error"
    evs = []
    if (out / "sql.jsonl").exists():
        for line in (out / "sql.jsonl").read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                evs.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    st = {"status": status, "detail": tail, "seconds": secs,
          "msgboxes": [e.get("text") for e in evs if e.get("ev") == "msgbox"]}
    (out / "oracle_status.json").write_text(json.dumps(st, indent=1), encoding="utf-8")
    return st


def run_go(case, cj, res):
    cmd = [str(GO), "-logfile", str(case / "$LogFile"), f"-utc={cj['utc']}", "-db", str(res / "cand.db"),
           "-csv", str(res / "cand.csv"), "-trace", str(res / "cand.trace.jsonl")]
    if cj.get("dst"):
        cmd.append("-dst")
    if cj.get("mft"):
        cmd += ["-mft", str(case / "$MFT")]
    for f in ("cand.db", "cand.csv", "cand.trace.jsonl"):
        (res / f).unlink(missing_ok=True)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "detail": ""}
    tail = p.stderr.strip().splitlines()[-1] if p.stderr.strip() else ""
    if p.returncode == 0:
        return {"status": "notsupported" if "not supported" in p.stderr else "ok", "detail": tail}
    if "input makes the original fail" in p.stderr:
        return {"status": "crash", "detail": tail}
    return {"status": "error", "detail": tail}


def streams(odir, res, mask):
    o = [masked(x, mask) for x in oracle_stream(odir / "sql.jsonl")] if (odir / "sql.jsonl").exists() else []
    c = [masked(x, mask) for x in cand_stream(res / "cand.trace.jsonl")] if (res / "cand.trace.jsonl").exists() else []
    return o, c


def first_diff(o, c):
    i = next((i for i, (x, y) in enumerate(zip(o, c)) if x != y), None)
    if i is None and len(o) != len(c):
        i = min(len(o), len(c))
    return i


# CSV fields from this many units on are only compared on this prefix: the original copies each value through a
# dead stack buffer whose tail holds run-dependent garbage (SPEC 8.5, U10).
LONG_FIELD_UNITS = 0xdaa  # earliest cut seen in any run of the original (cuts: 0xdaa, 0xe8c, 0xe8e, 0xf20, 0xf5e, 0xf60)


def compare_outputs(odir, res, mask):
    db = next(iter(sorted(odir.glob("oracle_*.db"))), None)
    csv = next(iter(sorted(odir.glob("NLT_LogFile_2*.csv"))), None)
    if db is None or csv is None or not (res / "cand.db").exists():
        return {"ok": False, "why": "missing output", "oracle_db": bool(db), "oracle_csv": bool(csv)}
    cmd = [PY, str(ROOT / "re" / "oracle" / "compare.py"), "--ref-db", str(db), "--cand-db", str(res / "cand.db"),
           "--ref-csv", str(csv), "--cand-csv", str(res / "cand.csv"), "--json", str(res / "compare.json")]
    for m in sorted(mask):
        cmd += ["--mask-time", str(m)]
    cmd += ["--long-field-units", str(LONG_FIELD_UNITS)]
    p = subprocess.run(cmd, capture_output=True)
    try:
        long_masked = json.loads((res / "compare.json").read_text(encoding="utf-8"))["csv"]["masked_long_fields"]
    except (OSError, ValueError, KeyError):
        long_masked = 0
    return {"ok": p.returncode == 0, "long_masked": long_masked}


def oracle_rows(odir):
    db = next(iter(sorted(odir.glob("oracle_*.db"))), None)
    if db is None:
        return None
    try:
        c = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        return c.execute("select count(*) from LogFile").fetchone()[0]
    except sqlite3.Error:
        return None


def judge(cj, ost, gst, odir, res, extra_mask=()):
    mask = set(cj.get("nondet_time_lsns", [])) | set(extra_mask)
    o, c = streams(odir, res, mask)
    fd = first_diff(o, c)
    v = {"oracle": ost["status"], "go": gst["status"], "oracle_statements": len(o), "go_statements": len(c),
         "first_diff": fd, "oracle_rows": oracle_rows(odir)}
    if ost["status"] == "harness-error":
        v["verdict"] = "harness-error"
    elif ost["status"] == "ok" and gst["status"] in ("ok", "notsupported"):
        cmp = compare_outputs(odir, res, mask)
        v["outputs_equal"] = cmp["ok"]
        if cmp.get("why") == "missing output":
            v["verdict"] = "harness-error"  # the oracle run reported success but its DB or CSV is missing
        else:
            v["verdict"] = "match" if fd is None and cmp["ok"] else "diverge"
            if cmp["long_masked"]:
                v["csv_long_fields_masked"] = cmp["long_masked"]
                if v["verdict"] == "match":
                    v["verdict"] = "match-nondet"
    elif ost["status"] in ("died", "timeout") and gst["status"] == "crash":
        # The original's statements before it died must equal the port's statements before it stopped.
        v["verdict"] = "match-crash" if fd is None else "diverge-crash"
    else:
        v["verdict"] = "diverge-outcome"
    if fd is not None:
        v["oracle_at_diff"] = o[fd][-400:] if fd < len(o) else "<end>"
        v["go_at_diff"] = c[fd][-400:] if fd < len(c) else "<end>"
    return v


def varying_lsns(a, b):
    """LSNs whose statements differ between two oracle runs of the same case (None if the runs differ otherwise)."""
    sa, sb = oracle_stream(a / "sql.jsonl"), oracle_stream(b / "sql.jsonl")
    if len(sa) != len(sb):
        return None
    out = set()
    for x, y in zip(sa, sb):
        if x != y:
            m = re.search(r"values\((\d+),", x) or re.search(r"LSN\s*=\s*'?(\d+)", x)
            if not m or masked(x, {int(m.group(1))}) != masked(y, {int(m.group(1))}):
                return None
            out.add(int(m.group(1)))
    return out


def same_oracle(a, b):
    sa = oracle_stream(a / "sql.jsonl") if (a / "sql.jsonl").exists() else None
    sb = oracle_stream(b / "sql.jsonl") if (b / "sql.jsonl").exists() else None
    return sa is not None and sa == sb


def process(case, a):
    res = RESULTS / case.name
    vpath = res / "verdict.json"
    odir = res / "oracle"
    if vpath.exists() and not a.rerun and not a.go_only:
        return
    old = json.loads(vpath.read_text(encoding="utf-8")) if vpath.exists() else {}
    res.mkdir(parents=True, exist_ok=True)
    cj = json.loads((case / "case.json").read_text(encoding="utf-8"))
    ostp = odir / "oracle_status.json"
    if a.go_only:
        if not ostp.exists():
            return
        ost = json.loads(ostp.read_text(encoding="utf-8"))
    else:
        ost = run_oracle(case, cj, odir, a.oracle_timeout)
        if ost["status"] == "harness-error":
            ost = run_oracle(case, cj, odir, a.oracle_timeout)
    gst = run_go(case, cj, res)
    # In --go-only mode, rows already proven to vary between two runs of the original stay masked.
    known = old.get("nondet_time_lsns", []) if a.go_only else []
    v = judge(cj, ost, gst, odir, res, known)
    v.update({"case": case.name, "family": cj.get("family"), "desc": cj.get("desc"),
              "oracle_detail": ost.get("detail"), "go_detail": gst.get("detail"), "msgboxes": ost.get("msgboxes")})
    if a.go_only:
        for k in ("oracle_deterministic", "nondet_time_lsns"):
            if k in old:
                v[k] = old[k]
        if known and v["verdict"] in ("match", "match-crash"):
            v["verdict"] += "-nondet"
    elif v["verdict"].startswith("diverge"):
        o2 = res / "oracle2"
        if not (o2 / "oracle_status.json").exists():
            run_oracle(case, cj, o2, a.oracle_timeout)
        v["oracle_deterministic"] = same_oracle(odir, o2)
        if not v["oracle_deterministic"] and (o2 / "sql.jsonl").exists():
            vary = varying_lsns(odir, o2)
            if vary:
                # Only time literals of these rows vary between two runs of the original itself.
                v2 = judge(cj, ost, gst, odir, res, vary)
                v.update({k: v2.get(k) for k in ("first_diff", "outputs_equal", "oracle_at_diff", "go_at_diff")})
                v["nondet_time_lsns"] = sorted(vary)
                if v2["verdict"] in ("match", "match-crash"):
                    v["verdict"] = v2["verdict"] + "-nondet"
    vpath.write_text(json.dumps(v, indent=1), encoding="utf-8")
    print(f"{case.name}: {v['verdict']} (oracle={v['oracle']} go={v['go']} diff@{v['first_diff']})", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="")
    ap.add_argument("--max-seconds", type=int, default=0)
    ap.add_argument("--go-only", action="store_true")
    ap.add_argument("--rerun", action="store_true")
    ap.add_argument("--oracle-timeout", type=int, default=240)
    ap.add_argument("--worker", type=int, default=0)
    ap.add_argument("--workers", type=int, default=1)
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    global WORKER
    WORKER = a.worker
    t_start = time.time()
    # Skip cases still being written by a generator (any file touched in the last 30 s).
    settled = lambda d: all(time.time() - f.stat().st_mtime > 30 for f in d.iterdir())
    cases = sorted(d for d in CASES.iterdir()
                   if (d / "case.json").exists() and (d / "$LogFile").exists() and a.filter in d.name and settled(d))
    cases = [c for i, c in enumerate(cases) if i % a.workers == a.worker]
    for case in cases:
        if a.max_seconds and time.time() - t_start > a.max_seconds:
            print("time budget reached", flush=True)
            break
        try:
            process(case, a)
        except Exception as e:  # keep the worker alive; the case has no verdict and is retried next time
            print(f"{case.name}: harness exception {e!r}", flush=True)
    summary = {}
    for vp in sorted(RESULTS.glob("*/verdict.json")):
        try:
            v = json.loads(vp.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # being written by another worker
            continue
        summary.setdefault(v["verdict"], []).append(v["case"])
    (ROOT / "fuzz" / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    print(json.dumps({k: len(v) for k, v in summary.items()}))


if __name__ == "__main__":
    main()
