"""Fuzz family "vhd": REAL NTFS volumes (scratch VHD/VHDX files) with simulated activity -> $LogFile (+ $MFT) cases.

  python -I re/fuzz/gen_vhd.py --seed 1 [--only SLUG[,SLUG...]] [--list] [--force] [--cleanup]

Needs Administrator (diskpart, raw volume reads). One volume at a time, entirely inside fuzz/vhd/:
create vdisk (expandable) -> attach -> create partition -> format (diskpart, or format.com for /L) -> assign a drive
letter taken from the free pool (never A:, B:, C:, D: or T:) -> optional log resize (chkdsk /F /X /L:<KB>) ->
activity steps -> raw extraction with re/oracle/extract_logfile.py (record 2 = $LogFile, record 0 = $MFT) while the
volume is mounted (or after a read-only / read-write re-attach, or after chkdsk) -> detach -> delete the virtual disk
(always, in a finally block). Cluster sizes below 4 KiB need a 512-byte physical sector, so those volumes are .vhd
files (VHDX reports 4 KiB physical sectors and format refuses smaller units); all others are .vhdx. Every disk is
<= 2 GB. Cases: fuzz/cases/vhd-NNN-<slug>/{$LogFile, [$MFT], case.json}; NNN is fixed by the scenario table, so a
--only run never renumbers. Existing case directories are kept unless --force.

Determinism: every choice the generator makes (names, sizes, orders, op mix, time zones, activity seeds) derives
from --seed and the scenario slug. The resulting bytes are NOT reproducible (real time stamps, LSNs, GUIDs, lazy
writer timing); each case.json records what was done plus a summary of the restart area / RCRD pages extracted.

Targeted behaviours of the original (NTFS Log Tracker v1.71) -- each volume documents its own subset in case.json:
 - Geometry the original hard-codes: parent-location key "0x%X" % (ref >> 2) and (ref & 3) * 2 assume 4 KiB clusters
   with 1 KiB FILE records. Real TargetVCN / cluster_block_offset values for 512 B, 1 KiB, 2 KiB, 8 KiB and 64 KiB
   clusters, and for 4 KiB FILE records (format /L), so the E2 match (and E1/F/H keys) see different values.
 - $MFT pre-pass assumes 1 KiB records (count = size >> 10, fixups only at +0x1fe/+0x3fe, attribute walk bounded
   by 0x400): a 4 KiB-record $MFT shifts every record number by 4x, splits records, cuts attributes past 0x400.
 - $LogFile size (2048 KB minimum, 3 MB, 6208 KB default for 2 GB, 8 MB, odd 2050 KB with a partial last page):
   seq_number_bits / shift, number of RCRD pages, 0xFF-filled never-used pages, partial-page read with stale tail.
 - Circular wrap-around: heavy create/delete churn wraps the log many times, so RCRD last_lsn runs split, the
   qsort of runs, v2.0 buffer pages b4[0..0x1f] placed at start/end/dropped, overlapping/duplicate LSNs.
 - Restart area states: live (LFS 2.0, lazy, mid-activity, possibly torn between pages; an idle volume has fewer
   than 0x20 RCRD pages), read-only re-attach after a clean dismount (Windows downgrades the restart pages to LFS 1.1
   with the clean flag, so the original takes its v1.1 page-ordering branch on real data), read-write re-attach
   (mount-time records), chkdsk /F log reset, chkdsk /L resize (log reinitialised).
 - Large log records: checkpoint dumps with many open attributes / dirty pages (many files open at once), 4 KiB
   FILE record images (InitializeFileRecordSegment) and attribute lists, so records cross 1 or >= 2 page boundaries
   (header split, body span, q = ovf / 0xfc0 page skip).
 - Opcode / event variety: create/delete of files and directories, index root/allocation add/delete, B-tree splits
   in huge directories, renames/moves/tunneling, hard links, alternate data streams, NTFS compression, WOF (LZX)
   compression, sparse files and zero ranges, short names (setshortname, 8dot3 strip), symlinks/junctions (reparse
   index), object IDs ($ObjId index), security descriptors ($Secure $SDS/$SII/$SDH), quota ($Quota $Q/$O), USN
   journal create/delete, TxF commit/rollback, extended attributes ($EA), resident <-> non-resident transitions,
   truncation/extension/valid-data, large fragmented non-resident files, mapping-pair updates, defrag moves, a
   full volume, label changes, case-sensitive directories, attribute flag changes.
 - Names: paths > 260 and > 8000 chars (\\\\?\\ prefixes), 255-char components, quotes/commas/percent signs
   (SQL and CSV quoting, format strings), lone surrogates, characters not representable in the ANSI code page,
   trailing dots/spaces, reserved device names, RTL override / combining marks.
 - Time stamps set with SetFileInformationByHandle (all four $SI times) to extremes that interact with the hour
   shift: 1601-01-01 + few ticks (negative after a negative shift), 1601-01-01 12:00 (exactly 0 at UTC-12),
   9999-12-31 10:00+ (year 10000 after +14/+15), 1999/2000 and 2099/2100 boundaries (the "20" prefix test),
   DOS/Unix/2038/2106 epochs, and times before/after the $MFT creation time (p+0x1a8 comparison).
 - Idle (just formatted) volumes, and a volume after chkdsk.
"""
import argparse
import ctypes
import datetime
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VHD_DIR = ROOT / "fuzz" / "vhd"
CASES = ROOT / "fuzz" / "cases"
EXTRACT = ROOT / "re" / "oracle" / "extract_logfile.py"
ACTIVITY = ROOT / "re" / "oracle" / "make_activity.py"
PY = sys.executable
SYS32 = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
FORBIDDEN = set("ABCDT")
POOL = "WXYZVUSRQPONMLKJIHGFE"
TICK = 10_000_000
HOUR = 3600 * TICK

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
HANDLE, DWORD, LPCWSTR = wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR
k32.CreateFileW.restype = HANDLE
k32.CreateFileW.argtypes = [LPCWSTR, DWORD, DWORD, ctypes.c_void_p, DWORD, DWORD, HANDLE]
k32.WriteFile.argtypes = [HANDLE, ctypes.c_void_p, DWORD, ctypes.POINTER(DWORD), ctypes.c_void_p]
k32.CloseHandle.argtypes = [HANDLE]
k32.FlushFileBuffers.argtypes = [HANDLE]
k32.SetFileInformationByHandle.argtypes = [HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD]
k32.CreateHardLinkW.argtypes = [LPCWSTR, LPCWSTR, ctypes.c_void_p]
k32.SetFileAttributesW.argtypes = [LPCWSTR, DWORD]
k32.GetLogicalDrives.restype = DWORD
k32.CreateFileTransactedW.restype = HANDLE
k32.CreateFileTransactedW.argtypes = [LPCWSTR, DWORD, DWORD, ctypes.c_void_p, DWORD, DWORD, HANDLE, HANDLE,
                                      ctypes.c_void_p, ctypes.c_void_p]
k32.MoveFileTransactedW.argtypes = [LPCWSTR, LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, DWORD, HANDLE]
k32.DeleteFileTransactedW.argtypes = [LPCWSTR, HANDLE]
k32.CreateDirectoryTransactedW.argtypes = [LPCWSTR, LPCWSTR, ctypes.c_void_p, HANDLE]
k32.RemoveDirectoryTransactedW.argtypes = [LPCWSTR, HANDLE]
ntdll.NtSetEaFile.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.ULONG]
INVALID = ctypes.c_void_p(-1).value


class BasicInfo(ctypes.Structure):
    _fields_ = [("c", ctypes.c_longlong), ("a", ctypes.c_longlong), ("w", ctypes.c_longlong),
                ("m", ctypes.c_longlong), ("attr", wintypes.DWORD)]


def ft(y, mo=1, d=1, h=0, mi=0, s=0, ticks=0):
    dt = datetime.datetime(y, mo, d, h, mi, s) - datetime.datetime(1601, 1, 1)
    return (dt.days * 86400 + dt.seconds) * TICK + ticks


# --------------------------------------------------------------------------------------------- scenario table
# ext: "vhd" for clusters < 4 KiB (512 B physical sector), "vhdx" otherwise.  frs4k: format.com /L.
# plan: activity steps ("name", {params}); ("extract", tag) / ("remount_ro",) / ("remount_rw",) / ("chkdsk_fix",)
# cases: (tag, mft) per case built from that extraction.
V = []


def vol(slug, size_mb, unit, plan, cases, why, frs4k=False, log_kb=None):
    V.append(dict(slug=slug, size_mb=size_mb, unit=unit, frs4k=frs4k, log_kb=log_kb, plan=plan, cases=cases,
                  why=why, ext="vhd" if unit < 4096 else "vhdx"))


vol("idle-4k", 64, 4096, [("sleep", {"s": 3}), ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "idle just-formatted volume: few RCRD pages, mostly 0xFF never-written pages, minimum 2048 KB log")
vol("idle-64k-frs4k", 2048, 65536, [("sleep", {"s": 3}), ("extract", "live")], [("live", True)],
    "idle 2 GB volume, 64 KiB clusters + 4 KiB FILE records, default 6208 KB log: geometry and 4K-record $MFT",
    frs4k=True)
vol("act-512", 128, 512, [("make_activity", {}), ("churn", {"rounds": 3, "per_round": 150, "keep": 3}),
                          ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "make_activity on 512 B clusters: TargetVCN = 2*record, cluster offset 0, parent key assumes 4K/1K geometry")
vol("act-1k", 192, 1024, [("make_activity", {}), ("churn", {"rounds": 3, "per_round": 150, "keep": 3}),
                          ("times", {"n": 12}), ("extract", "live")],
    [("live", False)],
    "make_activity + extreme times on 1 KiB clusters: one record per cluster, parent-location key mismatch")
vol("act-2k", 96, 2048, [("make_activity", {}), ("churn", {"rounds": 3, "per_round": 150, "keep": 3}),
                         ("hardlinks", {"files": 20, "links": 6}), ("extract", "live")],
    [("live", True)],
    "make_activity + hard links on 2 KiB clusters: 2 records per cluster, cluster_block_offset 0/2")
vol("act-8k", 512, 8192, [("make_activity", {}), ("churn", {"rounds": 3, "per_round": 150, "keep": 3}),
                          ("hardlinks", {"files": 30, "links": 8}), ("extract", "live"),
                          ("remount_ro", {}), ("extract", "ro")],
    [("live", False), ("ro", True)],
    "make_activity + hard links on 8 KiB clusters: 8 records per cluster, cluster_block_offset up to 14")
vol("act-64k", 1024, 65536, [("make_activity", {}), ("churn", {"rounds": 3, "per_round": 150, "keep": 3}),
                             ("ads", {"files": 25, "streams": 4}), ("extract", "live")],
    [("live", False)],
    "make_activity + ADS on 64 KiB clusters: 64 records per cluster, offsets up to 126, TargetVCN = record/64")
vol("frs4k-4k", 256, 4096, [("make_activity", {}), ("hardlinks", {"files": 15, "links": 40}),
                            ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "4 KiB FILE records (/L) on 4 KiB clusters: TargetVCN = record number, big FILE images, 4K-record $MFT",
    frs4k=True)
vol("frs4k-512", 128, 512, [("make_activity", {}), ("extract", "live")], [("live", True)],
    "4 KiB FILE records on 512 B clusters (8 clusters per record): TargetVCN = 8*record", frs4k=True)
vol("frs4k-64k-attrlist", 512, 65536, [("attrlist", {"links": 160, "streams": 40}), ("ads", {"files": 10,
                                                                                           "streams": 12}),
                                       ("extract", "live")], [("live", True)],
    "4 KiB FILE records on 64 KiB clusters with files overflowing into attribute lists: multi-page log records",
    frs4k=True)
vol("churn-2m", 64, 4096, [("churn", {"rounds": 40, "per_round": 450, "keep": 9}), ("extract", "live"),
                           ("remount_ro", {}), ("extract", "ro")],
    [("live", False), ("ro", True)],
    "heavy create/delete churn wrapping the 2048 KB log ~10x: run split, run qsort, buffer pages, LSN seq bump")
vol("churn-odd-log", 128, 4096, [("churn", {"rounds": 25, "per_round": 400, "keep": 0}), ("extract", "live")],
    [("live", False)],
    "log resized to 2050 KB (file not a multiple of 0x1000: partial last page with stale tail) + wrapping churn",
    log_kb=2050)
vol("churn-8m-many-open", 512, 1024, [("churn", {"rounds": 30, "per_round": 600, "keep": 5}),
                                      ("many_open", {"n": 1800, "wait": 12}), ("extract", "live")],
    [("live", False)],
    "8192 KB log, 1 KiB clusters, churn + 1800 files open across checkpoints: huge open-attribute/dirty-page dumps",
    log_kb=8192)
vol("deep-longpath", 256, 1024, [("deep", {"depth": 45, "comp": 180, "files": 2}), ("deep2", {}),
                                 ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "deep trees with paths > 260 and ~8000 chars, 255-char names, mid-tree renames/moves, subtree deletes")
vol("rename-storm", 256, 8192, [("renames", {"files": 300, "ops": 2500}), ("hardlinks", {"files": 40, "links": 5}),
                                ("extract", "live")], [("live", True)],
    "rename/move storm (case-only renames, replace-over, tunneling, dir renames) + hard links on 8 KiB clusters")
vol("ads-compress-sparse", 512, 4096, [("ads", {"files": 40, "streams": 6}), ("compress", {}), ("sparse", {}),
                                       ("extract", "live")], [("live", False)],
    "alternate data streams, NTFS + WOF/LZX compression, sparse files and zero ranges: mapping pairs, reparse")
vol("links-objid-short", 256, 4096, [("shortnames", {}), ("links", {}), ("objid", {}), ("extract", "live"),
                                     ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "8.3 short names (setshortname, strip), symlinks/junctions (reparse index), object IDs ($ObjId index)")
vol("acl-attrib-times", 128, 512, [("acl", {"n": 260}), ("attrib", {}), ("times", {"n": 40}), ("extract", "live")],
    [("live", True), ("live", False)],
    "many distinct security descriptors ($Secure), attribute flag combos, extreme $SI times vs hour shift")
vol("bigfiles", 2048, 65536, [("bigfiles", {"mb": 420}), ("extract", "live")], [("live", False)],
    "large fragmented non-resident files, truncate/extend/seteof/setvaliddata/zero-data on 64 KiB clusters")
vol("dir-mass-delete", 512, 4096, [("dirmass", {"dirs": 4, "per_dir": 2500}), ("extract", "live")],
    [("live", True)],
    "huge directories (multi-level index allocation, B-tree splits) then mass delete + rmdir, $MFT growth",
    log_kb=4096)
vol("txf", 256, 4096, [("txf", {"n": 120}), ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", False), ("ro", True)],
    "transactional NTFS (commit and rollback): undo/compensation records, $TXF_DATA logged utility streams")
vol("quota-usn-label", 256, 2048, [("quota_usn_label", {}), ("churn", {"rounds": 4, "per_round": 200, "keep": 3}),
                                   ("extract", "live")], [("live", False)],
    "quota tracking/limits ($Quota), USN journal create/delete, volume label changes, case-sensitive dirs")
vol("chkdsk-after", 192, 4096, [("make_activity", {}), ("churn", {"rounds": 6, "per_round": 300, "keep": 4}),
                                ("extract", "live"), ("chkdsk_fix", {}), ("extract", "post")],
    [("live", True), ("post", False)],
    "same volume before and after chkdsk /F (log reset to a couple of RCRD pages, new restart area)")
vol("defrag-wof", 512, 4096, [("bigfiles", {"mb": 120}), ("compress", {}), ("defrag", {}), ("extract", "live")],
    [("live", False)],
    "fragmented files, WOF/NTFS compression then defrag cluster moves: mapping-pair and bitmap records")
vol("fill-full", 64, 512, [("fill", {}), ("extract", "live")], [("live", True)],
    "volume filled to ENOSPC, half deleted, refilled with small files ($MFT grows into the MFT zone)")
vol("resident-flip", 128, 1024, [("resident_flip", {"n": 60}), ("ea", {"n": 20}), ("extract", "live")],
    [("live", False)],
    "resident <-> non-resident $DATA/ADS transitions, truncation/extension, extended attributes ($EA)")
vol("mixed-2g", 2048, 4096, [("make_activity", {}), ("churn", {"rounds": 8, "per_round": 300, "keep": 6}),
                             ("many_open", {"n": 800, "wait": 8}), ("times", {"n": 20}),
                             ("extract", "live"), ("remount_rw", {}), ("extract", "rw")],
    [("live", True), ("rw", False)],
    "2 GB volume, default 6208 KB log, mixed activity; second case after a read-write re-attach (mount records)")
vol("names-weird", 128, 4096, [("weird_names", {}), ("extract", "live"), ("remount_ro", {}), ("extract", "ro")],
    [("live", True), ("ro", False)],
    "names with quotes/commas/percent/format specifiers, lone surrogates, non-ANSI, trailing dot/space, CON/NUL")
vol("churn-3m-frs4k-1k", 160, 1024, [("churn", {"rounds": 20, "per_round": 400, "keep": 7}),
                                     ("renames", {"files": 150, "ops": 800}), ("extract", "live")],
    [("live", True)],
    "3072 KB log, 4 KiB FILE records on 1 KiB clusters (4 clusters per record), churn + renames",
    frs4k=True, log_kb=3072)
vol("path-boundary", 128, 4096, [("path_lengths", {"targets": [255, 1000, 2047, 2048, 3000, 3327, 3328, 3500, 3583,
                                                               3584, 3700, 3839, 3840, 3950, 4000, 4053, 4054, 4060,
                                                               4080, 4094, 4095]}), ("extract", "live")],
    [("live", True)],
    "FullPath lengths 255..4095 UTF-16 units (with $MFT): the CSV read-back buffer is 0x1000 units and tail units "
    "from ~0xd00..0xfd6 on may be overwritten by stack reuse (spec 06 edge case 10, unverified)")

TZ_POOL = [(-12, False), (14, True), (0, False), (-3, False), (9, False), (-12, True), (14, False), (0, True),
           (-3, True), (9, True), (1, False), (2, True), (-5, False), (-8, True), (5, False), (8, False),
           (-1, True), (3, False), (10, True), (12, False), (13, True), (-10, False), (-7, True), (6, False),
           (4, True), (-4, False), (11, False), (-11, True), (7, True), (-9, False), (-2, True), (-6, False),
           (12, True), (-12, False), (14, True), (0, False), (9, False), (-3, False), (1, True), (5, True),
           (-8, False), (3, True), (-6, True), (2, False)]


def tz_assignment(seed):
    """Deterministic (utc, dst) per case number; the must-have extremes come first in the shuffled pool."""
    rng = random.Random(f"{seed}/tz")
    must, rest = TZ_POOL[:10], TZ_POOL[10:]
    rng.shuffle(must)
    rng.shuffle(rest)
    return must + rest


# --------------------------------------------------------------------------------------------- system helpers
def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def sh(cmd, inp=None, timeout=900, check=False):
    p = subprocess.run(cmd, input=inp, capture_output=True, timeout=timeout, encoding="cp850", errors="replace")
    if check and p.returncode != 0:
        raise RuntimeError(f"{cmd[0]} rc={p.returncode}: {(p.stdout + p.stderr).strip()[-600:]}")
    return p


def diskpart(lines, check=True):
    script = VHD_DIR / "_diskpart.txt"
    script.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")
    try:
        p = sh([str(SYS32 / "diskpart.exe"), "/s", str(script)], timeout=600)
    finally:
        script.unlink(missing_ok=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"diskpart rc={p.returncode}: {p.stdout.strip()[-800:]}")
    return p


def attached_vdisks():
    p = sh(["powershell", "-NoProfile", "-Command", "(Get-Disk).Location"], timeout=120)
    return [l.strip() for l in p.stdout.splitlines() if str(VHD_DIR).lower() in l.strip().lower()]


def detach(path):
    diskpart([f'select vdisk file="{path}"', "detach vdisk noerr"], check=False)


def free_letter(prefer=None):
    used = k32.GetLogicalDrives()
    for l in ([prefer] if prefer else []) + list(POOL):
        if l and l not in FORBIDDEN and not used & (1 << (ord(l) - 65)):
            return l
    raise RuntimeError("no free drive letter")


def volume_letters(guid):
    buf = ctypes.create_unicode_buffer(1024)
    n = DWORD()
    if not k32.GetVolumePathNamesForVolumeNameW(guid, buf, 1024, ctypes.byref(n)):
        return []
    out, cur = [], ""
    for ch in buf[:n.value]:
        if ch == "\0":
            if cur:
                out.append(cur)
            cur = ""
        else:
            cur += ch
    return [x[0] for x in out if len(x) == 3 and x[1:] == ":\\"]


def volume_guid(letter):
    buf = ctypes.create_unicode_buffer(64)
    if not k32.GetVolumeNameForVolumeMountPointW(f"{letter}:\\", buf, 64):
        raise RuntimeError(f"no volume GUID for {letter}:")
    return buf.value


def wait_for(letter, secs=30, fs=True):
    """Wait until the letter is mapped (and, with fs, until its file system answers)."""
    for _ in range(secs * 4):
        if k32.GetLogicalDrives() & (1 << (ord(letter) - 65)) and (not fs or os.path.exists(f"{letter}:\\")):
            return
        time.sleep(0.25)
    raise RuntimeError(f"{letter}: did not appear")


def flush_volume(letter):
    h = k32.CreateFileW(rf"\\.\{letter}:", 0xC0000000, 3, None, 3, 0, None)
    if h in (None, INVALID):
        return False
    ok = bool(k32.FlushFileBuffers(h))
    k32.CloseHandle(h)
    return ok


# --------------------------------------------------------------------------------------------- activity helpers
def lp(*parts):
    return "\\\\?\\" + os.path.join(*parts)


def write(path, data, mode="wb"):
    with open(path, mode) as f:
        f.write(data)


def rname(rng, n, alpha="abcdefghijklmnopqrstuvwxyz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ ñéü"):
    s = "".join(rng.choice(alpha) for _ in range(n))
    return s.strip() or "x"


def fsutil(*args, timeout=300):
    return sh([str(SYS32 / "fsutil.exe"), *args], timeout=timeout).returncode


def open_handle(path, access=0x100, flags=0x02000000, disp=3):
    h = k32.CreateFileW(path, access, 7, None, disp, flags, None)
    return None if h in (None, INVALID) else h


def set_times(path, c=0, a=0, w=0, m=0, attr=0):
    h = open_handle(path, 0x100, 0x02000000 | 0x00200000)
    if not h:
        return False
    bi = BasicInfo(c, a, w, m, attr)
    ok = bool(k32.SetFileInformationByHandle(h, 0, ctypes.byref(bi), ctypes.sizeof(bi)))
    k32.CloseHandle(h)
    return ok


class Ctx:
    def __init__(self, letter, rng, seed):
        self.letter, self.rng, self.seed = letter, rng, seed
        self.root = f"{letter}:\\"

    def d(self, *parts):
        p = os.path.join(self.root, *parts)
        os.makedirs(p, exist_ok=True)
        return p


def act_sleep(c, s):
    time.sleep(s)
    return {"slept": s}


def act_make_activity(c):
    s = c.rng.randrange(1, 10_000)
    p = sh([PY, "-I", str(ACTIVITY), c.root, "--seed", str(s)], timeout=1800)
    return {"make_activity_seed": s, "rc": p.returncode, "out": p.stdout.strip()[-80:]}


def act_churn(c, rounds, per_round, keep):
    rng, base = c.rng, c.d("churn")
    made = deleted = rmd = 0
    sizes = [0, 1, 37, 400, 700, 1100, 3000, 9000, 70000]
    suffixes = ["", ".tmp", ".txt", "_" + "y" * 40, " (copy)", "~1.TMP", "." + "e" * 10]
    for r in range(rounds):
        d = os.path.join(base, f"d{r % 7}")
        os.makedirs(d, exist_ok=True)
        names = []
        for i in range(per_round):
            n = os.path.join(d, f"c{r:03d}_{i:05d}{rng.choice(suffixes)}")
            write(n, rng.randbytes(rng.choice(sizes)))
            names.append(n)
            made += 1
        rng.shuffle(names)
        for j, n in enumerate(names):
            if keep and j % keep == 0:
                continue
            os.remove(n)
            deleted += 1
        if r % 5 == 4:
            victim = os.path.join(base, f"d{rng.randrange(7)}")
            if os.path.isdir(victim):
                shutil.rmtree(victim, ignore_errors=True)
                rmd += 1
    return {"created": made, "deleted": deleted, "dirs_removed": rmd}


def act_many_open(c, n, wait):
    base = c.d("open")
    hs = []
    for i in range(n):
        h = open_handle(os.path.join(base, f"o{i:05d}.bin"), 0x40000000 | 0x100, 0x80, 2)
        if h:
            buf = c.rng.randbytes(8192 + (i % 5) * 512)
            k32.WriteFile(h, buf, len(buf), ctypes.byref(DWORD()), None)
            hs.append(h)
    time.sleep(wait)
    for i, h in enumerate(hs):
        buf = c.rng.randbytes(4096)
        k32.WriteFile(h, buf, len(buf), ctypes.byref(DWORD()), None)
    time.sleep(wait / 2)
    for h in hs:
        k32.CloseHandle(h)
    return {"open": len(hs), "wait": wait}


def act_deep(c, depth, comp, files):
    rng = c.rng
    p = lp(c.root, "deep")
    os.makedirs(p, exist_ok=True)
    levels = []
    for lvl in range(depth):
        p = os.path.join(p, f"L{lvl:02d}_" + rname(rng, comp - 4))
        os.mkdir(p)
        levels.append(p)
        for f in range(files):
            write(os.path.join(p, rname(rng, rng.choice([8, 120, 251])) + ".txt"), rng.randbytes(rng.choice([20, 2000])))
    maxlen = len(p) - 4
    mid = levels[depth // 2]
    renamed = os.path.join(os.path.dirname(mid), "renamed_" + rname(rng, 200))
    os.rename(mid, renamed)
    moved = os.path.join(lp(c.root, "deep"), "moved_subtree")
    os.rename(renamed, moved)
    # Delete the lowest levels of the moved subtree.
    victims = []
    for dp, dn, fn in os.walk(moved):
        victims.append(dp)
    for dp in sorted(victims, key=len, reverse=True)[:6]:
        shutil.rmtree(dp, ignore_errors=True)
    return {"depth": depth, "max_path_chars": maxlen}


def act_deep2(c):
    """A second tree: 255-character components (the NTFS maximum) and a file at > 260 chars under the root."""
    rng = c.rng
    p = lp(c.root, "max255")
    os.makedirs(p, exist_ok=True)
    for i in range(10):
        p = os.path.join(p, rname(rng, 255))
        os.mkdir(p)
        write(os.path.join(p, rname(rng, 251) + ".dat"), rng.randbytes(rng.choice([100, 5000])))
    leaf = os.path.join(p, "leaf.txt")
    write(leaf, b"leaf")
    os.rename(leaf, os.path.join(p, rname(rng, 255)))
    return {"components": 10, "max_path_chars": len(p) - 4}


def act_renames(c, files, ops):
    rng = c.rng
    dirs = [c.d("ren", f"dir{i}") for i in range(6)]
    cur = []
    for i in range(files):
        p = os.path.join(rng.choice(dirs), f"f{i:04d}.txt")
        write(p, rng.randbytes(rng.choice([10, 900, 6000])))
        cur.append(p)
    stats = dict(case=0, move=0, long=0, replace=0, tunnel=0, dir=0)
    for k in range(ops):
        i = rng.randrange(len(cur))
        p = cur[i]
        op = rng.choice(list(stats))
        try:
            if op == "case":
                q = os.path.join(os.path.dirname(p), os.path.basename(p).swapcase())
                os.rename(p, q)
            elif op == "move":
                q = os.path.join(rng.choice(dirs), os.path.basename(p))
                if os.path.exists(q):
                    continue
                os.rename(p, q)
            elif op == "long":
                q = os.path.join(os.path.dirname(p), f"k{k}_" + rname(rng, rng.choice([3, 60, 200])) + ".txt")
                os.rename(p, q)
            elif op == "replace":
                j = rng.randrange(len(cur))
                if j == i:
                    continue
                os.replace(p, cur[j])
                write(p, b"recreated")
                q = p
            elif op == "tunnel":
                os.remove(p)
                write(p, b"tunneled")
                q = p
            else:
                di = rng.randrange(len(dirs))
                nd = os.path.join(os.path.dirname(dirs[di]), f"dir{di}_r{k}")
                os.rename(dirs[di], nd)
                cur = [x.replace(dirs[di] + os.sep, nd + os.sep) if x.startswith(dirs[di] + os.sep) else x
                       for x in cur]
                dirs[di] = nd
                stats[op] += 1
                continue
            cur[i] = q
            stats[op] += 1
        except OSError:
            pass
    return stats


def act_hardlinks(c, files, links):
    rng, base = c.rng, c.d("hl")
    made = 0
    for i in range(files):
        p = os.path.join(base, f"orig{i:03d}_" + rname(rng, rng.choice([5, 40])))
        write(p, rng.randbytes(rng.choice([50, 3000, 20000])))
        names = [p]
        for j in range(links):
            sub = c.d("hl", f"s{j % 4}")
            q = os.path.join(sub, f"link{i}_{j}_" + rname(rng, rng.choice([4, 30, 100])))
            if k32.CreateHardLinkW(q, p, None):
                names.append(q)
                made += 1
        for q in rng.sample(names, len(names) // 3):
            os.remove(q)
    return {"links": made}


def act_attrlist(c, links, streams):
    """Files with so many $FILE_NAME / named $DATA attributes that the base record needs an $ATTRIBUTE_LIST."""
    rng, base = c.rng, c.d("al")
    out = {}
    for i in range(4):
        p = os.path.join(base, f"big{i}.dat")
        write(p, rng.randbytes(2000))
        n = 0
        for j in range(links):
            if k32.CreateHardLinkW(os.path.join(base, f"big{i}_link{j:03d}_" + rname(rng, 120)), p, None):
                n += 1
        for j in range(streams):
            write(p + f":s{j:02d}_" + rname(rng, 50, "abcdef"), rng.randbytes(rng.choice([30, 300, 5000])))
        out[f"big{i}"] = n
        for q in sorted(os.listdir(base))[:: 3]:
            if q.startswith(f"big{i}_link"):
                os.remove(os.path.join(base, q))
    return out


def act_ads(c, files, streams):
    rng, base = c.rng, c.d("ads")
    made = 0
    for i in range(files):
        p = os.path.join(base, f"host{i:03d}.txt")
        write(p, b"host")
        for j in range(streams):
            write(f"{p}:st{j}" + rng.choice(["", " sp", "ñ", "Zone.Identifier"]), rng.randbytes(rng.choice([0, 20, 900,
                                                                                                         40000])))
            made += 1
        if i % 3 == 0:
            try:
                os.remove(f"{p}:st0")
            except OSError:
                pass
    dpath = c.d("ads", "dir with stream")
    write(dpath + ":dirstream", b"x" * 300)
    return {"streams": made}


def act_compress(c):
    rng, base = c.rng, c.d("cmp")
    for i in range(30):
        write(os.path.join(base, f"z{i}.txt"), (b"compressible " * rng.randrange(10, 20000)))
    r1 = sh([str(SYS32 / "compact.exe"), "/c", "/s:" + base, "/i", "/q"]).returncode
    for i in range(6):
        write(os.path.join(base, f"after{i}.txt"), b"inherits compression " * 3000)
    r2 = sh([str(SYS32 / "compact.exe"), "/u", os.path.join(base, "z1.txt"), os.path.join(base, "z2.txt")]).returncode
    wb = c.d("wof")
    for i, alg in enumerate(["lzx", "xpress4k", "xpress8k", "xpress16k"]):
        p = os.path.join(wb, f"w_{alg}.exe")
        write(p, rng.randbytes(30000) + b"\0" * 200000)
        sh([str(SYS32 / "compact.exe"), "/c", f"/exe:{alg}", p])
    r3 = sh([str(SYS32 / "compact.exe"), "/u", "/exe", os.path.join(wb, "w_xpress8k.exe")]).returncode
    return {"compact_c": r1, "compact_u": r2, "wof_u": r3}


def act_sparse(c):
    rng, base = c.rng, c.d("sparse")
    rcs = []
    for i in range(5):
        p = os.path.join(base, f"sp{i}.bin")
        write(p, rng.randbytes(256 * 1024))
        rc = fsutil("sparse", "setflag", p)
        rcs.append(rc)
        rcs.append(fsutil("sparse", "setrange", p, str(4096 * (i + 1)), str(65536)))
        if rc == 0:  # only a sparse file may take a far write without allocating the gap
            with open(p, "r+b") as f:
                f.seek((i + 1) * 64 * 1024 * 1024)
                f.write(b"far away data")
        rcs.append(fsutil("file", "setzerodata", f"offset={8192}", f"length={32768}", p))
    rcs.append(fsutil("sparse", "setflag", os.path.join(base, "sp0.bin"), "0"))
    return {"rcs": rcs}


def act_shortnames(c):
    rng, base = c.rng, c.d("short names dir")
    rcs = [fsutil("8dot3name", "set", f"{c.letter}:", "0")]
    for i in range(25):
        p = os.path.join(base, f"Long File Name Number {i} with spaces and {rname(rng, 20)}.document")
        write(p, b"8dot3")
        if i % 3 == 0:
            rcs.append(fsutil("file", "setshortname", p, f"SN{i:04d}~9.DOC"))
    for i in range(5):
        os.rename(os.path.join(base, next(n for n in os.listdir(base) if n.startswith(f"Long File Name Number {i} "))),
                  os.path.join(base, f"renamed long name {i}.document"))
    # /l keeps the strip log on the scratch volume (default would be %TEMP%).
    rcs.append(fsutil("8dot3name", "strip", "/f", "/s", "/l", os.path.join(c.root, "8dot3 strip.log"), base))
    return {"rcs": rcs}


def act_links(c):
    base = c.d("lnk")
    tgt = os.path.join(base, "target file.txt")
    write(tgt, b"target")
    tdir = c.d("lnk", "target dir")
    rcs = []
    cmd = [str(SYS32 / "cmd.exe"), "/c", "mklink"]
    rcs.append(sh(cmd + [os.path.join(base, "sym file.txt"), tgt]).returncode)
    rcs.append(sh(cmd + [os.path.join(base, "sym relative.txt"), "target file.txt"]).returncode)
    rcs.append(sh(cmd + ["/D", os.path.join(base, "sym dir"), tdir]).returncode)
    rcs.append(sh(cmd + ["/J", os.path.join(base, "junction"), tdir]).returncode)
    rcs.append(sh(cmd + [os.path.join(base, "dangling"), r"Z:\does\not\exist\anywhere.txt"]).returncode)
    rcs.append(sh(cmd + ["/J", os.path.join(base, "junction to root"), c.root]).returncode)
    for i in range(30):
        rcs.append(sh(cmd + [os.path.join(base, f"many{i:02d}"), f"..\\target{i}" * (1 + i % 5)]).returncode)
    for i in range(0, 30, 3):
        os.remove(os.path.join(base, f"many{i:02d}"))
    os.rmdir(os.path.join(base, "junction"))
    return {"rcs_nonzero": sum(1 for r in rcs if r)}


def act_objid(c):
    rng, base = c.rng, c.d("objid")
    rcs = []
    for i in range(30):
        p = os.path.join(base, f"oid{i}.txt")
        write(p, b"oid")
        if i % 2:
            rcs.append(fsutil("objectid", "create", p))
        else:
            ids = [rng.randbytes(16).hex() for _ in range(4)]
            rcs.append(fsutil("objectid", "set", *ids, p))
    for i in range(0, 30, 4):
        rcs.append(fsutil("objectid", "delete", os.path.join(base, f"oid{i}.txt")))
    for i in range(1, 30, 5):
        os.remove(os.path.join(base, f"oid{i}.txt"))
    return {"rcs_nonzero": sum(1 for r in rcs if r)}


SIDS = ["*S-1-1-0", "*S-1-5-32-545", "*S-1-5-32-544", "*S-1-5-11", "*S-1-5-18", "*S-1-5-19", "*S-1-5-20",
        "*S-1-5-32-551", "*S-1-5-32-547", "*S-1-3-0", "*S-1-5-4", "*S-1-5-6"]
PERMS = ["R", "W", "RX", "M", "F", "(RD)", "(WD,AD)", "(DE)", "(RC)", "(WDAC)", "(GR,GE)", "(S)"]


def act_acl(c, n):
    rng, base = c.rng, c.d("acl")
    ica = str(SYS32 / "icacls.exe")
    rcs = []
    for i in range(n):
        p = os.path.join(base, f"sd{i:03d}.txt")
        write(p, b"sd")
        args = [ica, p]
        for _ in range(rng.randrange(1, 4)):
            args += [rng.choice(["/grant", "/deny", "/grant:r"]), f"{rng.choice(SIDS)}:{rng.choice(PERMS)}"]
        if i % 7 == 0:
            args += ["/inheritance:r"]
        rcs.append(sh(args).returncode)
        if i % 11 == 0:
            rcs.append(sh([ica, p, "/setowner", rng.choice(SIDS[:3])]).returncode)
    for i in range(0, n, 9):
        rcs.append(sh([ica, os.path.join(base, f"sd{i:03d}.txt"), "/reset"]).returncode)
    return {"n": n, "rcs_nonzero": sum(1 for r in rcs if r)}


ATTRS = [0x1, 0x2, 0x4, 0x20, 0x100, 0x1000, 0x2000, 0x20000, 0x1 | 0x2 | 0x4, 0x2000 | 0x1000 | 0x20, 0x80,
         0x40000, 0x80000, 0x100000]


def act_attrib(c):
    base = c.d("attrib")
    ok = 0
    for i, a in enumerate(ATTRS):
        p = os.path.join(base, f"a{i:02d}_{a:x}.txt")
        write(p, b"attr")
        ok += bool(k32.SetFileAttributesW(p, a))
        ok += bool(k32.SetFileAttributesW(p, 0x80))
        ok += bool(k32.SetFileAttributesW(p, a | 0x20))
    d = c.d("attrib", "hidden system dir")
    ok += bool(k32.SetFileAttributesW(d, 0x2 | 0x4 | 0x10))
    return {"set_ok": ok}


def time_values():
    return [1, 7, HOUR * 11 + 1, HOUR * 12, HOUR * 12 - 1, HOUR * 13 + 5, HOUR * 15,
            ft(1899, 12, 30), ft(1970), ft(1980), ft(1999, 12, 31, 23), ft(1999, 12, 31, 22, 30),
            ft(2000), ft(2000, 1, 1, 0, 59, 59, 9_999_999), ft(2000, 2, 29, 23, 30), ft(2038, 1, 19, 3, 14, 8),
            ft(2099, 12, 31, 10), ft(2099, 12, 31, 23, 59, 59), ft(2100), ft(2106, 2, 7, 6, 28, 16),
            ft(9999, 12, 31, 9, 59, 59), ft(9999, 12, 31, 10), ft(9999, 12, 31, 23, 59, 59, 9_999_999),
            ft(2024, 3, 10, 2, 30), ft(2024, 11, 3, 1, 30), ft(2016, 12, 31, 23, 59, 59)]


def act_times(c, n):
    rng, base = c.rng, c.d("times")
    vals = time_values()
    ok = 0
    for i in range(n):
        p = os.path.join(base, f"t{i:03d}" + ("" if i % 4 else "_dir"))
        if i % 4:
            write(p, b"t" * rng.choice([1, 3000]))
        else:
            os.makedirs(p, exist_ok=True)
        if i < len(vals):
            v = vals[i]
            ok += set_times(p, v, v, v, v)
        else:
            ok += set_times(p, *(rng.choice(vals) for _ in range(4)))
        if i % 5 == 0:
            q = p + "_ren"
            os.rename(p, q)
    return {"set_ok": ok, "values": len(vals)}


def act_bigfiles(c, mb):
    rng, base = c.rng, c.d("big")
    chunk = 1 << 20
    hs = [open(os.path.join(base, f"big{i}.bin"), "wb") for i in range(4)]
    for k in range(mb):
        f = hs[k % 4] if k % 3 else rng.choice(hs)
        f.write(rng.randbytes(chunk) if k % 4 else b"\0" * chunk)
        f.flush()
    for f in hs:
        f.close()
    p0, p1, p2, p3 = (os.path.join(base, f"big{i}.bin") for i in range(4))
    os.truncate(p0, 12345)
    os.truncate(p1, os.path.getsize(p1) // 3)
    with open(p0, "ab") as f:
        f.write(rng.randbytes(5 * chunk))
    rcs = [fsutil("file", "seteof", p2, str(os.path.getsize(p2) + 50 * chunk)),
           fsutil("file", "setvaliddata", p2, str(os.path.getsize(p2) - 10 * chunk)),
           fsutil("file", "setzerodata", "offset=0", f"length={3 * chunk}", p3)]
    os.remove(p1)
    with open(os.path.join(base, "tail.bin"), "wb") as f:
        f.seek(mb // 2 * chunk)
        f.write(b"end")
    return {"mb": mb, "rcs": rcs}


def act_dirmass(c, dirs, per_dir):
    rng = c.rng
    total = 0
    for d in range(dirs):
        base = c.d("mass", f"D{d}")
        for i in range(per_dir):
            write(os.path.join(base, f"entry_{i:05d}_" + rname(rng, rng.choice([1, 30, 90]))), b"" if i % 2 else b"m")
            total += 1
    for d in range(dirs):
        base = os.path.join(c.root, "mass", f"D{d}")
        names = os.listdir(base)
        rng.shuffle(names)
        for n in names[: len(names) * (3 if d % 2 else 4) // 4]:
            os.remove(os.path.join(base, n))
        if d % 2 == 0:
            shutil.rmtree(base)
    return {"created": total}


def act_txf(c, n):
    ktm = ctypes.WinDLL("ktmw32", use_last_error=True)
    ktm.CreateTransaction.restype = HANDLE
    ktm.CreateTransaction.argtypes = [ctypes.c_void_p, ctypes.c_void_p, DWORD, DWORD, DWORD, DWORD, LPCWSTR]
    ktm.CommitTransaction.argtypes = [HANDLE]
    ktm.RollbackTransaction.argtypes = [HANDLE]
    rng, base = c.rng, c.d("txf")
    for i in range(20):
        write(os.path.join(base, f"pre{i}.txt"), b"pre-existing" * (i + 1))
    st = dict(commit=0, rollback=0, fail=0)
    for i in range(n):
        tx = ktm.CreateTransaction(None, None, 0, 0, 0, 0, f"t{i}")
        if tx in (None, INVALID):
            st["fail"] += 1
            continue
        ok = True
        p = os.path.join(base, f"tx{i:03d}.txt")
        h = k32.CreateFileTransactedW(p, 0x40000000, 0, None, 2, 0x80, None, tx, None, None)
        if h in (None, INVALID):
            ok = False
        else:
            buf = rng.randbytes(rng.choice([10, 2000, 30000]))
            k32.WriteFile(h, buf, len(buf), ctypes.byref(DWORD()), None)
            k32.CloseHandle(h)
        if i % 3 == 0:
            ok &= bool(k32.MoveFileTransactedW(os.path.join(base, f"pre{i % 20}.txt"),
                                               os.path.join(base, f"pre{i % 20}_tx{i}.txt"), None, None, 0, tx))
        if i % 4 == 1:
            ok &= bool(k32.CreateDirectoryTransactedW(None, os.path.join(base, f"txdir{i}"), None, tx))
        if i % 5 == 2:
            k32.DeleteFileTransactedW(os.path.join(base, f"tx{i - 1:03d}.txt"), tx)
        if rng.random() < 0.45:
            ktm.RollbackTransaction(tx)
            st["rollback"] += 1
        else:
            st["commit" if ktm.CommitTransaction(tx) else "fail"] += 1
        k32.CloseHandle(tx)
        st["fail"] += not ok
    return st


def act_quota_usn_label(c):
    L = f"{c.letter}:"
    user = os.environ.get("USERNAME", "Administrator")
    rcs = [fsutil("usn", "createjournal", "m=0x200000", "a=0x40000", L),
           fsutil("quota", "track", L),
           fsutil("quota", "modify", L, "3000000", "5000000", user)]
    base = c.d("q")
    for i in range(200):
        write(os.path.join(base, f"q{i}.bin"), c.rng.randbytes(c.rng.choice([10, 9000])))
    rcs.append(fsutil("quota", "enforce", L))
    for lab in ["FIRST", "Second Label", "ÑANDÚ ÜBER", "x" * 32, ""]:  # "" = delete the label (prompted)
        rcs.append(sh([str(SYS32 / "label.exe"), L] + ([lab] if lab else []), inp="\r\nS\r\n").returncode)
    cs = c.d("case sensitive")
    rcs.append(fsutil("file", "setCaseSensitiveInfo", cs, "enable"))
    write(os.path.join(cs, "Name.txt"), b"1")
    try:
        write(os.path.join(cs, "NAME.txt"), b"2")
    except OSError:
        pass
    rcs.append(fsutil("usn", "deletejournal", "/d", L, timeout=600))
    rcs.append(fsutil("quota", "disable", L))
    return {"rcs": rcs}


def act_chkdsk_fix(c):
    p = sh([str(SYS32 / "chkdsk.exe"), f"{c.letter}:", "/F", "/X"], inp="S\r\nS\r\n", timeout=1200)
    wait_for(c.letter)
    return {"chkdsk_rc": p.returncode}


def act_defrag(c):
    p1 = sh([str(SYS32 / "defrag.exe"), f"{c.letter}:", "/D", "/U"], timeout=1800)
    p2 = sh([str(SYS32 / "defrag.exe"), f"{c.letter}:", "/X", "/U"], timeout=1800)
    return {"defrag_rc": [p1.returncode, p2.returncode]}


def act_fill(c):
    rng, base = c.rng, c.d("fill")
    n = 0
    try:
        while True:
            write(os.path.join(base, f"f{n:05d}.bin"), rng.randbytes(rng.choice([256 * 1024, 1 << 20, 3000])))
            n += 1
    except OSError:
        pass
    for i in range(0, n, 2):
        try:
            os.remove(os.path.join(base, f"f{i:05d}.bin"))
        except OSError:
            pass
    m = 0
    try:
        while m < 20000:
            write(os.path.join(base, f"small{m:05d}_" + rname(rng, 20)), rng.randbytes(rng.choice([0, 100, 600])))
            m += 1
    except OSError:
        pass
    return {"big": n, "small": m}


def act_resident_flip(c, n):
    rng, base = c.rng, c.d("flip")
    for i in range(n):
        p = os.path.join(base, f"r{i:03d}.txt")
        write(p, rng.randbytes(rng.choice([1, 50, 400])))
        with open(p, "ab") as f:
            f.write(rng.randbytes(rng.choice([800, 3000, 70000])))
        os.truncate(p, rng.choice([0, 5, 300]))
        with open(p, "ab") as f:
            f.write(rng.randbytes(rng.choice([10, 5000])))
        s = p + ":flip"
        write(s, rng.randbytes(100))
        write(s, rng.randbytes(9000))
        write(s, rng.randbytes(10))
        if i % 4 == 0:
            os.remove(p)
    return {"n": n}


def act_ea(c, n):
    class IOSB(ctypes.Structure):
        _fields_ = [("status", ctypes.c_void_p), ("info", ctypes.c_void_p)]

    rng, base = c.rng, c.d("ea")
    ok = 0
    for i in range(n):
        p = os.path.join(base, f"ea{i:02d}.txt")
        write(p, b"ea")
        h = open_handle(p, 0x10 | 0x100, 0x80)
        if not h:
            continue
        name = f"EANAME{i}".encode()
        val = rng.randbytes(rng.choice([1, 40, 900]))
        rec = struct.pack("<IBBH", 0, 0, len(name), len(val)) + name + b"\0" + val
        buf = ctypes.create_string_buffer(rec + b"\0" * ((-len(rec)) % 4))
        ok += ntdll.NtSetEaFile(h, ctypes.byref(IOSB()), buf, len(buf)) == 0
        k32.CloseHandle(h)
    return {"ea_ok": ok}


WEIRD = ["it's", "O'Brien's ''quoted''", "a,b,,c", '" no', "100%done", "%s%n%x%d", "%%%%", "50% off, 'sale'.txt",
         "semi;colon", "tab\u00a0nbsp", "lone\ud800surrogate", "low\udfffonly", "\ud83d\ude00 emoji",
         "日本語ファイル名", "中文名字", "한국어", "Ελληνικά", "עברית", "\u202eRTL override.txt", "e\u0301combining",
         "zero\u200bwidth", "\ufeffbom", "\uffffnonchar", "trailing dot.", "trailing space ", "CON", "NUL.txt",
         "AUX", "COM1", "LPT9.log", "....", "x" * 255, "ä" * 255, "\U0001F600" * 127, "a" * 250 + "'.txt",
         "line\u2028sep", "back\\slash?",
         # A lone surrogate as the LAST unit makes SQLite 3.7.3's UTF-16 reader swallow the closing quote of the
         # INSERT literal (spec 06, edge case 11); a high surrogate right before a quote swallows that quote.
         "end high\ud800", "end low\udc00", "\ud800", "q\ud800'x", "two\ud800\ud800", "max pair \U0010FFFF",
         "\udfff\ud800 reversed", "comma\ud800,", "pct\ud800%s"]


def act_weird_names(c):
    rng = c.rng
    base = lp(c.root, "weird, 'names' %s")
    os.makedirs(base, exist_ok=True)
    ok, made, failed = 0, [], []
    for i, n in enumerate(WEIRD):
        for is_dir, p in ((False, os.path.join(base, n)), (True, os.path.join(base, f"d{i}_" + n[:200]))):
            try:
                if is_dir:
                    os.mkdir(p)
                    write(os.path.join(p, n), b"inner")
                else:
                    write(p, rng.randbytes(rng.choice([3, 2000])))
                made.append(p)
                ok += 1
            except (OSError, ValueError):
                failed.append(ascii(n[:40]) + ("/dir" if is_dir else ""))
    for p in made[::3]:
        try:
            q = p + "_ren'd,%n"
            os.rename(p, q)
        except OSError:
            pass
    for p in made[1::4]:
        try:
            if os.path.isdir(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
        except OSError:
            pass
    return {"created": ok, "tried": 2 * len(WEIRD), "failed": failed}


def act_path_lengths(c, targets):
    """Files whose FullPath as the original builds it ("\\" + dirs + "\\" + name, no drive letter, UTF-16 units)
    has an exact length: a chain of 200-unit ASCII directory names plus a file name of 55..255 units."""
    chain, made = [], {}
    for t in targets:
        k = max(0, -(-(t - 1 - 255) // 201))
        r = t - 1 - 201 * k
        while len(chain) < k:
            chain.append(f"P{len(chain):02d}" + "p" * 197)
            os.mkdir(lp(c.root, *chain))
        name = f"T{t}_" + "f" * (r - len(f"T{t}_"))
        p = lp(c.root, *chain[:k], name)
        write(p, b"len")
        made[t] = len("\\" + "\\".join(chain[:k] + [name]))
    return {"fullpath_len": made}


ACTS = {"sleep": act_sleep, "path_lengths": act_path_lengths, "make_activity": act_make_activity, "churn": act_churn, "many_open": act_many_open,
        "deep": act_deep, "deep2": act_deep2, "renames": act_renames, "hardlinks": act_hardlinks,
        "attrlist": act_attrlist, "ads": act_ads, "compress": act_compress, "sparse": act_sparse,
        "shortnames": act_shortnames, "links": act_links, "objid": act_objid, "acl": act_acl, "attrib": act_attrib,
        "times": act_times, "bigfiles": act_bigfiles, "dirmass": act_dirmass, "txf": act_txf,
        "quota_usn_label": act_quota_usn_label, "chkdsk_fix": act_chkdsk_fix, "defrag": act_defrag,
        "fill": act_fill, "resident_flip": act_resident_flip, "ea": act_ea, "weird_names": act_weird_names}


# --------------------------------------------------------------------------------------------- extraction
def logfile_summary(path):
    data = Path(path).read_bytes()
    out = {"size": len(data), "rstr": []}
    for i in (0, 1):
        p = data[i * 4096:(i + 1) * 4096]
        if p[:4] != b"RSTR":
            out["rstr"].append({"sig": p[:4].hex()})
            continue
        chk = struct.unpack_from("<Q", p, 8)[0]
        sysps, logps, ra, minor, major = struct.unpack_from("<IIHhh", p, 0x10)
        cur, nclients, _, _, flags, seqbits = struct.unpack_from("<QHHHHI", p, ra)
        fsize = struct.unpack_from("<Q", p, ra + 0x18)[0]
        out["rstr"].append(dict(version=f"{major}.{minor}", chkdsk_lsn=chk, page=[sysps, logps],
                                current_lsn=cur, flags=flags, seq_number_bits=seqbits, file_size=fsize))
    lsns, ff = [], 0
    for off in range(0x2000, len(data) - 4095, 4096):
        sig = data[off:off + 4]
        if sig == b"RCRD":
            lsns.append(struct.unpack_from("<Q", data, off + 8)[0])
        elif data[off:off + 8] == b"\xff" * 8:
            ff += 1
    out["rcrd_pages"], out["ff_pages"] = len(lsns), ff
    out["partial_tail_bytes"] = len(data) % 4096
    if lsns:
        seqbits = next((r["seq_number_bits"] for r in out["rstr"] if "seq_number_bits" in r), 0)
        nz = [x for x in lsns if x]
        if nz:
            out["last_lsn_min"], out["last_lsn_max"] = min(nz), max(nz)
            if seqbits:
                out["lsn_seq_min"], out["lsn_seq_max"] = min(nz) >> (64 - seqbits), max(nz) >> (64 - seqbits)
        out["runs"] = 1 + sum(1 for a, b in zip(lsns, lsns[1:]) if b and a and b < a)
    return out


def extract(letter, dst_dir):
    dst_dir.mkdir(parents=True, exist_ok=True)
    for rec, name in ((2, "$LogFile"), (0, "$MFT")):
        sh([PY, "-I", str(EXTRACT), f"{letter}:", str(dst_dir / name), "--record", str(rec)], timeout=600, check=True)
    return logfile_summary(dst_dir / "$LogFile")


# --------------------------------------------------------------------------------------------- volume driver
PREFIX = "vhd"  # --prefix: a second corpus from another --seed gets its own case names (e.g. vhd2)


def case_ids():
    """Static numbering: (volume index, case index within volume) -> <prefix>-NNN-<slug>[-tag]."""
    ids, n = {}, 0
    for vi, v in enumerate(V):
        multi = len(v["cases"]) > 1
        for ci, (tag, _) in enumerate(v["cases"]):
            ids[(vi, ci)] = (n, f"{PREFIX}-{n:03d}-{v['slug']}" + (f"-{tag}{ci}" if multi else ""))
            n += 1
    return ids


def format_volume(v, path, letter):
    label = ("V" + v["slug"].replace("-", ""))[:11].upper()
    lines = [f'create vdisk file="{path}" maximum={v["size_mb"]} type=expandable', f'select vdisk file="{path}"',
             "attach vdisk", "create partition primary"]
    if not v["frs4k"]:
        lines.append(f'format fs=ntfs unit={v["unit"]} quick label={label}')
    lines.append(f"assign letter={letter}")
    diskpart(lines)
    wait_for(letter, fs=not v["frs4k"])
    if v["frs4k"]:
        unit = str(v["unit"]) if v["unit"] < 16384 else f"{v['unit'] // 1024}K"  # format.com wants 64K, not 65536
        sh([str(SYS32 / "format.com"), f"{letter}:", "/FS:NTFS", f"/A:{unit}", "/L", "/Q", "/Y", f"/V:{label}"],
           inp="\r\n", timeout=1200, check=True)
        wait_for(letter)
    if v["log_kb"]:
        sh([str(SYS32 / "chkdsk.exe"), f"{letter}:", "/F", "/X", f"/L:{v['log_kb']}"], inp="S\r\nS\r\n", timeout=1200)
        wait_for(letter)
    info = sh([str(SYS32 / "fsutil.exe"), "fsinfo", "ntfsinfo", f"{letter}:"]).stdout
    return [l.strip() for l in info.splitlines() if any(k in l for k in ("Bytes", "LFS", "FileRecord"))]


def reattach(path, guid, letter, readonly):
    diskpart([f'select vdisk file="{path}"', "detach vdisk"], check=False)  # diskpart has crashed after detaching
    if any(str(path).lower() == l.lower() for l in attached_vdisks()):
        raise RuntimeError(f"{path.name} still attached after detach")
    diskpart([f'select vdisk file="{path}"', "attach vdisk" + (" readonly" if readonly else "")])
    time.sleep(3)
    have = volume_letters(guid)
    if letter in have and len(have) == 1:
        return letter
    new = free_letter(letter)
    diskpart([f'select vdisk file="{path}"', "select partition 1", "remove all noerr", f"assign letter={new}"])
    wait_for(new)
    return new


def run_volume(vi, v, seed, ids, tzs, force):
    targets = {ci: ids[(vi, ci)] for ci in range(len(v["cases"]))}
    if not force and all((CASES / cid).exists() for _, cid in targets.values()):
        log(f"[{v['slug']}] all cases exist, skipping")
        return []
    path = VHD_DIR / f"{vi:02d}-{v['slug']}.{v['ext']}"
    work = VHD_DIR / f"_work-{v['slug']}"
    shutil.rmtree(work, ignore_errors=True)
    rng = random.Random(f"{seed}/{v['slug']}")
    letter = free_letter()
    steps, extracts, written = [], {}, []
    log(f"[{v['slug']}] {path.name} {v['size_mb']} MB unit={v['unit']} frs4k={v['frs4k']} log_kb={v['log_kb']} "
        f"letter={letter}")
    try:
        geom = format_volume(v, path, letter)
        guid = volume_guid(letter)
        ctx = Ctx(letter, rng, seed)
        for step in v["plan"]:
            name, params = step[0], (step[1] if len(step) > 1 else {})
            t0 = time.time()
            if name == "extract":
                time.sleep(2)
                extracts[params] = extract(letter, work / params)
                steps.append({"extract": params, "letter": letter})
                log(f"[{v['slug']}]   extract {params}: {extracts[params]}")
                continue
            if name in ("remount_ro", "remount_rw"):
                letter = reattach(path, guid, letter, name == "remount_ro")
                ctx.letter, ctx.root = letter, f"{letter}:\\"
                steps.append({name: True, "letter": letter})
                continue
            try:
                res = ACTS[name](ctx, **params)
            except Exception as e:  # an activity failing must not lose the volume; record it
                res = {"error": f"{type(e).__name__}: {e}"[:300]}
            steps.append({name: params, "result": res, "secs": round(time.time() - t0, 1)})
            log(f"[{v['slug']}]   {name} {params} -> {res} ({time.time() - t0:.1f}s)")
        for ci, (tag, mft) in enumerate(v["cases"]):
            n, cid = targets[ci]
            utc, dst = tzs[n % len(tzs)]
            out = CASES / cid
            if out.exists():
                if not force:
                    continue
                shutil.rmtree(out)
            out.mkdir(parents=True)
            shutil.copyfile(work / tag / "$LogFile", out / "$LogFile")
            if mft:
                shutil.copyfile(work / tag / "$MFT", out / "$MFT")
            geo = f"{v['size_mb']} MB, {v['unit']} B clusters, {'4096' if v['frs4k'] else '1024'} B FILE records"
            variant = {"live": "extracted live while mounted (LFS 2.0, dirty restart area)",
                       "ro": "after clean detach + read-only re-attach (clean restart area, LFS downgraded to 1.1)",
                       "rw": "after clean detach + read-write re-attach (mount-time records)",
                       "post": "after chkdsk /F (log reset)"}[tag]
            cj = {"utc": utc, "dst": dst, "mft": mft, "family": "vhd",
                  "desc": f"{v['why']} [{geo}; {variant}]",
                  "base": f"real NTFS volume fuzz/vhd/{path.name} (deleted after extraction): {geo}, "
                          f"log {'resized to ' + str(v['log_kb']) + ' KB' if v['log_kb'] else 'default size'}",
                  "mutation": {"generator": "re/fuzz/gen_vhd.py", "seed": seed, "volume": v["slug"],
                               "variant": tag, "size_mb": v["size_mb"], "cluster": v["unit"],
                               "frs": 4096 if v["frs4k"] else 1024, "log_kb": v["log_kb"], "container": v["ext"],
                               "ntfsinfo": geom, "steps": steps, "logfile": extracts[tag],
                               "mft_size": (work / tag / "$MFT").stat().st_size}}
            (out / "case.json").write_text(json.dumps(cj, ensure_ascii=False, indent=1), encoding="utf-8")
            written.append(cid)
            log(f"[{v['slug']}] wrote {cid} utc={utc} dst={dst} mft={mft}")
    finally:
        detach(path)
        time.sleep(1)
        for _ in range(10):
            try:
                path.unlink(missing_ok=True)
                break
            except OSError:
                time.sleep(2)
                detach(path)
        shutil.rmtree(work, ignore_errors=True)
    return written


def cleanup():
    VHD_DIR.mkdir(parents=True, exist_ok=True)
    for p in list(VHD_DIR.glob("*.vhd")) + list(VHD_DIR.glob("*.vhdx")):
        log("cleanup: detaching and deleting", p.name)
        detach(p)
        p.unlink(missing_ok=True)
    for p in VHD_DIR.glob("_work-*"):
        shutil.rmtree(p, ignore_errors=True)
    left = attached_vdisks()
    log("still attached under fuzz/vhd:", left or "none")
    return left


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default="", help="comma-separated volume slugs")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--force", action="store_true", help="overwrite existing case directories")
    ap.add_argument("--cleanup", action="store_true", help="detach/delete leftover disks in fuzz/vhd and exit")
    ap.add_argument("--prefix", default="vhd", help="case-name prefix (use a new one with a new --seed)")
    a = ap.parse_args()
    global PREFIX
    PREFIX = a.prefix
    ids, tzs = case_ids(), tz_assignment(a.seed)
    if a.list:
        for (vi, ci), (n, cid) in sorted(ids.items()):
            tag, mft = V[vi]["cases"][ci]
            print(cid, tag, "mft" if mft else "-", tzs[n % len(tzs)])
        return
    if a.cleanup:
        sys.exit(1 if cleanup() else 0)
    VHD_DIR.mkdir(parents=True, exist_ok=True)
    CASES.mkdir(parents=True, exist_ok=True)
    only = set(filter(None, a.only.split(",")))
    unknown = only - {v["slug"] for v in V}
    if unknown:
        sys.exit(f"unknown slugs: {sorted(unknown)}")
    cleanup()
    written, failed = [], []
    try:
        for vi, v in enumerate(V):
            if only and v["slug"] not in only:
                continue
            try:
                written += run_volume(vi, v, a.seed, ids, tzs, a.force)
            except Exception as e:
                failed.append(f"{v['slug']}: {type(e).__name__}: {e}"[:400])
                log("FAILED", failed[-1])
    finally:
        left = cleanup()
    log(f"written {len(written)} cases; failed volumes: {failed or 'none'}; attached left: {left or 'none'}")


if __name__ == "__main__":
    main()
