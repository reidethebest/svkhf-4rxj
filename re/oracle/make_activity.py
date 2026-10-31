"""Generate varied, edge-case file-system activity on a scratch NTFS volume (for synthetic $LogFile samples).

  python make_activity.py T:\\ [--seed 1]

Only touches the given (test) volume. Covers: names with quote/comma/space/non-ASCII/surrogate pairs, long names
(8.3 short names and tunneling), resident and non-resident writes, fragmentation, renames, cross-directory moves,
deletes, directory trees, alternate data streams, hard links, and extreme timestamps (1601 and far future).
"""
import ctypes
import os
import random
import sys
import time
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype = wintypes.HANDLE
k32.SetFileTime.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

NAMES = ["plain.txt", "it's here.txt", "a,b,c.csv", "with space and, comma's.log", "café.txt", "niño año.doc",
         "Ελληνικά.txt", "日本語ファイル.txt", "emoji 😀 file.txt", "Résumé (final) v2.docx", "x" * 120 + ".txt",
         "LONGFILENAME_FOR_83.TXT", "semi;colon.txt", "per%cent.txt", "back`tick.txt", "tab\u00a0nbsp.txt",
         "Привет мир.txt", "über-straße.txt", "ünïcödé'quote,comma.txt"]


def set_times(path, ft):
    h = k32.CreateFileW(path, 0x100, 7, None, 3, 0x02000000, None)  # FILE_WRITE_ATTRIBUTES, backup semantics
    if h == wintypes.HANDLE(-1).value:
        return
    t = ctypes.c_ulonglong(ft)
    k32.SetFileTime(h, ctypes.byref(t), ctypes.byref(t), ctypes.byref(t))
    k32.CloseHandle(h)


def main():
    root = sys.argv[1]
    rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    base = os.path.join(root, "act")
    os.makedirs(base, exist_ok=True)
    dirs = [base]
    for d in ["docs", "docs/sub dir", "tmp", "Ñandú's, folder", "深い/フォルダ", "a/b/c/d/e"]:
        p = os.path.join(base, d)
        os.makedirs(p, exist_ok=True)
        dirs.append(p)
    files = []
    for i, n in enumerate(NAMES):
        p = os.path.join(rnd.choice(dirs), n)
        size = rnd.choice([10, 300, 700, 5000, 70000, 300000])
        with open(p, "wb") as f:
            f.write(os.urandom(size))
        files.append(p)
    # Fragmented non-resident growth.
    big = os.path.join(base, "growing, file's.bin")
    for _ in range(30):
        with open(big, "ab") as f:
            f.write(os.urandom(rnd.choice([4096, 65536, 100000])))
        with open(os.path.join(base, "tmp", "filler%d.bin" % rnd.randrange(1000)), "wb") as f:
            f.write(os.urandom(8192))
    files.append(big)
    # Resident value updates.
    small = os.path.join(base, "small resident.txt")
    for i in range(20):
        with open(small, "w", encoding="utf-8") as f:
            f.write("v%d " % i * rnd.randrange(1, 40))
    # Renames, moves and tunneling (delete then re-create the same name quickly).
    for i in range(25):
        p = rnd.choice(files)
        if not os.path.exists(p):
            continue
        d = rnd.choice(dirs)
        newname = rnd.choice(NAMES).replace(".", "_%d." % i, 1)
        q = os.path.join(d, newname)
        if not os.path.exists(q):
            os.replace(p, q)
            files[files.index(p)] = q
    for p in list(files)[:6]:
        if os.path.exists(p):
            tmp = p + ".tmp"
            with open(tmp, "wb") as f:
                f.write(b"new content")
            os.remove(p)
            os.replace(tmp, p)
    # Alternate data streams and hard links.
    with open(small + ":hidden stream", "wb") as f:
        f.write(b"ads data" * 50)
    try:
        os.link(small, os.path.join(base, "docs", "hard link, to small.txt"))
    except OSError:
        pass
    # Extreme timestamps.
    t1 = os.path.join(base, "time 1601.txt")
    t2 = os.path.join(base, "time future.txt")
    t3 = os.path.join(base, "time zero-ish.txt")
    for p in (t1, t2, t3):
        with open(p, "wb") as f:
            f.write(b"t")
    set_times(t1, 1)                         # 1601-01-01 00:00:00.0000001
    set_times(t2, 0x7FFF35F4F06C7FFF)         # near the FILETIME maximum (year 30827)
    set_times(t3, 36_000_000_000 * 2)        # 1601-01-01 02:00:00
    # Deletes, including a whole tree.
    for p in files[::3]:
        if os.path.exists(p):
            os.remove(p)
    for dp, dn, fn in os.walk(os.path.join(base, "a"), topdown=False):
        for n in fn:
            os.remove(os.path.join(dp, n))
        os.rmdir(dp)
    time.sleep(1)
    print("activity done")


if __name__ == "__main__":
    main()
