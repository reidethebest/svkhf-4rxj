"""Fuzz-case generator, family "mft": $MFT-input edge cases paired with a $LogFile (mft=true in every case).

  python -I re/fuzz/gen_mft.py [--seed 1] [--out fuzz/cases] [--only SUBSTR] [--list]

Writes fuzz/cases/mft-NNN-<slug>/{$LogFile, $MFT, case.json}. Deterministic: the same seed and the same inputs give
byte-identical cases. Inputs (read-only): samples/synth-01/$LogFile + samples/synth-01/$MFT (same volume), and, when
present, real volumes extracted from scratch VHDs into fuzz/vhd-mft/<vol>/{$MFT,$LogFile} (cases skipped otherwise).
re/oracle/lfsdump.py is imported (read-only) to list the $LogFile's record LSNs and op codes.

Spec: re/spec/04-attributes-time-paths.md (2.4 ParseMFT 0x416310, 2.5 BuildFullPath 0x41adf0, 2.6 V40 lookup,
E12..E18), re/spec/02-logfile-structure.md (V40 lookup, edge case 23), re/spec/06-persistence-csv.md (escaping,
Unicode through SQLite, CSV). All $MFT bytes are written in on-disk form (update-sequence array applied), except
where a case deliberately breaks it.

"Neutral" base: synth-01 $MFT with record 101 ("time future.txt") SI C/M/A changed from 0x7FFF35F4F06C7FFF (year
30827, whose V40 time string makes the original read an uninitialised FILETIME, U3: nondeterministic in seed-01) to
its own MFT-modified time. Every case starts from it unless it says otherwise.

Targeted behaviours (one or more cases each):
  Directory map / FullPath (BuildFullPath 0x41adf0, ComposeFullPath in 0x412710):
  - parent cycles: 2-directory cycle (docs <-> sub dir) and 3-directory cycle (no cycle guard, U5: the original is
    expected to loop / grow a CString until timeout or allocation failure); a cycle among unreferenced records
    (must NOT hang);
  - self-parented directory other than the root (key == parentRef -> no DirEntry at all);
  - parent reference to a missing / invalid record, to a garbage ref, and to the root with sequence 0 (the first
    parent is looked up without the root test, later ones with the seq-agnostic root test);
  - parents that are files (DirEntry flag 0: relative path without leading backslash);
  - a non-root directory named "." (stops the walk like the root), a directory named "..", the root renamed;
  - parent sequence-number mismatch (record header seq changed / $FN parent seq changed);
  - sequence-bit leak across skipped records (E12): a DOS-only / zero-length-name record before a directory;
  - very deep chain (100 synthetic directory levels, FullPath ~1.3k UTF-16 units);
  - directory names with ' , " % (escaping, 2^k quote doubling on copies), non-BMP / best-fit / non-characters,
    lone high/low surrogates (SQLite UTF-16 reader swallows the next unit, incl. the closing quote), embedded
    NUL (truncation), TAB/CR/LF, backslash, single space, DEL/control units, 255-unit names.
  Record level (ParseMFT 0x416310):
  - FILE signature broken / "BAAD", usa_ofs low byte not 0x30/0x2a, first-attribute offset >= 0x1f4 and just below;
  - NTFS 3.0 layout (usa_ofs 0x2a, first attribute at 0x30);
  - in-use flag cleared on every record; flags word variants (1 on a directory, 0, 2, 0xB, 0x103, 7, 0x8003);
  - base-record reference set (extension records), $ATTRIBUTE_LIST with the $FN moved to an extension record that
    has no $SI (stale $SI from the previous processed record, E13);
  - multiple $FILE_NAME: DOS after Win32, DOS before Win32, hard links (order swapped), a second Win32 name in
    another directory (last qualifying wins), a zero-length $FN (ignored), a $FN whose name starts with NUL
    (qualifies, empties the name -> record skipped);
  - attribute length 0 (FN, first SI, after FN), > 0x400 (stop), 0x80000060, landing exactly on 0x400, misaligned
    (lands mid-attribute), type 0x100 before the $FN (walk stops on type > 0xff);
  - attribute value offset / non-resident value offset far past the 1 KiB record (the original reads its
    never-written 10 MiB heap buffer, U11; a port with a small slack buffer may fault);
  - usa_ofs far past the record (USN read from never-written buffer -> no fixup) and just past it (0x430);
  - update-sequence mismatch at 0x1fe inside a name, usa_count 0 (raw USN units in the name), a name crossing
    0x3fe and running past 0x400 (fixup at 0x3fe + zero tail truncation), a $FN length byte at the 0x3fe sector end;
  - record LSN (FILE+8): duplicates (first inserted = lowest record wins), LSN 0, LSNs moved onto log records of
    every op pair incl. multi-page records, ~200 synthetic records hitting random log records;
  - $SI times: 0, 1, 1 tick, 12 h exactly / minus 1 tick (negative-shift underflow boundary), 9999-12-31 23:59:59
    and 10:00:00 (+shift crosses into a 5-digit year), sub-second ticks; >= 2^63 (V40 FileTimeToSystemTime fails
    and the slot keeps the previous V40 hit's value per field; the previous hit is pinned on the same log page);
  - record 0 capture of p+0x1a8 (E18): $SI(future) $FN("$MFT") $SI(normal) order, "$MFT" name in record 1, record
    0 without $SI and renamed ($MFT row gone, "20"-prefix Abnormal rule, siSeen skip path).
  File level:
  - $MFT truncated mid-record, length not a multiple of 1024, empty (0 bytes);
  - $MFT of a different volume: synthesized (permuted records, foreign seqs and LSNs) and real (scratch VHD);
  - 4096-byte FILE records (read by the original with a fixed 1024 stride): synthesized from synth-01 and real
    (scratch VHD formatted with large FRS), the latter also with its own $LogFile.
  Time zones vary per case (-12, +14 with DST, 0, -3, +9 and others).
"""
import argparse
import datetime
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "re" / "oracle"))
sys.dont_write_bytecode = True  # never leave a __pycache__ under re/oracle/
import lfsdump  # noqa: E402  (read-only helper)

FAMILY = "mft"
SYNTH = ROOT / "samples" / "synth-01"
VHD = ROOT / "fuzz" / "vhd-mft"
REC = 0x400
HOUR = 36_000_000_000
BASE_DESC = "samples/synth-01 ($LogFile + $MFT, same volume)"


# ----------------------------------------------------------------------------------------------- byte helpers
def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def p16(b, o, v):
    struct.pack_into("<H", b, o, v)


def p32(b, o, v):
    struct.pack_into("<I", b, o, v)


def p64(b, o, v):
    struct.pack_into("<Q", b, o, v)


def ref(rec, seq):
    return (seq << 48) | rec


def U(s):
    """UTF-16 code units of s (lone surrogates allowed)."""
    b = s.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack("<%dH" % (len(b) // 2), b))


def ft(y, mo, d, h=0, mi=0, s=0, ticks=0):
    dt = datetime.datetime(y, mo, d, h, mi, s) - datetime.datetime(1601, 1, 1)
    return (dt.days * 86400 + dt.seconds) * 10_000_000 + ticks


def hexu(units):
    return " ".join("%04X" % u for u in units)


# ----------------------------------------------------------------------------------------------- FILE records
def fixup(raw):
    """On-disk -> logical (standard NTFS: every sector end equal to the USN gets its saved value)."""
    L = bytearray(raw)
    uo, uc = u16(L, 4), u16(L, 6)
    if uo + 2 * uc > len(L):
        return L
    usn = bytes(L[uo:uo + 2])
    for k in range(1, uc):
        e = k * 512 - 2
        if e + 2 <= len(L) and L[e:e + 2] == usn:
            L[e:e + 2] = L[uo + 2 * k:uo + 2 * k + 2]
    return L


def unfix(L):
    """Logical -> on-disk: save every sector end in the USA and write the USN there."""
    D = bytearray(L)
    uo, uc = u16(D, 4), u16(D, 6)
    usn = bytes(D[uo:uo + 2])
    for k in range(1, uc):
        e = k * 512 - 2
        if e + 2 > len(D):
            break
        D[uo + 2 * k:uo + 2 * k + 2] = D[e:e + 2]
        D[e:e + 2] = usn
    return D


def attrs_of(L):
    """Raw attribute blobs of a logical record, from the first-attribute offset to the end marker."""
    out, off = [], u16(L, 0x14)
    while off + 8 <= len(L):
        t, n = struct.unpack_from("<II", L, off)
        if t == 0xFFFFFFFF or n == 0 or off + n > len(L):
            break
        out.append(bytes(L[off:off + n]))
        off += n
    return out


def rebuild(L, attrs, a0=None):
    """New logical record: header bytes of L up to a0, the attributes, end marker; used size updated."""
    a0 = u16(L, 0x14) if a0 is None else a0
    N = bytearray(len(L))
    N[:a0] = L[:a0]
    p16(N, 0x14, a0)
    off = a0
    for a in attrs:
        N[off:off + len(a)] = a
        off += len(a)
    assert off + 8 <= len(N), "record overflow"
    N[off:off + 4] = b"\xff\xff\xff\xff"
    p32(N, 0x18, off + 8)
    return N


def resident(t, value, attr_id=0, indexed=0):
    n = (0x18 + len(value) + 7) & ~7
    a = bytearray(n)
    struct.pack_into("<IIBBHHHIHBB", a, 0, t, n, 0, 0, 0x18, 0, attr_id, len(value), 0x18, indexed, 0)
    a[0x18:0x18 + len(value)] = value
    return bytes(a)


def typ(a):
    return u32(a, 0)


def fn_parts(a):
    vo = u16(a, 0x14)
    v = a[vo:]
    n = v[0x40]
    return u64(v, 0), list(struct.unpack_from("<%dH" % n, v, 0x42)), v[0x41], v


def mk_fn(template, parent=None, units=None, ns=None, attr_id=None):
    p0, u0, ns0, v = fn_parts(template)
    parent = p0 if parent is None else parent
    units = u0 if units is None else units
    ns = ns0 if ns is None else ns
    value = bytearray(v[:0x40])
    p64(value, 0, parent)
    value += bytes([len(units), ns]) + struct.pack("<%dH" % len(units), *units)
    return resident(0x30, bytes(value), u16(template, 0xE) if attr_id is None else attr_id, 1)


def si_times(a):
    vo = u16(a, 0x14)
    return [u64(a, vo + 8 * k) for k in range(4)]


def with_si_times(a, times):
    a = bytearray(a)
    vo = u16(a, 0x14)
    for k, t in enumerate(times):
        if t is not None:
            p64(a, vo + 8 * k, t)
    return bytes(a)


class Mft:
    def __init__(self, data):
        self.n = len(data) // REC
        self.raw = [bytearray(data[i * REC:(i + 1) * REC]) for i in range(self.n)]
        self.tail = bytes(data[self.n * REC:])

    def copy(self):
        return Mft(self.data())

    def data(self):
        return b"".join(bytes(r) for r in self.raw) + self.tail

    def L(self, i):
        return fixup(self.raw[i])

    def put(self, i, L):
        self.raw[i] = unfix(L)

    def valid(self, i):
        return self.raw[i][:4] == b"FILE"

    def attrs(self, i):
        return attrs_of(self.L(i))

    def set_attrs(self, i, attrs, a0=None):
        self.put(i, rebuild(self.L(i), attrs, a0))

    def hdr(self, i, seq=None, flags=None, lsn=None, base=None):
        L = self.L(i)
        old = {"seq": u16(L, 0x10), "flags": u16(L, 0x16), "lsn": u64(L, 8), "base": u64(L, 0x20)}
        if seq is not None:
            p16(L, 0x10, seq)
        if flags is not None:
            p16(L, 0x16, flags)
        if lsn is not None:
            p64(L, 8, lsn)
        if base is not None:
            p64(L, 0x20, base)
        self.put(i, L)
        return old

    def lsn(self, i):
        return u64(self.raw[i], 8)

    def seq(self, i):
        return u16(self.raw[i], 0x10)

    def fns(self, i):
        return [a for a in self.attrs(i) if typ(a) == 0x30]

    def name(self, i, k=-1):
        u = fn_parts(self.fns(i)[k])[1]
        return struct.pack("<%dH" % len(u), *u).decode("utf-16-le", "replace")

    def set_fn(self, i, k=-1, **kw):
        """Replace the k-th $FILE_NAME of record i (parent / units / ns)."""
        at = self.attrs(i)
        idx = [j for j, a in enumerate(at) if typ(a) == 0x30][k]
        old = fn_parts(at[idx])
        at[idx] = mk_fn(at[idx], **kw)
        self.set_attrs(i, at)
        return {"parent": "%d/%d" % (old[0] & 0xFFFFFFFFFFFF, old[0] >> 48), "units": hexu(old[1]), "ns": old[2]}

    def set_si(self, i, times):
        at = self.attrs(i)
        j = next(j for j, a in enumerate(at) if typ(a) == 0x10)
        old = si_times(at[j])
        at[j] = with_si_times(at[j], times)
        self.set_attrs(i, at)
        return old


# ----------------------------------------------------------------------------------------------- inputs
class Ctx:
    def __init__(self, seed):
        self.seed = seed
        self.logfile = (SYNTH / "$LogFile").read_bytes()
        self.orig = Mft((SYNTH / "$MFT").read_bytes())
        self.base = self.orig.copy()
        # Neutralise record 101's year-30827 SI times (U3 nondeterminism through V40).
        r101 = self.base.attrs(101)[0]
        assert typ(r101) == 0x10 and si_times(r101)[0] == 0x7FFF35F4F06C7FFF, "unexpected synth-01 record 101"
        mm = si_times(r101)[2]
        self.base.set_si(101, [mm, mm, None, mm])
        self.neutral_note = {"rec101_si_CMA": "0x7FFF35F4F06C7FFF -> 0x%X (own MFT-modified time)" % mm}
        self.rec = {}
        for i in range(self.orig.n):
            if self.orig.valid(i) and self.orig.fns(i):
                self.rec.setdefault(self.orig.name(i), i)
        expect = {"act": 38, "docs": 39, "sub dir": 40, "tmp": 41, "Ñandú's, folder": 42, "深い": 43, "フォルダ": 44,
                  "a": 45, "e": 49, "WPSettings.dat": 37, "filler540.bin": 71, "filler782.bin": 72,
                  "filler961.bin": 73, "time future.txt": 101, ".": 5, "$MFT": 0}
        for k, v in expect.items():
            assert self.rec.get(k) == v, (k, self.rec.get(k))
        self.dir_tmpl = self.base.attrs(45)  # 'a': SI(0x60) FN INDEX_ROOT(0x50), the smallest directory record
        recs = [lfsdump.decode(o, b) for o, b in lfsdump.records(self.logfile)]
        self.log_recs = sorted({r["lsn"]: r for r in recs}.values(), key=lambda r: r["lsn"])
        self.mft_lsns = {self.orig.lsn(i) for i in range(self.orig.n) if self.orig.valid(i)}

    def rnd(self, tag):
        return random.Random("%d/%s" % (self.seed, tag))

    def free_log_lsns(self):
        return [r for r in self.log_recs if r["lsn"] not in self.mft_lsns and "redo" in r]

    def dir_record(self, recno, seq, units, parent, lsn, flags=3, times=None):
        """Logical directory record built from the template 'a' (record 45)."""
        L = self.base.L(45)
        p32(L, 0x2C, recno)
        p16(L, 0x10, seq)
        p16(L, 0x16, flags)
        p64(L, 8, lsn)
        si, fn, ir = self.dir_tmpl
        if times:
            si = with_si_times(si, times)
        return rebuild(L, [si, mk_fn(fn, parent=parent, units=units), ir])

    def file_record(self, recno, seq, units, parent, lsn, times, flags=1):
        L = self.base.L(71)  # filler540.bin: SI FN $DATA(non-resident)
        p32(L, 0x2C, recno)
        p16(L, 0x10, seq)
        p16(L, 0x16, flags)
        p64(L, 8, lsn)
        si, fn, data = self.base.attrs(71)
        return rebuild(L, [with_si_times(si, times), mk_fn(fn, parent=parent, units=units), data])


# ----------------------------------------------------------------------------------------------- cases
CASES = []


def case(slug, utc, dst):
    def deco(f):
        CASES.append((slug, utc, dst, f))
        return f
    return deco


def rename(m, i, s, **kw):
    return {"rec": i, "fn": m.set_fn(i, units=U(s) if isinstance(s, str) else s, **kw),
            "new_units": hexu(U(s) if isinstance(s, str) else s)}


@case("baseline-neutral", -3, False)
def c_baseline(c):
    return ("control: synth-01 $MFT with only the neutral fix of record 101 (year-30827 SI times); every other "
            "mft case is a diff against this", c.base, {})


@case("cycle-2dir", 9, False)
def c_cycle2(c):
    m = c.base.copy()
    mut = {"docs(39).fn.parent": m.set_fn(39, parent=ref(40, 1))["parent"] + " -> 40/1 (sub dir)"}
    return ("parent cycle docs -> sub dir -> docs: BuildFullPath has no cycle guard (U5), the original should loop "
            "growing a CString (timeout/crash expected) at the first path through docs", m, mut)


@case("cycle-3dir", -5, True)
def c_cycle3(c):
    m = c.base.copy()
    mut = {"深い(43).parent": m.set_fn(43, parent=ref(42, 1))["parent"] + " -> 42/1",
           "Ñandú(42).parent": m.set_fn(42, parent=ref(44, 1))["parent"] + " -> 44/1",
           "フォルダ(44).parent": "43/1 (unchanged)"}
    return ("3-directory parent cycle 42 -> 44 -> 43 -> 42 under act: unbounded BuildFullPath walk in the original "
            "(hang/alloc failure) vs a port guard", m, mut)


@case("cycle-unreferenced", 1, False)
def c_cycle_unref(c):
    m = c.base.copy()
    m.put(150, c.dir_record(150, 1, U("loopA"), ref(151, 1), 0))
    m.put(151, c.dir_record(151, 1, U("loopB"), ref(150, 1), 0))
    return ("two synthetic directories (150, 151, LSN 0) forming a parent cycle that no log record or V40 hit "
            "reaches: the original must NOT hang, output identical to baseline", m,
            {"rec150": "dir loopA parent 151/1 lsn 0", "rec151": "dir loopB parent 150/1 lsn 0"})


@case("parent-self-missing", -3, False)
def c_parent_missing(c):
    m = c.base.copy()
    mut = {"tmp(41).parent": m.set_fn(41, parent=ref(41, 1))["parent"] + " -> 41/1 (itself: key==parent, no DirEntry)",
           "docs(39).parent": m.set_fn(39, parent=ref(200, 1))["parent"] + " -> 200/1 (zero record)",
           "Ñandú(42).parent": m.set_fn(42, parent=0xFFFFFFFFFFFFFFFF)["parent"] + " -> 0xFFFFFFFFFFFFFFFF",
           "深い(43).parent": m.set_fn(43, parent=ref(5, 0))["parent"] + " -> 5/0 (root, seq 0)"}
    return ("self-parented directory (no DirEntry), parent in a zero record, garbage parent ref, and parent = root "
            "with seq 0 (first lookup has no root test, deeper ones are seq-agnostic)", m, mut)


@case("parent-is-file", 5, False)
def c_parent_file(c):
    m = c.base.copy()
    mut = {"docs(39).parent": m.set_fn(39, parent=ref(99, 1))["parent"] + " -> 99/1 (file small resident.txt)",
           "tmp(41).parent": m.set_fn(41, parent=ref(37, 1))["parent"] + " -> 37/1 (file WPSettings.dat)",
           "Ñandú(42).parent": m.set_fn(42, parent=ref(52, 5))["parent"] + " -> 52/5 (deleted file, flags 0)"}
    return ("directories whose parent is a file record (DirEntry flag 0): the walk stops and FullPath becomes a "
            "relative path without leading backslash", m, mut)


@case("dot-named-dir", -12, False)
def c_dot(c):
    m = c.base.copy()
    mut = {"docs": rename(m, 39, "."), "tmp": rename(m, 41, "..")}
    return ("non-root directory named '.' (DirEntry via the '.' branch, stops the walk as if it were the root) and "
            "one named '..'", m, mut)


@case("root-renamed", 14, True)
def c_root(c):
    m = c.base.copy()
    mut = {"root(5)": rename(m, 5, "$Root")}
    return ("root record renamed from '.' to '$Root': key == parent so it gets no DirEntry; first-level lookups "
            "through the root fail while deeper walks still end at the seq-agnostic root test", m, mut)


@case("parent-seq-mismatch", 9, True)
def c_seq(c):
    m = c.base.copy()
    mut = {"act(38).hdr.seq": m.hdr(38, seq=2)["seq"], "act.new_seq": 2,
           "sub dir(40).hdr.seq": m.hdr(40, seq=0)["seq"], "sub dir.new_seq": 0,
           "Ñandú(42).parent": m.set_fn(42, parent=ref(38, 0xFFFF))["parent"] + " -> 38/0xFFFF"}
    return ("sequence-number mismatches: act and sub dir header seq changed (children reference the old seq), "
            "Ñandú's parent seq 0xFFFF; dirMap keys include the seq", m, mut)


@case("seq-leak", -8, False)
def c_leak(c):
    m = c.base.copy()
    mut = {"WPSettings(37)": {"seq": m.hdr(37, seq=6)["seq"], "new_seq": 6, "fn": m.set_fn(37, ns=2), "new_ns": 2},
           "深い(43)": {"seq": m.hdr(43, seq=8)["seq"], "new_seq": 8, "fn": m.set_fn(43, units=[]),
                       "new_units": "(length 0)"}}
    return ("E12 sequence-bit leak: skipped records (DOS-only name, zero-length name) leave their seq in hiAcc, so "
            "the next directory (act, フォルダ) is keyed with OR-ed seqs and its children lose their paths", m, mut)


@case("deep-chain", 2, False)
def c_deep(c):
    m = c.base.copy()
    r = c.rnd("deep")
    parent, names = ref(38, 1), []
    for k in range(142, 242):
        nm = "L%03d" % (k - 141) + "_" * r.randrange(0, 12)
        names.append(nm)
        m.put(k, c.dir_record(k, 1, U(nm), parent, 0))
        parent = ref(k, 1)
    mut = {"recs": "142..241 synthetic directories, each the child of the previous, 142 under act",
           "docs(39).parent": m.set_fn(39, parent=parent)["parent"] + " -> 241/1",
           "path_units_to_docs": sum(len(n) + 1 for n in names) + len("\\act\\docs")}
    return ("very deep parent chain: docs re-parented under 100 synthetic directory levels (FullPath of the docs "
            "subtree ~1.3k units, no fixed buffers expected)", m, mut)


@case("dirname-quotes", 0, True)
def c_quotes(c):
    m = c.base.copy()
    mut = {"docs": rename(m, 39, "it's \"q\", 100%s%d"), "tmp": rename(m, 41, "''"),
           "Ñandú": rename(m, 42, "a,b','c"), "sub dir": rename(m, 40, "\"")}
    return ("directory names with single quotes, commas, double quotes and printf specifiers: quote doubling "
            "(2^k on copied rows), ',' -> '/', unescaped '\"' in the CSV", m, mut)


@case("dirname-unicode", 9, False)
def c_unicode(c):
    m = c.base.copy()
    mut = {"\u6df1\u3044": rename(m, 43, "deep \U0001F600 \u00e9 \u0141 \uff21 \u2019 \u20ac \u2026 \u0301x"),
           "\u30d5\u30a9\u30eb\u30c0": rename(m, 44, "\u0081\u008d\ufffe\uffff\u00a0z"),
           "docs": rename(m, 39, "\u0395\u03bb\u03bb\u03b7\u03bd\u03b9\u03ba\u03ac"),
           "tmp": rename(m, 41, "e\u0301\u200b\u2028 t")}
    return ("directory names with a surrogate pair, best-fit-mapped chars (cp1252 CSV), C1 controls, U+FFFE/U+FFFF "
            "(SQLite stores U+FFFD), Greek, combining and zero-width / line-separator units", m, mut)


@case("dirname-lone-surrogate", -12, False)
def c_lone(c):
    m = c.base.copy()
    mut = {"docs": rename(m, 39, "doc\ud800s"), "tmp": rename(m, 41, "tmp\udc00"), "sub dir": rename(m, 40, "\ud83d")}
    return ("lone surrogates in directory names: SQLite's UTF-16 reader swallows the next unit (a path '\\', or "
            "the closing quote of the V40 FileName literal -> broken INSERT)", m, mut)


@case("dirname-nul-ctrl", 3, False)
def c_nul(c):
    m = c.base.copy()
    mut = {"docs": rename(m, 39, "do\x00cs"), "tmp": rename(m, 41, "t\tm\r\np"), "sub dir": rename(m, 40, "sub\\dir"),
           "Ñandú": rename(m, 42, " "), "深い": rename(m, 43, "N" * 254 + "Z"), "フォルダ": rename(m, 44, "\x7f\x01")}
    return ("directory names with an embedded NUL (Format %s truncation), TAB/CR/LF, a backslash, a single space, "
            "the 255-unit maximum and control units", m, mut)


@case("multi-fn", -6, True)
def c_multi(c):
    m = c.base.copy()
    mut = {}
    at = m.attrs(99)  # small resident.txt: FN(act) FN(docs, hard link) -> swap
    i, j = [k for k, a in enumerate(at) if typ(a) == 0x30]
    at[i], at[j] = at[j], at[i]
    m.set_attrs(99, at)
    mut["rec99"] = "hard-link $FN order swapped (last qualifying wins: 'small resident.txt' in act)"
    at = m.attrs(41)
    fn = next(a for a in at if typ(a) == 0x30)
    at.insert(at.index(fn) + 1, mk_fn(fn, parent=ref(39, 1), units=U("tmp2"), ns=1, attr_id=9))
    m.set_attrs(41, at)
    mut["tmp(41)"] = "second Win32 $FN 'tmp2' (parent docs) after the original"
    at = m.attrs(40)
    fn = next(a for a in at if typ(a) == 0x30)
    at.insert(at.index(fn) + 1, mk_fn(fn, units=U("SUBDIR~1"), ns=2, attr_id=9))
    at.insert(at.index(fn) + 2, mk_fn(fn, units=[], ns=1, attr_id=10))
    m.set_attrs(40, at)
    mut["sub dir(40)"] = "DOS $FN 'SUBDIR~1' then a zero-length Win32 $FN after the original (both ignored)"
    at = m.attrs(42)
    fn = next(a for a in at if typ(a) == 0x30)
    at.insert(at.index(fn), mk_fn(fn, units=U("NANDUS~1"), ns=2, attr_id=9))
    m.set_attrs(42, at)
    mut["Ñandú(42)"] = "DOS $FN before the Win32 one"
    at = m.attrs(36)
    fn = next(a for a in at if typ(a) == 0x30)
    at.insert(at.index(fn) + 1, mk_fn(fn, units=U("\x00abc"), ns=1, attr_id=9))
    m.set_attrs(36, at)
    mut["System Volume Information(36)"] = ("second Win32 $FN whose name starts with NUL: qualifies, empties the "
                                            "name, record skipped (WPSettings.dat loses its path)")
    at = m.attrs(43)
    fn = next(a for a in at if typ(a) == 0x30)
    at.insert(at.index(fn) + 1, mk_fn(fn, units=U("deep2"), ns=3, attr_id=9))
    m.set_attrs(43, at)
    mut["深い(43)"] = "second Win32&DOS $FN 'deep2', same parent"
    return ("multiple $FILE_NAME attributes: hard-link order, extra Win32 names in other/same directories, DOS "
            "before/after Win32, zero-length and NUL-leading names (last qualifying $FN wins)", m, mut)


@case("ext-attrlist", 10, False)
def c_ext(c):
    m = c.base.copy()
    docs_lsn = m.lsn(39)
    at = m.attrs(39)
    fn = next(a for a in at if typ(a) == 0x30)
    si = at[0]
    # $ATTRIBUTE_LIST entries: type, len 0x20, name len 0, name off 0x1a, start vcn 0, base ref, attr id.
    al = b"".join(struct.pack("<IHBBQQH6x", t, 0x20, 0, 0x1A, 0, r, aid)
                  for t, r, aid in ((0x10, ref(39, 1), 0), (0x30, ref(150, 1), 2), (0x90, ref(39, 1), 3)))
    m.set_attrs(39, [si, resident(0x20, al, 5)] + [a for a in at if typ(a) not in (0x10, 0x30)])
    L = m.L(39)
    L150 = bytearray(REC)
    L150[:0x38] = L[:0x38]
    p64(L150, 8, docs_lsn)
    p16(L150, 0x16, 3)
    p64(L150, 0x20, ref(39, 1))
    p32(L150, 0x2C, 150)
    m.put(150, rebuild(L150, [fn], 0x38))
    L151 = bytearray(REC)
    L151[:0x38] = m.L(99)[:0x38]
    p64(L151, 0x20, ref(99, 1))
    p32(L151, 0x2C, 151)
    lsn151 = c.rnd("ext").choice([x for x in c.free_log_lsns() if (x["redo"], x["undo"]) == (7, 7)])["lsn"]
    p64(L151, 8, lsn151)
    m.put(151, rebuild(L151, [mk_fn(m.fns(99)[0], parent=ref(39, 1), units=U("ext link.txt"))], 0x38))
    olds = {}
    for i in (38, 41, 44):
        olds[i] = m.hdr(i, base=ref(7, 7))["base"]
    mut = {"docs(39)": "$FN removed, resident $ATTRIBUTE_LIST added (SI@39, FN@150, IR@39): no name -> skipped",
           "rec150": "extension (base 39/1, flags 3, seq 1, lsn %d) with only $FN 'docs' parent act: stale $SI of "
                     "record 141 (E13)" % u64(L150, 8), "rec151": "extension (base 99/1, lsn %d) with only $FN "
                                                                   "'ext link.txt' in docs" % lsn151,
           "base_ref_set": "records 38, 41, 44 base ref 0 -> 7/7 (ignored by the original)"}
    return ("extension records: docs' $FN moved to an extension record behind an $ATTRIBUTE_LIST (keyed under "
            "the extension's own record number, stale $SI), plus base-reference set on normal records", m, mut)


@case("flags-variants", 4, False)
def c_flags(c):
    m = c.base.copy()
    new = {38: 2, 39: 1, 41: 0xB, 42: 0x103, 43: 7, 44: 0x8003, 40: 0}
    mut = {str(i): {"old": m.hdr(i, flags=f)["flags"], "new": f} for i, f in new.items()}
    return ("flags word compared as a whole: act 2 (dir, not in use), docs 1 (file), sub dir 0, tmp 0xB, Ñandú "
            "0x103, 深い 7, フォルダ 0x8003 -> DirEntry flag 1 / flag 0 / none", m, mut)


@case("inuse-cleared", -4, True)
def c_inuse(c):
    m = c.base.copy()
    n = 0
    for i in range(m.n):
        if m.valid(i):
            f = u16(m.raw[i], 0x16)
            if f & 1:
                p16(m.raw[i], 0x16, f & ~1)
                n += 1
    return ("in-use bit cleared on every FILE record (deleted records): the original never tests it, so output "
            "should equal the baseline (0xD/9/5/7 -> 0xC/8/4/6 stay without DirEntry)", m, {"records_changed": n})


@case("sig-invalid", 6, False)
def c_sig(c):
    m = c.base.copy()
    m.raw[39][:4] = b"BAAD"
    m.raw[41][:4] = b"FILD"
    m.raw[42][4] = 0x28
    p16(m.raw[44], 0x14, 0x1F4)
    p16(m.raw[40], 0x14, 0x1F0)
    mut = {"docs(39)": "sig FILE -> BAAD", "tmp(41)": "sig FILE -> FILD", "Ñandú(42)": "byte +4 0x30 -> 0x28",
           "フォルダ(44)": "first attr 0x38 -> 0x1F4 (invalid)", "sub dir(40)": "first attr 0x38 -> 0x1F0 (valid, "
                                                                            "walk starts in slack)"}
    return ("record validation: BAAD / wrong signature, usa_ofs low byte not 0x30/0x2a, first-attribute offset "
            "0x1f4 (invalid) and 0x1f0 (valid, garbage walk); invalid records mask the seq accumulator", m, mut)


@case("attr-len-0", -7, False)
def c_len0(c):
    m = c.base.copy()

    def zero_len(i, t, nth=0):
        L = m.L(i)
        off = u16(L, 0x14)
        k = 0
        while True:
            if u32(L, off) == t:
                if k == nth:
                    p32(L, off + 4, 0)
                    m.put(i, L)
                    return off
                k += 1
            off += u32(L, off + 4)
    mut = {"docs(39).FN.len@0x%X" % zero_len(39, 0x30): 0, "tmp(41).SI.len@0x%X" % zero_len(41, 0x10): 0,
           "Ñandú(42).INDEX_ROOT.len@0x%X" % zero_len(42, 0x90): 0}
    L = m.L(44)
    off = u32(L, 0x18) - 8
    struct.pack_into("<II", L, off, 0x80, 0)
    m.put(44, L)
    mut["フォルダ(44).end_marker@0x%X" % off] = "0xFFFFFFFF -> type 0x80 len 0"
    return ("attribute length 0: on the $FN (walk stops before the name), on the first $SI (stops at once), after "
            "the $FN (no effect), and in place of the end marker", m, mut)


@case("attr-len-overrun", 8, False)
def c_overrun(c):
    m = c.base.copy()
    mut = {}
    for i, n in ((39, 0x1000), (41, 0x3C8), (42, 0x68), (43, 0x80000060)):
        L = m.L(i)
        mut["%d.SI.len" % i] = "0x%X -> 0x%X" % (u32(L, 0x3C), n)
        p32(L, 0x3C, n)
        m.put(i, L)
    at = m.attrs(44)
    at.insert(1, resident(0x100, b"\x00" * 0x20, 7))
    m.set_attrs(44, at)
    mut["フォルダ(44)"] = "type 0x100 attribute inserted between $SI and $FN (walk stops on type > 0xff)"
    return ("attribute lengths: 0x1000 (> 0x400, stop after $SI), 0x3C8 (lands exactly on 0x400, reads past the "
            "record), 0x68 (misaligned, parses $FN bytes as a header), 0x80000060; type 0x100 before the $FN", m, mut)


@case("attr-ofs-far", 11, False)
def c_far(c):
    m = c.base.copy()
    L = m.L(39)
    p16(L, 0x38 + 0x14, 0x7F00)
    m.put(39, L)
    L = m.L(41)
    off = 0x38 + u32(L, 0x3C)
    assert u32(L, off) == 0x30
    p16(L, off + 0x14, 0x2000)
    m.put(41, L)
    L = m.L(42)
    L[0x38 + 8] = 1
    nr = u16(L, 0x38 + 0x20)
    m.put(42, L)
    mut = {"docs(39).SI.value_off": "0x18 -> 0x7F00", "tmp(41).FN.value_off": "0x18 -> 0x2000",
           "Ñandú(42).SI.nonresident": "0 -> 1 (value offset taken from word +0x20 = 0x%X)" % nr}
    return ("attribute values addressed far past the 1 KiB record (resident offset 0x7F00 / 0x2000, non-resident "
            "flag -> mapping-pairs offset): the original reads its never-written 10 MiB heap buffer (zeros, U11)",
            m, mut)


@case("usa-ofs-far", 12, False)
def c_usa_far(c):
    m = c.base.copy()
    p16(m.raw[39], 4, 0x7F30)
    p16(m.raw[41], 4, 0xFF2A)
    return ("usa_ofs 0x7F30 / 0xFF2A (low byte still valid): USN read from the never-written buffer (0), sector "
            "ends keep the raw USN; no visible change expected, tests out-of-record reads", m,
            {"docs(39).usa_ofs": "0x30 -> 0x7F30", "tmp(41).usa_ofs": "0x30 -> 0xFF2A"})


def long_name_record(c, m, i, prefix, mark):
    """Rebuild directory record i as SI + FN(long name crossing 0x1fe, unit at 0x1fe = mark) + small INDEX_ROOT."""
    L = m.L(i)
    si = m.attrs(i)[0]
    fn = m.fns(i)[0]
    fn_off = u16(L, 0x14) + len(si)
    k = (0x1FE - (fn_off + 0x5A)) // 2
    units = (U(prefix) + [ord("x")] * k)[:k] + [ord(mark)] + U("-tail")
    m.set_attrs(i, [si, mk_fn(fn, units=units), c.dir_tmpl[2]])
    return k, units


@case("fixup", -10, False)
def c_fixup(c):
    m = c.base.copy()
    mut = {}
    k, units = long_name_record(c, m, 39, "docs-mismatch-", "#")
    m.raw[39][0x1FE:0x200] = b"Q\x00"
    mut["docs(39)"] = "name unit %d at 0x1fe '#'; on-disk sector end 0x1fe = 'Q' != USN -> not replaced" % k
    k, units = long_name_record(c, m, 41, "tmp-count0-", "#")
    p16(m.raw[41], 6, 0)
    mut["tmp(41)"] = "name unit %d at 0x1fe '#'; usa_count 0 -> raw USN 0x%04X stays in the name" % (
        k, u16(m.raw[41], 0x30))
    k, units = long_name_record(c, m, 42, "nandu-usa430-", "#")
    p16(m.raw[42], 4, 0x430)
    mut["Ñandú(42)"] = "name unit %d at 0x1fe '#'; usa_ofs 0x430 (just past the record: USN 0 -> no fixup)" % k
    k, units = long_name_record(c, m, 44, "folder-ok-", "#")
    mut["フォルダ(44)"] = "control: name unit %d at 0x1fe '#', correct update sequence" % k
    return ("update-sequence fixups inside directory names crossing 0x1fe: sector-end mismatch, usa_count 0, "
            "usa_ofs just past the record, and a correct control", m, mut)


@case("fn-at-record-end", 13, False)
def c_fn_end(c):
    m = c.base.copy()
    # tmp: SI, pad(0x40), FN at 0x388 whose name starts at 0x3e2, crosses 0x3fe and runs past 0x400.
    L = m.L(41)
    si, fn = m.attrs(41)[0], m.fns(41)[0]
    N = bytearray(REC)
    N[:0x38] = L[:0x38]
    N[0x38:0x38 + len(si)] = si
    pad_off = 0x38 + len(si)
    struct.pack_into("<IIBBHHHIHBB", N, pad_off, 0x40, 0x388 - pad_off, 0, 0, 0x18, 0, 8, 0x10, 0x18, 0, 0)
    units = U("tmp_end_of_recZ" + "-lost-beyond-0x400-" + "y" * 5)
    full = mk_fn(fn, units=units)
    N[0x388:0x400] = full[:0x400 - 0x388]
    p32(N, 0x18, 0x400)
    assert 0x388 + 0x5A + 2 * 14 == 0x3FE and units[14] == ord("Z")
    m.put(41, N)
    # docs: SI, pad, FN whose length byte (value+0x40) is the low byte of the 0x3fe sector end; name starts at 0x400.
    L = m.L(39)
    si, fn = m.attrs(39)[0], m.fns(39)[0]
    N = bytearray(REC)
    N[:0x38] = L[:0x38]
    N[0x38:0x38 + len(si)] = si
    fn_off = 0x3BE - 0x18
    pad_off = 0x38 + len(si)
    struct.pack_into("<IIBBHHHIHBB", N, pad_off, 0x40, fn_off - pad_off, 0, 0, 0x18, 0, 8, 0x10, 0x18, 0, 0)
    full = mk_fn(fn, units=U("docs"))
    N[fn_off:0x400] = full[:0x400 - fn_off]
    p32(N, 0x18, 0x400)
    m.put(39, N)
    mut = {"tmp(41)": "FN at 0x388, name 0x3e2.., unit 14 'Z' at 0x3fe (fixup), declared %d units, record ends at "
                      "0x400 (no end marker)" % len(units),
           "docs(39)": "FN at 0x%X, name length byte at 0x3fe (from usa[2]) = 4, name bytes at 0x400.. (never "
                       "written: zeros) -> empty name, record skipped" % fn_off}
    return ("$FN at the very end of the record: name crossing the 0x3fe fixup and running past 0x400 (truncated by "
            "the zero tail of the 10 MiB buffer), and a length byte at the sector end", m, mut)


@case("lsn-dup", 13, True)
def c_lsn_dup(c):
    m = c.base.copy()
    mut = {}
    for i, j in ((41, 70), (140, 71), (141, 44)):
        mut["rec%d.lsn" % i] = "%d -> %d (= rec%d's; first inserted = rec%d wins)" % (m.lsn(i), m.lsn(j), j,
                                                                                     min(i, j))
        m.hdr(i, lsn=m.lsn(j))
    mut["docs(39).lsn"] = "%d -> 0" % m.lsn(39)
    m.hdr(39, lsn=0)
    return ("duplicate FILE-record LSNs (multimap lower_bound: lowest record index wins) and LSN 0", m, mut)


@case("lsn-on-events", -11, True)
def c_lsn_events(c):
    m = c.base.copy()
    r = c.rnd("lsn-on-events")
    free = c.free_log_lsns()
    pairs = [(2, 0), (3, 2), (14, 15), (15, 14), (12, 13), (13, 12), (7, 7), (9, 9), (5, 6), (6, 5), (11, 11),
             (0, 0), (27, 1), (21, 22), (22, 21), (20, 20), (19, 19), (8, 0), (37, 0), (28, 0), (1, 0), (0, 3),
             (0, 2), (8, 8), (16, 16), (17, 17), (10, 0), (29, 0)]
    picks = []
    for pr in pairs:
        cand = [x for x in free if (x["redo"], x["undo"]) == pr]
        if cand:
            picks.append(r.choice(cand))
    span = [x for x in free if x["off"] % 4096 + 0x30 + x["cdl"] > 4096 and x not in picks]
    picks += r.sample(span, min(3, len(span)))
    targets = [i for i in range(50, 142) if m.valid(i) and i not in (71, 72, 73, 99, 101)]
    mut = []
    for i, x in zip(targets, picks):
        mut.append({"rec": i, "name": m.name(i), "old_lsn": m.lsn(i), "new_lsn": x["lsn"],
                    "op": "%d/%d" % (x["redo"], x["undo"]), "multipage": x["off"] % 4096 + 0x30 + x["cdl"] > 4096})
        m.hdr(i, lsn=x["lsn"])
    return ("FILE-record LSNs moved onto log records of every op pair (creation, deletion, index add/delete, "
            "resident/non-resident updates, renames, multi-page records): V40 values meet every branch", m,
            {"moves": mut})


def everywhere(c, tag, n_new):
    m = c.base.copy()
    r = c.rnd(tag)
    free = c.free_log_lsns()
    picks = r.sample(free, len(free))
    pool = ["plain.txt", "it's here.txt", "a,b,c.csv", "with space and, comma's.log", "café.txt", "日本語.txt",
            "emoji \U0001F600.txt", "LONGFILENAME_FOR_83.TXT", "per%cent.txt", "x" * 100 + ".bin", "Ω~1.txt",
            "semi;colon.txt", "q\"uote.txt", "$Fake"]
    parents = [ref(38, 1), ref(39, 1), ref(40, 1), ref(41, 1), ref(42, 1), ref(43, 1), ref(44, 1), ref(5, 5),
               ref(11, 11), ref(30, 1), ref(36, 1), ref(45, 2), ref(49, 2), ref(99, 1), ref(250, 1)]
    moved, k = 0, 0
    for i in range(50, 142):
        if m.valid(i) and i not in (99, 101):
            m.hdr(i, lsn=picks[k]["lsn"])
            k += 1
            moved += 1
    made = 0
    for i in range(142, 142 + n_new):
        y = r.randrange(2001, 2031)
        t = [ft(y, r.randrange(1, 13), r.randrange(1, 29), r.randrange(24), r.randrange(60), r.randrange(60),
                r.randrange(10_000_000)) for _ in range(4)]
        nm = "%s_%d" % (r.choice(pool), i)
        if r.random() < 0.15:
            m.put(i, c.dir_record(i, r.randrange(1, 4), U("dir_" + nm), r.choice(parents), picks[k]["lsn"],
                                  times=t))
        else:
            m.put(i, c.file_record(i, r.randrange(1, 4), U(nm), r.choice(parents), picks[k]["lsn"], t,
                                   flags=r.choice((0, 1, 1, 1))))
        k += 1
        made += 1
    return m, {"existing_records_moved": moved, "synthetic_records": "142..%d" % (141 + n_new),
               "lsns": "random sample (seeded) of log LSNs not used by the base $MFT"}


@case("lsn-everywhere-a", 7, False)
def c_every_a(c):
    m, mut = everywhere(c, "everywhere-a", 114)
    return ("~200 FILE records (existing user files re-pointed + 114 synthetic files/dirs, mixed names/parents/"
            "seqs/times) whose LSNs hit random log records: V40 in every context", m, mut)


@case("lsn-everywhere-b", -3, True)
def c_every_b(c):
    m, mut = everywhere(c, "everywhere-b", 60)
    return ("second random draw of V40 hits on random log records (different LSN sample, names and parents)",
            m, mut)


EXTREMES = [
    ("zero", [0, 0, 0, 0]),
    ("one-tick", [1, 1, 1, 1]),
    ("12h-exact/12h-1", [12 * HOUR, 12 * HOUR - 1, 12 * HOUR + 1, 3 * HOUR]),
    ("9999-12-31", [ft(9999, 12, 31, 23, 59, 59, 9_999_999), ft(9999, 12, 31, 10), ft(9999, 12, 31, 9, 59, 59),
                    ft(9999, 12, 31, 23)]),
    ("mixed", [0, ft(9999, 12, 31, 23, 59, 59), 1, 12 * HOUR]),
    ("subsecond", [ft(2000, 1, 1, 0, 0, 0, 9_999_999), ft(1999, 12, 31, 23, 59, 59, 5_000_000),
                   ft(2000, 1, 1, 11, 59, 59), ft(2038, 1, 19, 3, 14, 8)]),
    ("leap", [ft(2024, 2, 29, 23, 30), ft(2100, 2, 28, 23), ft(1601, 1, 1, 14, 59, 59), ft(1601, 1, 1, 12)]),
]


def extremes(c):
    m = c.base.copy()
    assert ft(9999, 12, 31, 23, 59, 59, 9_999_999) == 0x24C85A5ED1C03FFF
    mut = {}
    for i, (tag, t) in zip(range(74, 74 + len(EXTREMES)), EXTREMES):
        mut["rec%d(%s, lsn %d)" % (i, m.name(i), m.lsn(i))] = {"case": tag, "old": ["0x%X" % x for x in m.set_si(i, t)],
                                                               "new": ["0x%X" % x for x in t]}
    return m, mut


@case("si-extremes-pos", 14, True)
def c_ext_pos(c):
    m, mut = extremes(c)
    return ("V40 $SI times at extremes with +15 h: 0, 1 tick, 12 h boundaries, 9999-12-31 (shift crosses into "
            "year 10000, 5-digit output), sub-second ticks, leap days", m, mut)


@case("si-extremes-neg", -12, False)
def c_ext_neg(c):
    m, mut = extremes(c)
    return ("same V40 extreme times with -12 h: underflow below 1601 keeps the unshifted string, 12 h exactly "
            "reaches FILETIME 0", m, mut)


@case("si-highbit", 9, False)
def c_highbit(c):
    m = c.base.copy()
    t540 = [ft(2011, 1, 2, 3, 4, 5), ft(2012, 6, 7, 8, 9, 10), ft(2013, 11, 12, 13, 14, 15), ft(2014, 4, 5, 6, 7, 8)]
    t782 = [1 << 63, 0xFFFFFFFFFFFFFFFF, ft(2015, 5, 5, 5, 5, 5), (1 << 63) + 12345]
    t961 = [1 << 63, (1 << 63) + 1, 0xFFFFFFFFFFFFFFFE, 0xC000000000000000]
    mut = {}
    for i, t in ((71, t540), (72, t782), (73, t961)):
        mut["rec%d(%s, lsn %d)" % (i, m.name(i), m.lsn(i))] = ["0x%X" % x for x in t]
        m.set_si(i, t)
    mut["note"] = ("LSNs 1145892/1145920/1145948 are consecutive records on one log page, so the failed V40 "
                   "conversions of 72 and 73 repeat the slot of the previous hit field by field")
    return ("V40 $SI times >= 2^63: FileTimeToSystemTime fails and the original prints the previous V40 hit's "
            "SYSTEMTIME slot per field (deterministic: predecessor hit pinned on the same page)", m, mut)


@case("mftcreate-two-si", -3, False)
def c_mftcreate(c):
    m = c.base.copy()
    at = m.attrs(0)
    si, fn = at[0], at[1]
    assert typ(si) == 0x10 and typ(fn) == 0x30
    fut = with_si_times(si, [ft(2099, 1, 1), ft(2099, 1, 2), ft(2099, 1, 3), ft(2099, 1, 4)])
    m.set_attrs(0, [fut, fn, si] + at[2:])
    old1 = m.set_fn(1, units=U("$MFT"))
    m.set_si(1, [1, 1, 1, 1])
    return ("record 0 = $SI(2099) $FN('$MFT') $SI(normal): p+0x1a8 captures the $SI current at the $FN (2099 -> "
            "every deletion row 'Abnormal Timestamp'), V40 uses the last $SI; record 1 also named '$MFT' "
            "(index != 0, no capture)", m, {"rec0": "SI(2099-01-01..04), FN $MFT, SI(original), rest",
                                             "rec1": {"fn": old1, "new": "$MFT", "si": "all 1"}})


@case("rec0-no-si", -12, False)
def c_rec0(c):
    m = c.base.copy()
    at = m.attrs(0)
    m.set_attrs(0, at[1:])
    old = m.set_fn(0, units=U("$MFX"))
    m.hdr(0, seq=0x40)
    return ("record 0 without $SI and renamed '$MFX': siSeen skip path (no $MFT V40 row, seq leak), p+0x1a8 "
            "stays empty -> '20'-prefix Abnormal rule with $MFT present", m,
            {"rec0": {"si": "removed", "fn": old, "new": "$MFX", "seq": "1 -> 0x40"}})


@case("trunc-mid-record", 5, True)
def c_trunc(c):
    d = c.base.data()[:40 * REC + 700]
    return ("$MFT truncated 700 bytes into record 40: GetLength >> 10 drops the partial record and everything "
            "after it (sub dir, tmp, ... lose names and paths)", Mft(d), {"length": len(d)})


@case("len-not-multiple", 1, False)
def c_len(c):
    d = c.base.data() + bytes(c.base.raw[38][:1000])
    return ("$MFT length = 256 KiB + 1000 (a partial copy of a valid FILE record): the trailing partial record is "
            "ignored, output should equal the baseline", Mft(d), {"length": len(d)})


@case("empty", -3, False)
def c_empty(c):
    return ("empty $MFT (0 bytes): the open succeeds but no record is read; maps empty, p+0x1a8 empty", Mft(b""),
            {"length": 0})


@case("foreign-synth", 2, True)
def c_foreign(c):
    m = c.base.copy()
    r = c.rnd("foreign")
    users = list(range(36, 142))
    perm = users[:]
    r.shuffle(perm)
    src = {i: c.base.L(j) for i, j in zip(users, perm)}
    lsns = [x["lsn"] for x in c.log_recs]
    lo, hi = lsns[0] - 40000, lsns[-1] + 40000
    hits = 0
    for i in range(m.n):
        if not m.valid(i):
            continue
        L = src.get(i, m.L(i))
        if i >= 36:
            p16(L, 0x10, r.randrange(1, 30))
            p32(L, 0x2C, i)
        if r.random() < 0.15:
            p64(L, 8, r.choice(lsns))
            hits += 1
        else:
            p64(L, 8, r.randrange(lo, hi))
        m.put(i, L)
    m.set_si(0, [ft(2023, 3, 1, 10), None, None, None])
    return ("synthesized $MFT of a different volume: user records permuted, foreign seqs and LSNs (15% equal to "
            "log LSNs), $MFT created 2023: names/paths/times from unrelated records", m,
            {"permutation_seed": "%d/foreign" % c.seed, "lsn_hits_forced": hits})


@case("frs4k-synth", 0, False)
def c_frs4k(c):
    out = []
    for i in range(c.base.n):
        if not c.base.valid(i):
            out.append(bytes(0x1000))
            continue
        L = c.base.L(i)
        N = bytearray(0x1000)
        N[:0x30] = L[:0x30]
        p16(N, 4, 0x30)
        p16(N, 6, 9)
        N[0x30:0x32] = L[0x30:0x32]
        p32(N, 0x1C, 0x1000)
        N = rebuild(N, attrs_of(L), 0x48)
        out.append(bytes(unfix(N)))
    return ("synth-01 records re-laid as 4096-byte FILE records (usa_count 9, first attr 0x48): the original reads "
            "1024-byte chunks, so record k is chunk 4k (wrong record numbers, root key broken)", Mft(b"".join(out)),
            {"record_size": 4096, "records": c.base.n})


@case("ntfs30-layout", 6, False)
def c_ntfs30(c):
    m = c.base.copy()
    for i in range(38, 45):
        L = m.L(i)
        at = attrs_of(L)
        N = bytearray(REC)
        N[:0x2A] = L[:0x2A]
        p16(N, 4, 0x2A)
        N[0x2A:0x2C] = L[0x30:0x32]
        m.put(i, rebuild(N, at, 0x30))
    return ("NTFS 3.0 FILE layout (usa_ofs 0x2a, first attribute 0x30) on the act..フォルダ directories: accepted by "
            "the +4 in {0x30, 0x2a} test, fixups through the 0x2a array", m, {"records": "38..44"})


# ----------------------------------------------------------------------------------------------- real volumes
def vhd_cases(c):
    out = []
    a = VHD / "vol-a"
    if (a / "$MFT").exists():
        out.append(("foreign-real", -9, False, c.logfile, (a / "$MFT").read_bytes(),
                    "real $MFT of a different scratch NTFS volume (fuzz/vhd-mft/vol-a) with the synth-01 $LogFile: "
                    "unrelated dir map, accidental LSN hits",
                    "synth-01 $LogFile + fuzz/vhd-mft/vol-a/$MFT", {"mft_source": "fuzz/vhd-mft/vol-a/$MFT"}))
        if (a / "$LogFile").exists():
            out.append(("vol-a-own-log", 9, True, (a / "$LogFile").read_bytes(), (a / "$MFT").read_bytes(),
                        "second real same-volume pair (fresh 48 MB NTFS, 1 KiB records, distinct tree with quotes/"
                        "commas/non-ASCII dirs, deep path, renames, deletions): V40 and paths on unseen real data",
                        "fuzz/vhd-mft/vol-a ($LogFile + $MFT, same volume)", {"source": "fuzz/vhd-mft/vol-a"}))
    l4 = VHD / "vol-l"
    if (l4 / "$MFT").exists():
        out.append(("frs4k-real", 14, True, c.logfile, (l4 / "$MFT").read_bytes(),
                    "real $MFT of a large-FRS (4096-byte record) scratch volume with the synth-01 $LogFile: 1024-byte "
                    "stride over 4 KiB records", "synth-01 $LogFile + fuzz/vhd-mft/vol-l/$MFT",
                    {"mft_source": "fuzz/vhd-mft/vol-l/$MFT"}))
        if (l4 / "$LogFile").exists():
            out.append(("frs4k-own-log", -3, False, (l4 / "$LogFile").read_bytes(), (l4 / "$MFT").read_bytes(),
                        "large-FRS volume's own $LogFile + $MFT: 4 KiB FILE records in the redo data and in the "
                        "$MFT, consistent LSNs", "fuzz/vhd-mft/vol-l ($LogFile + $MFT, same volume)",
                        {"source": "fuzz/vhd-mft/vol-l"}))
    return out


# ----------------------------------------------------------------------------------------------- output
def write_file(p, data):
    if not p.exists() or p.stat().st_size != len(data) or p.read_bytes() != data:
        p.write_bytes(data)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "fuzz" / "cases"))
    ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    c = Ctx(a.seed)
    items = []
    for slug, utc, dst, f in CASES:
        desc, m, mut = f(c)
        items.append((slug, utc, dst, c.logfile, m.data(), desc, BASE_DESC, mut))
    items += vhd_cases(c)
    out = Path(a.out)
    for n, (slug, utc, dst, log, mft, desc, base, mut) in enumerate(items):
        cid = "%s-%03d-%s" % (FAMILY, n, slug)
        if a.list or a.only not in cid:
            print(cid, utc, dst, len(mft))
            continue
        d = out / cid
        d.mkdir(parents=True, exist_ok=True)
        write_file(d / "$LogFile", log)
        write_file(d / "$MFT", mft)
        if base == BASE_DESC:
            mut = dict(mut, base_fix=c.neutral_note)
        cj = {"utc": utc, "dst": dst, "mft": True, "family": FAMILY, "desc": desc, "base": base,
              "mutation": dict(mut, seed=a.seed)}
        write_file(d / "case.json", json.dumps(cj, ensure_ascii=False, indent=1).encode("utf-8"))
        print(cid, "written")


if __name__ == "__main__":
    main()
