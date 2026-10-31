"""Family "sem": semantic edge-value cases for every ProcessLogRecord (0x412710) branch, built from synth-01.

  python -I re/fuzz/gen_sem.py [--seed 1] [--out fuzz/cases] [--only sem-012]

Every case is a full copy of samples/synth-01/$LogFile (optionally with samples/synth-01/$MFT) in which a few real
log records are patched IN PLACE: opcodes, header words (record_offset, attribute_offset, target_vcn, redo_length)
and redo/undo payload bytes. Record sizes (client_data_length), LSNs and page structure are never changed, so the
traversal of section 02 is identical to the base file. Every copy of a patched record (LFS 2.0 tail copies in the
first 0x20 RCRD pages) is patched identically, and bytes that fall on a sector end (page offset 0x1fe/0x3fe/...)
are written into the page's update-sequence array, which the original copies blindly over the sector ends.
"Big" records (8,0 / 11,11 neighbours) are re-typed when a payload needs more room than the real record of that
kind has (255-unit names, long run lists, crafted FILE images).

Targeted behaviours (section numbers refer to re/spec):
  File names (A File Creation, C Delete Index Entry, G Delete Attribute, H Create Attribute, B via txn):
    - single quotes: '' doubling at INSERT, in-place mutation of cur that leaks a second doubling into rows copied
      later (E1/F name inheritance, H old name, E2 tunneling Detail)            [03 5.1, 06 5.2]
    - commas -> '/' at INSERT (idempotent), runs of commas at start/end         [06 2.1]
    - names of length 1 and 255 (255 needs a re-typed big record)               [04 E17]
    - NUL code units inside names: "%s" truncation before IsDos83ShortName / "~" wcsstr / FileName
    - lone surrogates (0xD800..0xDFFF): SQLite 3.7.3 UTF-16 reader swallows the next unit, incl. the closing quote
      of the literal -> INSERT syntax error, row silently dropped              [06 5.11]
    - characters with no cp1252 mapping (best-fit and '?'), U+FFFE/U+FFFF -> U+FFFD, C1 controls, '"', CR, LF, TAB
      written raw into the CSV                                                    [06 5.8, 5.9]
    - $FILE_NAME namespace 0/1/2/3 (ignored on the $LogFile path; namespace 2 skipped only in ParseMFT)
    - DOS 8.3 pattern (IsDos83ShortName, glossary 3.6) true/false look-alikes in A and C; "~" anywhere in G/H
    - names differing only by case (H rename detail; "$Mft" vs "$MFT" in ParseMFT record 0)
  Times:
    - FILETIME 0 and 1, 1601-01-01 boundaries where a negative shift underflows (AdjustTimeString keeps the input)
    - 0x7FFFFFFFFFFFFFFF (5-digit year -> AdjustTimeString misparse), >= 0x8000000000000000 (FileTimeToSystemTime
      fails, stale SYSTEMTIME slot), 9999-12-31 -> 10000 roll-over under +14, 5-digit unshifted years in D ("20"
      prefix test), Feb-29 / 1900 / 2100 leap edges, end-of-year roll-overs under +14 DST and -12 DST
    - Abnormal Timestamp in C/B: "20"-prefix rule on SHIFTED strings without $MFT, ordinal compare with the $MFT
      create string (unshifted, second resolution) with $MFT                   [03 2.12]
    - E2 tunneling / EventTime updates with edge times, TargetVCN high dword ignored by the key
  Mapping pairs (F Update Mapping Pairs, A $DATA): header 0 terminator, offset size 0 (sparse) ends decoding,
    8-byte lengths/offsets, negative deltas and negative LCNs printed as u64, 64-bit wrap, length nibble 9..12
    (spill), >= 13 (saved Parser* clobbered: crash candidate), offset nibble >= 9 (F keeps delta, A uses 0),
    F length high-byte carry-over, run ending at/after redo_length dropped, hundreds of runs (long Detail),
    A $DATA with attribute length < mapping-pairs offset (memcpy underflow: crash candidate)
  Resident writes (E1): redo_length 0 / 0xFFFF, record_offset 0xFFFF / 0xF8 / 0xF7, attribute_offset 0x19,
    target_vcn high dword (TargetVCN prints the low dword only, lookbacks compare the string)
  Parent references: root test lo==5 && (hi & 0xffff)==0 (any sequence), 48-bit record numbers, self reference
    (with $MFT: A parent = own record number resolving to a FILE DirEntry; $MFT key == parentRef -> no DirEntry),
    sequence-only differences (full-u64 dir-map miss, H rename vs move), C/D location key (u32)(n>>2) truncation
    and the 16-bit sequence mask                                                 [03 2.19, 04 2.4-2.5]
  Index entries: name length 0, name length 0xFF reading past the entry into the zeroed buffer, odd entry/key
    lengths (unused by the original), exact-equality flag names ("Directory")
  FILE walk (A): stale attribute length after an unknown type, $INDEX_ROOT with an empty or '$' FileName,
    $SI after $FN (EventTime ""), two non-DOS $FN (last wins)
  $MFT (mft=true): p+0x1a8 abnormal compare, "$MFT" case-sensitive capture, namespace-2-only record leaking its
    sequence bits into the next key, directory flag word 7, parent cycle (hang/crash candidate), V40 SI times
    >= 2^63 (stale V40 SYSTEMTIME slot), quote/comma in V40 names and BuildFullPath components.

Cases are deterministic for a given --seed (the seed only changes filler characters / run deltas).
"""
import argparse
import datetime as dt
import json
import random
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE_DIR = ROOT / "samples" / "synth-01"
PAGE = 0x1000
FAMILY = "sem"


# ------------------------------------------------------------------------------------------------ packing helpers
def p16(v):
    return struct.pack("<H", v & 0xFFFF)


def p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def p64(v):
    return struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF)


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def align8(n):
    return (n + 7) & ~7


def U(s):
    """Python str (lone surrogates allowed) -> list of UTF-16 code units."""
    b = s.encode("utf-16-le", "surrogatepass")
    return list(struct.unpack("<%dH" % (len(b) // 2), b))


def units_bytes(units):
    return b"".join(p16(u) for u in units)


EPOCH = dt.datetime(1601, 1, 1)
TICKS_S = 10_000_000
TICKS_H = 3600 * TICKS_S


def FT(y, mo, d, h=0, mi=0, s=0, ticks=0):
    """FILETIME (100 ns ticks since 1601-01-01) of a proleptic Gregorian date; years > 9999 handled manually."""
    if y <= 9999:
        delta = dt.datetime(y, mo, d, h, mi, s) - EPOCH
        return (delta.days * 86400 + delta.seconds) * TICKS_S + ticks
    days = (dt.date(9999, 12, 31) - EPOCH.date()).days + 1      # days up to 10000-01-01
    for yy in range(10000, y):
        days += 366 if (yy % 4 == 0 and (yy % 100 != 0 or yy % 400 == 0)) else 365
    days += (dt.date(2000 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 2001, mo, d)
             - dt.date(2000 if (y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)) else 2001, 1, 1)).days
    return ((days * 86400 + h * 3600 + mi * 60 + s) * TICKS_S) + ticks


# ------------------------------------------------------------------------------------------------ $LogFile model
class Log:
    """Logical (fixed-up) view of an LFS 2.0 $LogFile with in-place record patching."""

    def __init__(self, data):
        self.b = bytearray(data)
        ra = u16(self.b, 0x18)
        seq_bits = u32(self.b, ra + 0x10)
        self.mask = (1 << (64 - seq_bits)) - 1
        self.rcrd = [o for o in range(0, len(self.b) - PAGE + 1, PAGE) if self.b[o:o + 8] == b"RCRD\x28\x00\x09\x00"]
        self.muts = []
        self._index()

    @staticmethod
    def phys(page_off, o):
        # The original copies the 8 USA words at +0x2a..+0x38 over the sector ends 0x1fe, 0x3fe, ... 0xffe.
        if (o & 0x1FF) >= 0x1FE:
            return page_off + 0x2A + 2 * (o >> 9) + (o & 1)
        return page_off + o

    def rd(self, page_off, o, n):
        return bytes(self.b[self.phys(page_off, o + i)] for i in range(n))

    def wr(self, page_off, o, data):
        for i, x in enumerate(data):
            self.b[self.phys(page_off, o + i)] = x

    def _index(self):
        self.recs, self.copies = {}, {}
        pages = {o: self.rd(o, 0, PAGE) for o in self.rcrd}
        for off, p in pages.items():
            for pos in range(0x40, PAGE - 0x30 + 1, 8):
                lsn, _prev, _un, cdl, _cid, rtype = struct.unpack_from("<QQQIII", p, pos)
                if lsn == 0 or (lsn & self.mask) * 8 != off + pos or rtype not in (1, 2) or cdl > 0x100000:
                    continue
                self.recs[lsn] = {"page": off, "pos": pos, "cdl": cdl, "hdr": p[pos:pos + 0x30]}
        for off, p in pages.items():          # identical copies (LFS 2.0 tail pages, duplicated buffer pages)
            for pos in range(0x40, PAGE - 0x30 + 1, 8):
                r = self.recs.get(u64(p, pos))
                if r and p[pos:pos + 0x30] == r["hdr"]:
                    self.copies.setdefault(u64(p, pos), []).append((off, pos))

    def rec(self, lsn):
        r = self.recs[lsn]
        off, pos = self.copies[lsn][0]
        assert all(ps + 0x30 + r["cdl"] <= PAGE for _, ps in self.copies[lsn]), f"record {lsn} spans pages"
        return self.rd(off, pos, 0x30 + r["cdl"])

    def hdr(self, lsn):
        b = self.rec(lsn)
        k = struct.unpack_from("<HHHHHHHHHHH", b, 0x30)
        return dict(zip(("redo", "undo", "redo_off", "redo_len", "undo_off", "undo_len", "tattr", "lcns", "rec_off",
                         "attr_off", "cbo"), k), tvcn=u64(b, 0x48), prev=u64(b, 8), cdl=self.recs[lsn]["cdl"])

    def patch(self, lsn, rel, data, what):
        r = self.recs[lsn]
        data = bytes(data)
        assert rel >= 0 and rel + len(data) <= 0x30 + r["cdl"], (lsn, hex(rel), len(data))
        old = self.rec(lsn)[rel:rel + len(data)]
        if old == data:
            return
        lo = next(i for i in range(len(data)) if old[i] != data[i])           # record only the changed span
        hi = next(i for i in range(len(data) - 1, -1, -1) if old[i] != data[i]) + 1
        rel, old, data = rel + lo, old[lo:hi], data[lo:hi]
        offs = []
        for off, pos in self.copies[lsn]:
            assert pos + rel + len(data) <= PAGE
            self.wr(off, pos + rel, data)
            offs.append(off + pos + rel)
        self.muts.append({"lsn": lsn, "what": what, "rec_rel": hex(rel), "file_offsets": [hex(o) for o in offs],
                          "old": old.hex(), "new": data.hex()})

    # client-data views -------------------------------------------------------------------------------------
    def buf_rel(self, lsn):
        return 0x30 + self.hdr(lsn)["redo_off"]

    def buf(self, lsn):
        """What 0x412710 receives: client data from redo_offset to the end of the record."""
        return bytearray(self.rec(lsn)[self.buf_rel(lsn):])

    def put(self, lsn, k, data, what):
        self.patch(lsn, self.buf_rel(lsn) + k, data, what)

    def set_ops(self, lsn, redo, undo, what="opcodes"):
        self.patch(lsn, 0x30, p16(redo) + p16(undo), what)

    def set_hdr16(self, lsn, field, v):
        rel = {"redo_len": 0x36, "rec_off": 0x40, "attr_off": 0x42, "cbo": 0x44}[field]
        self.patch(lsn, rel, p16(v), field)

    def set_tvcn(self, lsn, v):
        self.patch(lsn, 0x48, p64(v), "target_vcn")

    def prev_in_page(self, lsn):
        """The record processed right before lsn (same page, header ends where lsn starts)."""
        off, pos = self.copies[lsn][0]
        for l2, r in self.recs.items():
            for o2, p2 in self.copies[l2]:
                if o2 == off and p2 + 0x30 + r["cdl"] == pos:
                    return l2
        raise AssertionError(f"no in-page predecessor for {lsn}")


# ------------------------------------------------------------------------------------------------ FILE images (A)
def file_attrs(buf):
    """Real NTFS attribute list of a FILE image (from 0x38, by real lengths)."""
    out, off = [], 0x38
    while u32(buf, off) != 0xFFFFFFFF:
        n = u32(buf, off + 4)
        out.append(bytearray(buf[off:off + n]))
        off += n
    return out


def write_file_image(L, lsn, attrs, what, header=None):
    buf = L.buf(lsn)
    img = bytearray(header if header is not None else buf[:0x38]) + b"".join(attrs) + b"\xff\xff\xff\xff"
    assert len(img) <= len(buf), (lsn, hex(len(img)), hex(len(buf)))
    img += bytes(len(buf) - len(img))
    L.put(lsn, 0, img, what)


def fn_attr(base, units, ns=None, parent=None, nbyte=None, flags=None):
    """Resident $FILE_NAME attribute = base with a new name (name at attr+0x5a, length byte at attr+0x58)."""
    a = bytearray(base)
    assert u16(a, 0x14) == 0x18
    val = bytearray(a[0x18:0x18 + 0x42])
    if parent is not None:
        val[0:8] = p64(parent)
    if flags is not None:
        val[0x38:0x3c] = p32(flags)
    val[0x40] = (len(units) if nbyte is None else nbyte) & 0xFF
    if ns is not None:
        val[0x41] = ns
    val += units_bytes(units)
    n = align8(0x18 + len(val))
    out = a[:0x18] + val + bytes(n - 0x18 - len(val))
    out[4:8] = p32(n)
    out[0x10:0x14] = p32(len(val))
    return out


def si_attr(base, c=None, m=None, mm=None, a=None, flags=None):
    s = bytearray(base)
    for k, v in ((0x18, c), (0x20, m), (0x28, mm), (0x30, a)):
        if v is not None:
            s[k:k + 8] = p64(v)
    if flags is not None:
        s[0x38:0x3c] = p32(flags)
    return s


def a_set_name(L, lsn, units, ns=None, parent=None):
    """Replace the $FN of an A record's FILE image. If the longer name no longer fits, the trailing RESIDENT $DATA is
    dropped: branch A ends its walk at a resident $DATA anyway, so that is output-neutral."""
    buf = L.buf(lsn)
    attrs = file_attrs(buf)
    i = next(k for k, a in enumerate(attrs) if u32(a, 0) == 0x30)
    attrs[i] = fn_attr(attrs[i], units, ns=ns, parent=parent)
    what = "A $FILE_NAME"
    if 0x38 + sum(map(len, attrs)) + 4 > len(buf):
        attrs = [a for a in attrs if not (u32(a, 0) == 0x80 and a[8] == 0)]
        what += " (resident $DATA dropped to make room)"
    write_file_image(L, lsn, attrs, what)


def a_set_si(L, lsn, **kw):
    attrs = file_attrs(L.buf(lsn))
    i = next(k for k, a in enumerate(attrs) if u32(a, 0) == 0x10)
    attrs[i] = si_attr(attrs[i], **kw)
    write_file_image(L, lsn, attrs, "A $STANDARD_INFORMATION")


def nonres_data(runs, length=None, mp=0x40):
    """Non-resident unnamed $DATA attribute with the given mapping-pairs bytes."""
    n = align8(mp + len(runs)) if length is None else length
    a = bytearray(max(n, mp + len(runs), 0x48))
    a[0:4] = p32(0x80)
    a[4:8] = p32(n)
    a[8] = 1
    a[0x20:0x22] = p16(mp)
    a[mp:mp + len(runs)] = runs
    return a[:max(n, mp + len(runs))]


def craft_A(L, big, attrs, what):
    """Turn a big record into Initialize File Record Segment (2,0) and make its predecessor an 'Add Index Entry
    Allocation' (redo 0xe, undo unchanged -> no branch of its own), so branch A's precondition holds."""
    prev = L.prev_in_page(big)
    L.patch(prev, 0x30, p16(0x0E), "predecessor redo_op -> 0x0e (RedoInfo 'Add Index Entry Allocation')")
    L.set_ops(big, 2, 0, "redo/undo -> (2,0) Initialize File Record Segment / Noop")
    write_file_image(L, big, attrs, what, header=TEMPLATE["file_hdr"])
    return prev


def craft_F(L, big, runs, redo_len=None, rec_off=0x100):
    L.set_ops(big, 9, 9, "redo/undo -> (9,9) Update Mapping Pairs")
    L.set_hdr16(big, "rec_off", rec_off)
    L.set_hdr16(big, "attr_off", 0x40)
    buf = L.buf(big)
    assert len(runs) <= len(buf)
    L.put(big, 0, bytes(runs) + bytes(len(buf) - len(runs)), "mapping pairs")
    if redo_len is not None:
        L.set_hdr16(big, "redo_len", redo_len)


# ------------------------------------------------------------------------------------------------ $MFT model
class Mft:
    def __init__(self, data):
        self.b = bytearray(data)
        self.muts = []

    def phys(self, rec, o):
        base = rec * 1024
        if (o & 0x1FF) >= 0x1FE:
            usa = u16(self.b, base + 4)
            s = o >> 9
            if self.b[base + s * 0x200 + 0x1FE:base + s * 0x200 + 0x200] == self.b[base + usa:base + usa + 2]:
                return base + usa + 2 * (s + 1) + (o & 1)
        return base + o

    def rd(self, rec, o, n):
        return bytes(self.b[self.phys(rec, o + i)] for i in range(n))

    def wr(self, rec, o, data, what):
        old = self.rd(rec, o, len(data))
        for i, x in enumerate(data):
            self.b[self.phys(rec, o + i)] = x
        self.muts.append({"mft_record": rec, "what": what, "rec_off": hex(o), "old": old.hex(), "new": bytes(data).hex()})

    def attrs(self, rec):
        r = self.rd(rec, 0, 1024)
        off = u16(r, 0x14)
        while off + 8 <= 1024 and u32(r, off) != 0xFFFFFFFF and u32(r, off + 4):
            t, n = u32(r, off), u32(r, off + 4)
            v = off + (u16(r, off + 0x14) if r[off + 8] == 0 else u16(r, off + 0x20))
            yield off, t, n, v
            off += n

    def fn(self, rec):
        return [v for _, t, _, v in self.attrs(rec) if t == 0x30]

    def si(self, rec):
        return next(v for _, t, _, v in self.attrs(rec) if t == 0x10)

    def name(self, rec):
        v = self.fn(rec)[-1]
        n = self.rd(rec, v + 0x40, 1)[0]
        return self.rd(rec, v + 0x42, 2 * n).decode("utf-16-le", "surrogatepass")


# ------------------------------------------------------------------------------------------------ base targets
# Record LSNs in samples/synth-01/$LogFile (asserted in check_base()).
A_IT, D_IT, E1_IT, E2SITE_IT = 1076983, 1076958, 1077043, 1077076   # "it's here.txt" (parent 0x31, TargetVCN 0xC/6)
A_ABC, D_ABC, E1_ABC = 1077188, 1077164, 1077256                     # "a,b,c.csv"
A_WS, F_WS = 1077405, 1077542                                        # "with space and, comma's.log" + its runs
A_NINO, A_LONG = 1077934, 1079484                                    # "niño año.doc", "LONGFILENAME_FOR_83.TXT"
F_CAFE = 1077808                                                     # runs of "café.txt"
C_IT, B_IT, E2_B = 1105049, 1105074, 1105111                         # deletion of "it's here.txt" + EventTime E2
G_IT, H_IT = 1105200, 1105227                                        # rename it's here.txt.tmp -> it's here.txt
E1_TMP = 1104980                                                     # resident write of "it's here.txt.tmp"
A_ACT = 1074453                                                      # Directory Creation "act"
C_DIR_E = 1109616                                                    # Delete Index Entry Root of directory "e"
BIG1, BIG2, BIG3 = 1114253, 1139280, 1080487                         # (8,0) records with 0x7e8/0x7c0/0x300 redo bytes

TEMPLATE = {}


def check_base(L):
    exp = {A_IT: (2, 0), D_IT: (0xC, 0xD), E1_IT: (7, 7), E2SITE_IT: (0x13, 0x13), A_ABC: (2, 0), D_ABC: (0xC, 0xD),
           E1_ABC: (7, 7), A_WS: (2, 0), F_WS: (9, 9), A_NINO: (2, 0), A_LONG: (2, 0), F_CAFE: (9, 9),
           C_IT: (0xF, 0xE), B_IT: (3, 2), E2_B: (7, 7), G_IT: (6, 5), H_IT: (5, 6), E1_TMP: (7, 7), A_ACT: (2, 0),
           C_DIR_E: (0xD, 0xC), BIG1: (8, 0), BIG2: (8, 0), BIG3: (8, 0)}
    for lsn, ops in exp.items():
        h = L.hdr(lsn)
        assert (h["redo"], h["undo"]) == ops, (lsn, h)
    assert L.hdr(E2SITE_IT)["tvcn"] == 0xC and L.hdr(E2SITE_IT)["cbo"] == 2
    assert L.hdr(E2_B)["rec_off"] == 0x38 and L.hdr(E2_B)["attr_off"] == 0x20
    assert units_bytes(U("it's here.txt")) in L.buf(A_IT)
    for big in (BIG1, BIG2, BIG3):
        assert L.hdr(L.prev_in_page(big))["redo"] == 0xB
    attrs = file_attrs(L.buf(A_IT))
    TEMPLATE.update(file_hdr=bytes(L.buf(A_IT)[:0x38]), si=attrs[0], fn=attrs[1], data_res=attrs[2])


# ------------------------------------------------------------------------------------------------ cases
CASES = []


def case(slug, utc, dst, desc, mft=False):
    def deco(fn):
        CASES.append({"slug": slug, "utc": utc, "dst": dst, "desc": desc, "mft": mft, "fn": fn})
        return fn
    return deco


def c_set_times(L, lsn, c=None, m=None, mm=None, a=None):
    for k, v in ((0x18, c), (0x20, m), (0x28, mm), (0x30, a)):
        if v is not None:
            L.put(lsn, k, p64(v), f"index entry time +{k:#x}")


def ie_set_name(L, lsn, units, ns=None, nbyte=None):
    buf = L.buf(lsn)
    assert 0x52 + 2 * len(units) <= len(buf), (lsn, len(units))
    L.put(lsn, 0x50, bytes([(len(units) if nbyte is None else nbyte) & 0xFF]), "index entry name length")
    if ns is not None:
        L.put(lsn, 0x51, bytes([ns]), "index entry namespace")
    L.put(lsn, 0x52, units_bytes(units), "index entry name")


def at_set_name(L, lsn, units, ns=None):
    """G/H: buf is a $FILE_NAME attribute; name length +0x58, namespace +0x59, units +0x5a."""
    buf = L.buf(lsn)
    assert 0x5A + 2 * len(units) <= len(buf), (lsn, len(units), len(buf))
    L.put(lsn, 0x58, bytes([len(units) & 0xFF]), "attribute $FN name length")
    if ns is not None:
        L.put(lsn, 0x59, bytes([ns]), "attribute $FN namespace")
    L.put(lsn, 0x5A, units_bytes(units), "attribute $FN name")


def e2_site(L, t, tvcn=0xC):
    """Re-type the (0x13,0x13) record right after "it's here.txt"'s File Creation (same TargetVCN 0xC / cluster 2 =
    location of its parent directory 0x31) into an E2 Update Resident Value on the $SI at record_offset 0x38 /
    attribute_offset 0x20 carrying time t at buf+8."""
    L.set_ops(E2SITE_IT, 7, 7, "redo/undo -> (7,7) Update Resident Value")
    L.set_hdr16(E2SITE_IT, "rec_off", 0x38)
    L.set_hdr16(E2SITE_IT, "attr_off", 0x20)
    if tvcn != 0xC:
        L.set_tvcn(E2SITE_IT, tvcn)
    L.put(E2SITE_IT, 8, p64(t), "E2 time (buf+8)")


IT_CREATE = 0x01DD687FE996E694       # $SI / index times of "it's here.txt" in synth-01

# ---- file names -------------------------------------------------------------------------------------------------


@case("a-quote-runs", -3, False, "A FileName with leading/trailing quotes and runs of 2 and 3: '' doubling at INSERT "
      "and a second doubling when E1 (LSN 1077043) inherits the already-mutated name from rows")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("'q''uote'''.txt"))


@case("name-len1", 0, False, "File names of length 1 that are a lone quote (A it's here.txt) and a lone comma "
      "(A a,b,c.csv): escaping of single-unit names, E1 inheritance of \"''\" and \"/\"")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("'"))
    a_set_name(L, A_ABC, U(","))


@case("a-comma-runs", -12, False, "A FileName ',,a,,b,,.,,' : every comma -> '/' at INSERT (also in E1 copy and "
      "CSV), commas at both ends")
def _(L, M, rnd):
    a_set_name(L, A_ABC, U(",,a,,b,,.,,"))


@case("a-name-255", 14, True, "File Creation with a 255-unit name (crafted FILE image in a re-typed big record, "
      "parent root): maximum $FN length byte, 0x200-byte name buffer filled exactly, 256-unit FullPath")
def _(L, M, rnd):
    body = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789 -_") for _ in range(249))
    name = "'" + body[:120] + "," + body[120:] + ".tx'"
    assert len(name) == 255
    craft_A(L, BIG1, [TEMPLATE["si"], fn_attr(TEMPLATE["fn"], U(name), parent=0x0005000000000005),
                      TEMPLATE["data_res"]], "crafted FILE image, 255-unit $FN")


@case("a-name-nul-mid", -3, False, "A $FN name 'abc\\0def.txt' (11 units): FileName is Format(\"%s\") -> 'abc'; E1 "
      "inherits 'abc'")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("abc\0def.txt"))


@case("a-name-nul-hides-dos", 0, False, "A $FN name 'ABCDEF~1\\0TXT': IsDos83ShortName sees the NUL-truncated "
      "'ABCDEF~1' (DOS pattern) so the $FN is skipped and no File Creation row is emitted")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("ABCDEF~1\0TXT"))


@case("h-name-nul-hides-tilde", 9, False, "H (Create Attribute) name \"it's\\0~here.txt\": the '~' filter "
      "(wcsstr) only sees \"it's\", so the rename row is produced with FileName \"it's\"")
def _(L, M, rnd):
    at_set_name(L, H_IT, U("it's\0~here.txt"))


@case("a-lone-high-surrogate-mid", -3, False, "A FileName 'ab\\uD800cd.txt': SQLite 3.7.3 UTF-16 reader pairs "
      "the lone high surrogate with 'c' (stored U+10063-like pair, CSV '??'); same in the E1 copy")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("ab\ud800cd.txt"))


@case("a-lone-low-surrogate-end", 0, False, "A FileName ending in a lone low surrogate: the surrogate swallows "
      "the closing quote of the SQL literal -> INSERT syntax error, row silently dropped (rows[] still keeps it, "
      "E1 inherits it and is dropped too)")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("abc.txt\udc00"))


@case("a-surrogate-before-quote", 14, False, "A FileName 'x\\uD83D\\'y.txt': after '' doubling the lone high "
      "surrogate swallows the first quote and the second one closes the literal early -> INSERT fails")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("x\ud83d'y.txt"))


@case("a-unmappable-ansi", -12, True, "A FileName with best-fit / unmappable cp1252 characters (U+0100, U+0141, "
      "U+FF21, U+2019, U+20AC, combining U+0301, CJK, U+FFFE/U+FFFF -> U+FFFD, C1 controls, NBSP) plus a quote; "
      "F (LSN 1077542) inherits it double-escaped")
def _(L, M, rnd):
    name = "ĀŁＡ’€" + "é" + "中￾￿ '.t"
    a_set_name(L, A_WS, U(name))


@case("a-csv-breakers", 0, False, "A FileName with '\"', CR, LF and TAB: written raw inside the quoted CSV field "
      "(no escaping), splitting the CSV line")
def _(L, M, rnd):
    a_set_name(L, A_ABC, U('a"b\r\nc\td.txt'))


@case("namespace-ignored", -3, False, "$FILE_NAME namespace bytes changed (A ns=2 DOS on a long name, C ns=1, "
      "H ns=3): the $LogFile branches never read the namespace, only IsDos83ShortName / '~'")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("it's here.txt"), ns=2)
    ie_set_name(L, C_IT, U("it's here.txt"), ns=1)
    at_set_name(L, H_IT, U("it's here.txt"), ns=3)


@case("a-dos83-true", -3, False, "IsDos83ShortName true variants in A: '~1', 'x~1.', 'abcdef~9.txt' (lowercase), "
      "'~1.txt' -> each $FN skipped, no File Creation, inheriting E1/F rows get FileName ''")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("~1"))
    a_set_name(L, A_ABC, U("x~1."))
    a_set_name(L, A_WS, U("abcdef~9.txt"))
    a_set_name(L, A_NINO, U("~1.txt"))


@case("a-dos83-false", 0, False, "IsDos83ShortName false look-alikes in A: 'a~0.txt' (digit 0), 'AB~10.TXT', "
      "'a.b~1' (first dot at index 1), '~' (length 1), '~a.txt' -> all produce File Creation rows")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("a~0.txt"))
    a_set_name(L, A_ABC, U("AB~10.TXT"))
    a_set_name(L, A_WS, U("a.b~1"))
    a_set_name(L, A_NINO, U("~"))
    a_set_name(L, A_LONG, U("~a.txt"))


@case("c-dos83-name", 9, False, "C (Delete Index Entry) with DOS name 'ITSHER~1.TXT': Event/FileName blanked "
      "then Temp Event; B (LSN 1105074) skips it (FileName '') so no File Deletion row")
def _(L, M, rnd):
    ie_set_name(L, C_IT, U("ITSHER~1.TXT"))


@case("h-tilde-anywhere", -12, False, "H name \"it's~here.txt\" ('~' not in 8.3 position): H returns early, no "
      "rename row")
def _(L, M, rnd):
    at_set_name(L, H_IT, U("it's~here.txt"))


@case("g-tilde-anywhere", 0, False, "G name \"it's~here.txt.tmp\": G returns early (no Temp row), so the following "
      "H finds no 'Delete Attribute' row in its 9-row window -> Temp Event (deleted)")
def _(L, M, rnd):
    at_set_name(L, G_IT, U("it's~here.txt.tmp"))


@case("rename-case-only", 14, False, "Rename whose old (G) and new (H) names differ only by case: "
      "\"IT'S HERE.TXT\" -> \"it's here.txt\"; old part double-escaped from rows")
def _(L, M, rnd):
    at_set_name(L, G_IT, U("IT'S HERE.TXT"))


# ---- times ------------------------------------------------------------------------------------------------------
@case("a-ft-zero-neg", -3, False, "A $SI times all 0 under UTC-3: '1601-01-01 00:00:00' and the negative shift "
      "underflows, AdjustTimeString returns the input")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=0, m=0, mm=0, a=0)


@case("a-ft-zero-one-pos", 14, True, "A $SI times 0/1/0/1 under UTC+14 DST (15 h): '1601-01-01 15:00:00' "
      "(sub-second tick dropped before the shift)")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=0, m=1, mm=0, a=1)


@case("a-1601-boundary-m12", -12, False, "A $SI times around 1601-01-01 12:00:00 under UTC-12: 11:59:59.9999999 "
      "(underflow -> unchanged) vs 12:00:00 (-> 00:00:00) vs 12:00:00.5 vs 11:59:59")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=FT(1601, 1, 1, 11, 59, 59, 9_999_999), m=FT(1601, 1, 1, 12), mm=FT(1601, 1, 1, 12, 0, 0, 5_000_000),
             a=FT(1601, 1, 1, 11, 59, 59))


@case("a-1601-boundary-m11", -12, True, "A $SI times around 1601-01-01 11:00 under UTC-12 DST (-11 h): 10:59:59 "
      "(unchanged), 11:00:00 (-> 00:00:00), 14:59:59 and 00:00:00")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=FT(1601, 1, 1, 10, 59, 59), m=FT(1601, 1, 1, 11), mm=FT(1601, 1, 1, 14, 59, 59), a=0)


@case("a-ft-7fff", 0, False, "A $SI ModifiedTime 0x7FFFFFFFFFFFFFFF (30828-09-14): 5-digit year string misparsed by "
      "AdjustTimeString (SystemTimeToFileTime fails, uninitialised FILETIME) - nondeterminism candidate")
def _(L, M, rnd):
    a_set_si(L, A_IT, m=0x7FFFFFFFFFFFFFFF)


@case("a-ft-8000", 9, False, "A $SI AccessTime 0x8000000000000000: FileTimeToSystemTime fails, the stale A-branch "
      "slot [ebp-0x1448] (shared with C/D create and E2) is printed - stale-stack candidate")
def _(L, M, rnd):
    a_set_si(L, A_IT, a=0x8000000000000000)


@case("c-ft-ffff", -3, False, "C create time 0xFFFFFFFFFFFFFFFF: FileTimeToSystemTime fails, stale C slot "
      "[ebp-0x1448] flows into the B File Deletion row (times + Abnormal Detail) - stale-stack candidate")
def _(L, M, rnd):
    c_set_times(L, C_IT, c=0xFFFFFFFFFFFFFFFF)


@case("a-year-10000-rollover", 14, False, "A $SI times near 9999-12-31 under UTC+14: just below the 5-digit "
      "threshold (0x24C85A5ED1C03FFF) and 10:00:00 roll into year 10000 ('10000-01-01 ...', 5-digit output)")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=0x24C85A5ED1C03FFF, m=FT(9999, 12, 31, 10), mm=FT(9999, 12, 31, 9, 59, 59), a=FT(9999, 12, 31))


@case("a-leap-pos", 9, False, "A $SI times crossing Feb 28/29 under UTC+9: 1900 (not leap), 2000 (leap), 2100 "
      "(not leap), 2024-02-29 23:59:59 -> 2024-03-01")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=FT(1900, 2, 28, 23, 30), m=FT(2000, 2, 28, 20), mm=FT(2100, 2, 28, 15), a=FT(2024, 2, 29, 23, 59, 59))


@case("a-leap-neg", -12, True, "A $SI times crossing Mar 1 backwards under UTC-12 DST (-11 h): 1900, 2000, 2100, "
      "1601-03-01")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=FT(1900, 3, 1, 10), m=FT(2000, 3, 1, 5), mm=FT(2100, 3, 1, 10, 59, 59), a=FT(1601, 3, 1))


@case("a-year-rollover-p15", 14, True, "A $SI end-of-year times under UTC+14 DST (+15 h): 2025-12-31 09:00 -> "
      "2026-01-01 00:00, 1999-12-31 08:59:59 / 09:00:00, 2099-12-31 12:00 -> 2100")
def _(L, M, rnd):
    a_set_si(L, A_IT, c=FT(2025, 12, 31, 9), m=FT(1999, 12, 31, 8, 59, 59), mm=FT(1999, 12, 31, 9), a=FT(2099, 12, 31, 12))


@case("d-5digit-years", -3, False, "D (Add Index Entry, unshifted times, '20'-prefix test): year 20000 passes the "
      "test (5-digit Temp Event times), a 30827-12-31 23:59:59 time fails it (times blanked, no keys, no Temp row)")
def _(L, M, rnd):
    y20k = FT(20000, 1, 1)
    c_set_times(L, D_IT, c=y20k, m=y20k + TICKS_S, mm=y20k + 2 * TICKS_S, a=y20k + 3 * TICKS_S)
    c_set_times(L, D_ABC, mm=FT(30827, 12, 31, 23, 59, 59, 9_999_999))


@case("c-abnormal-20rule-m12", -12, False, "C create 2000-01-01 05:00:00 under UTC-12: shifted string is "
      "1999-12-31 (no '20' prefix) -> Abnormal; B Detail 'Abnormal Timestamp (2000-01-01 05:00:00)' (UNSHIFTED)")
def _(L, M, rnd):
    c_set_times(L, C_IT, c=FT(2000, 1, 1, 5))


@case("c-abnormal-1601", 14, True, "C times all 0 under UTC+14 DST: B row times '1601-01-01 15:00:00', Abnormal "
      "Detail with the unshifted '1601-01-01 00:00:00'")
def _(L, M, rnd):
    c_set_times(L, C_IT, c=0, m=0, mm=0, a=0)


# ---- E2 ---------------------------------------------------------------------------------------------------------
@case("e2-tunneling", -3, False, "E2 on the parent directory's $SI right after File Creation with a time 1 day "
      "later than CreateTime: UPDATE to 'File Creation(File System Tunneling)' with EventTime t, Detail re-stored")
def _(L, M, rnd):
    e2_site(L, IT_CREATE + 86400 * TICKS_S)


@case("e2-tvcn-highdword", 0, False, "Same E2 tunneling site but target_vcn = 0x1_0000000C: TargetVCN prints the "
      "low dword ('0xC'), so the parent-location key still matches")
def _(L, M, rnd):
    e2_site(L, IT_CREATE + 3600 * TICKS_S, tvcn=0x1_0000000C)


@case("e2-time-zero-neg", -12, False, "E2 tunneling with time 0 under UTC-12: t = '1601-01-01 00:00:00' "
      "(underflow keeps input), EventTime updated to it")
def _(L, M, rnd):
    e2_site(L, 0)


@case("e2-time-8000", 9, False, "E2 tunneling with time 0x8000000000000000: FileTimeToSystemTime fails, stale "
      "E2 slot [ebp-0x1448] becomes the tunneling EventTime - stale-stack candidate")
def _(L, M, rnd):
    e2_site(L, 0x8000000000000000)


@case("e2-deletion-year-10000", 14, False, "E2 that updates the File Deletion row (LSN 1105074) with a time of "
      "9999-12-31 23:00 under UTC+14 -> EventTime '10000-01-01 13:00:00'")
def _(L, M, rnd):
    L.put(E2_B, 8, p64(FT(9999, 12, 31, 23)), "E2 time (buf+8)")


# ---- mapping pairs ----------------------------------------------------------------------------------------------
@case("f-no-runs", 0, False, "F with header byte 0 (terminator) and F whose first run has offset size 0 (sparse): "
      "no '(' -> Event '' and no row")
def _(L, M, rnd):
    L.put(F_WS, 0, bytes(8), "mapping pairs (terminator)")
    L.put(F_CAFE, 0, bytes.fromhex("0105000000000000"), "mapping pairs (sparse first run)")


@case("f-sparse-after", 9, False, "F run list '11 02 10 | 01 05': the sparse run ends decoding, only '16(2)' is "
      "printed")
def _(L, M, rnd):
    L.put(F_WS, 0, bytes.fromhex("1102100105000000"), "mapping pairs")


@case("f-negative-lcn", -12, False, "F with redo_length 16 (undo bytes become part of the runs): first delta -128 "
      "-> LCN printed as u64 18446744073709551488, then -4096, +127; comma-joined runs stored with '/'")
def _(L, M, rnd):
    L.put(F_WS, 0, bytes.fromhex("1101802102 00f0 11037f 000000000000".replace(" ", "")), "mapping pairs")
    L.set_hdr16(F_WS, "redo_len", 16)


@case("f-run-past-redo-len", 14, False, "F: first run ends at k=5 (< redo_length 8) and is printed, second run "
      "ends at k=9 >= redo_length and is dropped")
def _(L, M, rnd):
    L.put(F_WS, 0, bytes.fromhex("31029b0500210101"), "mapping pairs")


@case("f-8byte-wrap", 0, False, "F (re-typed big record) with 8-byte length and offset fields: lengths "
      "0xFFFFFFFFFFFFFFFF, LCN sums that wrap past 2^64, raw u64 deltas")
def _(L, M, rnd):
    runs = (b"\x88" + p64(0xFFFFFFFFFFFFFFFF) + p64(0x7FFFFFFFFFFFFFFF) +
            b"\x88" + p64(1) + p64(0x7FFFFFFFFFFFFFFF) +
            b"\x88" + p64(0x8000000000000000) + p64(3) +
            b"\x48" + p64(2) + p32(0x80000000) + b"\x00")
    craft_F(L, BIG2, runs)


@case("f-nibble-carry", -3, False, "F (re-typed big record): length nibble 12 (only 8 bytes kept), offset nibble 9 "
      "and 15 (delta keeps previous value in F), shrinking length nibble keeps high bytes of the previous length")
def _(L, M, rnd):
    runs = (b"\x1c" + bytes.fromhex("8877665544332211aabbccdd") + b"\x10" +   # len 12 bytes, delta +16
            b"\x91" + b"\x05" + bytes(range(1, 10)) +                          # offN 9: delta unchanged (+16)
            b"\x11" + b"\x07" + b"\xfe" +                                      # length low byte only -> carry
            b"\xf2" + b"\x34\x12" + bytes(15) +                                # offN 15: delta unchanged (-2)
            b"\x00")
    craft_F(L, BIG2, runs)


@case("f-many-runs", 9, True, "F (re-typed big record) with ~280 small runs: long comma-joined Detail "
      "(~2600 units, all ',' -> '/'), deterministic but long CSV field")
def _(L, M, rnd):
    runs = bytearray()
    while len(runs) < 840:
        runs += bytes([0x11, rnd.randrange(1, 128), rnd.randrange(1, 128)])
    runs += b"\x00"
    craft_F(L, BIG2, bytes(runs))


@case("f-lennibble-13", 0, False, "F run with length nibble 13: memcpy of 13 bytes into the 8-byte length overwrites "
      "the low byte of the saved Parser* used by the F lookback / epilogue - crash candidate")
def _(L, M, rnd):
    craft_F(L, BIG2, b"\x1d" + bytes([0xEE] * 13) + b"\x01" + b"\x00")


@case("a-runs-edges", -3, False, "A (crafted FILE image) non-resident $DATA runs: length nibble 9 (first 8 bytes "
      "kept), offset nibble 9 (A: delta 0), negative delta -> u64 LCN, 8-byte length, then a length-nibble-0 header "
      "ends decoding")
def _(L, M, rnd):
    runs = (b"\x19" + p64(0x0100000000000000) + b"\xaa" + b"\x10" +
            b"\x91" + b"\x05" + bytes([0x7F] * 9) +
            b"\x21" + b"\x03" + p16(0x8000) +
            b"\x48" + p64(0xFFFFFFFFFFFFFFFF) + p32(0x7FFFFFFF) +
            b"\x80\x11\x01\x01\x00")
    craft_A(L, BIG3, [TEMPLATE["si"], fn_attr(TEMPLATE["fn"], U("runs,edge's.bin"), parent=0x0005000000000005),
                      nonres_data(runs)], "crafted FILE image, $DATA runs")


@case("a-data-len-lt-mp", 0, False, "A (crafted FILE image) non-resident $DATA with attribute length 0x48 < "
      "mapping-pairs offset 0x60: memcpy length (len - mp) underflows - crash candidate")
def _(L, M, rnd):
    data = bytearray(0x70)
    data[0:4], data[4:8], data[8] = p32(0x80), p32(0x48), 1
    data[0x20:0x22] = p16(0x60)
    data[0x60:0x64] = b"\x11\x01\x01\x00"
    attrs = [TEMPLATE["si"], fn_attr(TEMPLATE["fn"], U("short data.bin"), parent=0x0005000000000005), data[:0x48]]
    craft_A(L, BIG3, attrs, "crafted FILE image, $DATA len < mp")


# ---- resident writes ---------------------------------------------------------------------------------------------
@case("e1-size-extremes", 0, False, "E1 redo_length 0 ('Writing Size : 0') and redo_length 0xFFFF with "
      "record_offset 0xFFFF ('Writing Size : 65535'); lengths unrelated to the record size")
def _(L, M, rnd):
    L.set_hdr16(E1_IT, "redo_len", 0)
    L.set_hdr16(E1_ABC, "redo_len", 0xFFFF)
    L.set_hdr16(E1_ABC, "rec_off", 0xFFFF)


@case("e1-gate-boundaries", 9, False, "E1 gates: record_offset 0xF8 (still E1), 0xF7 (no branch, row vanishes), "
      "attribute_offset 0x19 (no branch)")
def _(L, M, rnd):
    L.set_hdr16(E1_IT, "rec_off", 0xF8)
    L.set_hdr16(E1_ABC, "rec_off", 0xF7)
    L.set_hdr16(E1_TMP, "attr_off", 0x19)


@case("e1-tvcn-highdword", 14, True, "E1 target_vcn = 0x1_0000000C: TargetVCN string is the low dword, so the "
      "File Creation lookback (string compare) still inherits the name")
def _(L, M, rnd):
    L.set_tvcn(E1_IT, 0x1_0000000C)


# ---- parent references -------------------------------------------------------------------------------------------
@case("a-parent-root-test", -3, False, "A parent refs: 0xFFFF000000000005 (root, any sequence -> '\\name'), "
      "0x0000000100000005 (48-bit record 0x100000005, not root), 0x0000FFFFFFFFFFFF (max record number)")
def _(L, M, rnd):
    a_set_name(L, A_IT, U("it's here.txt"), parent=0xFFFF000000000005)
    a_set_name(L, A_ABC, U("a,b,c.csv"), parent=0x0000000100000005)
    a_set_name(L, A_WS, U("with space and, comma's.log"), parent=0x0000FFFFFFFFFFFF)


@case("c-parent-key-trunc", 9, False, "C parent ref 0x0000000400000031: location key '0x%X' of (u32)(n>>2) = "
      "'0xC' (bit 34 dropped), so E2 (LSN 1105111) still sets the Deletion EventTime")
def _(L, M, rnd):
    L.put(C_IT, 0x10, p64(0x0000000400000031), "index entry parent ref")


@case("c-parent-seq-mask", -12, False, "C parent ref 0xFFFF000000000031: the sequence word is masked before the "
      "location key, key stays '0xC'/2, E2 still updates the Deletion row")
def _(L, M, rnd):
    L.put(C_IT, 0x10, p64(0xFFFF000000000031), "index entry parent ref")


@case("h-move-by-seq", 0, False, "H parent ref differs from the G row only in the sequence number (2 vs 1): full "
      "64-bit compare -> Move(Before) UPDATE + Move(After) instead of Renaming")
def _(L, M, rnd):
    L.put(H_IT, 0x18, p64(0x0002000000000031), "attribute $FN parent ref")


@case("a-parent-self-mft", 14, True, "With $MFT: A parent = its own record 0x33 under the $MFT's sequence 4 (a FILE "
      "DirEntry, flag 0, used as parent); A parent 'sub dir' with sequence 2 (full-u64 miss, FullPath unassigned); "
      "$MFT 'tmp' (0x29) parent = itself (key == parentRef -> no DirEntry, children lose paths)", mft=True)
def _(L, M, rnd):
    a_set_name(L, A_IT, U("it's here.txt"), parent=0x0004000000000033)
    a_set_name(L, A_ABC, U("a,b,c.csv"), parent=0x0002000000000028)
    assert M.name(0x29) == "tmp"
    M.wr(0x29, M.fn(0x29)[-1], p64(0x0001000000000029), "$FN parent of 'tmp' = its own key")


# ---- index entries -----------------------------------------------------------------------------------------------
@case("c-name-len0", -3, False, "C index entry with name length 0: FileName '' (not a DOS name), Temp Event, B "
      "finds no usable txn entry -> no File Deletion row")
def _(L, M, rnd):
    L.put(C_IT, 0x50, b"\x00", "index entry name length")


@case("c-name-lenff-odd", 0, False, "C index entry name length 0xFF with entry/key lengths odd (0x6B/0x5F): the "
      "name is read past the entry up to the zeroed 0x2000 buffer, 'it's here.txt' + 'XY' then NUL")
def _(L, M, rnd):
    L.put(C_IT, 0x08, p16(0x6B) + p16(0x5F), "index entry length / key length")
    L.put(C_IT, 0x50, b"\xff", "index entry name length")
    L.put(C_IT, 0x6C, units_bytes(U("XY")), "bytes after the name")


@case("flags-exact", 9, False, "Flag names by exact equality: directory 'e' with flags 0x10000002 -> 'File "
      "Deletion'; file \"it's here.txt\" with 0x10000000 -> 'Directory Deletion'")
def _(L, M, rnd):
    L.put(C_DIR_E, 0x48, p32(0x10000002), "index entry flags")
    L.put(C_IT, 0x48, p32(0x10000000), "index entry flags")


@case("h-dir-flags", -3, False, "H $FN flags (buf+0x50) 0x10000000 -> 'Renaming Directory' for a file rename")
def _(L, M, rnd):
    L.put(H_IT, 0x50, p32(0x10000000), "attribute $FN flags")


# ---- FILE walk (A) -----------------------------------------------------------------------------------------------
@case("a-index-root-dollar", 0, False, "A directory whose name starts with '$' ('$ct'): the $INDEX_ROOT test "
      "FileName[0] != '$' fails, Event stays 'File Creation'")
def _(L, M, rnd):
    a_set_name(L, A_ACT, U("$ct"))


@case("a-stale-len-fake-ir", 9, False, "A walk: $FN type changed to 0x40 (unknown) -> advance by the stale $SI "
      "length onto a planted 90 00 00 00 -> 'Directory Creation' with FileName '' and EventTime ''")
def _(L, M, rnd):
    L.put(A_IT, 0x98, p32(0x40), "attribute type 0x30 -> 0x40")
    L.put(A_IT, 0xF8, p32(0x90), "planted $INDEX_ROOT type at the stale-length offset")


@case("a-si-after-fn", -3, False, "A FILE image with $FN before $SI: EventTime = CreateTime at $FN time = '', "
      "while the four times are still set by the later $SI")
def _(L, M, rnd):
    attrs = file_attrs(L.buf(A_IT))
    write_file_image(L, A_IT, [attrs[1], attrs[0]] + attrs[2:], "A attributes reordered ($FN, $SI, $DATA)")


@case("a-two-fn-last-wins", 0, False, "A (crafted FILE image) with two non-DOS $FN: \"first'.txt\" under root "
      "then 'second,.txt' under 0x31 -> FileName from the last $FN; FullPath stays '\\first''.txt' because the "
      "second parent is not resolvable without $MFT (FullPath not reassigned)")
def _(L, M, rnd):
    craft_A(L, BIG3, [TEMPLATE["si"], fn_attr(TEMPLATE["fn"], U("first'.txt"), parent=0x0005000000000005),
                      fn_attr(TEMPLATE["fn"], U("second,.txt"), parent=0x0001000000000031),
                      TEMPLATE["data_res"]], "crafted FILE image, two $FN")


# ---- $MFT --------------------------------------------------------------------------------------------------------
@case("mft-abnormal-before-mft", -3, False, "With $MFT: C create 2020-01-01 is older than the $MFT create string "
      "(p+0x1a8) -> Abnormal, Detail carries the SHIFTED create time", mft=True)
def _(L, M, rnd):
    c_set_times(L, C_IT, c=FT(2020, 1, 1))


@case("mft-abnormal-same-second", 0, False, "With $MFT: C create = $MFT create - 1 tick (same second): the ordinal "
      "string compare sees equal strings -> NOT abnormal", mft=True)
def _(L, M, rnd):
    c_set_times(L, C_IT, c=u64(M.rd(0, M.si(0), 8), 0) - 1)


@case("mft-dollar-mft-case", -3, False, "With $MFT whose record 0 is named '$Mft' (case differs): p+0x1a8 is not "
      "captured, so the C create 2020-01-01 falls back to the '20' rule -> not abnormal", mft=True)
def _(L, M, rnd):
    v = M.fn(0)[-1]
    M.wr(0, v + 0x42, units_bytes(U("$Mft")), "record 0 $FN name")
    c_set_times(L, C_IT, c=FT(2020, 1, 1))


@case("mft-seq-leak", 9, False, "With $MFT: record 37's only $FN gets namespace 2 and sequence 2 -> skipped "
      "without masking, its seq bits leak into record 38 ('act') key -> children of act lose their path", mft=True)
def _(L, M, rnd):
    v = M.fn(37)[-1]
    M.wr(37, v + 0x41, b"\x02", "record 37 $FN namespace -> 2 (DOS)")
    M.wr(37, 0x10, p16(2), "record 37 sequence -> 2")


@case("mft-cycle", 0, False, "With $MFT: 'act' (38) parent -> 'docs' (39) whose parent is 'act': BuildFullPath "
      "has no cycle guard - hang / out-of-memory candidate", mft=True)
def _(L, M, rnd):
    v = M.fn(38)[-1]
    M.wr(38, v, p64(0x0001000000000027), "record 38 $FN parent -> record 39")


@case("mft-v40-stale-si", 14, True, "With $MFT: SI times of 'docs' (39) >= 2^63: the V40 conversion fails and the "
      "V40 SYSTEMTIME slots keep the previous V40 hit's values", mft=True)
def _(L, M, rnd):
    v = M.si(39)
    M.wr(39, v, p64(0x8000000000000000) + p64(0x8000000000000001) + p64(0xFFFFFFFFFFFFFFFF) +
         p64(0x8123456789ABCDEF), "record 39 $SI times")


@case("mft-flags-word", -3, False, "With $MFT: directory 'docs' (39) flags word 3 -> 7: DirEntry needs the exact "
      "word 2/3, so docs gets none and paths below it break", mft=True)
def _(L, M, rnd):
    M.wr(39, 0x16, p16(7), "record 39 flags")


@case("mft-v40-name-escape", 0, False, "With $MFT: directory 'act' renamed \"'a,\" in the $MFT: V40 FileName and "
      "every BuildFullPath component through it get '' / '/' escaping", mft=True)
def _(L, M, rnd):
    v = M.fn(38)[-1]
    M.wr(38, v + 0x42, units_bytes(U("'a,")), "record 38 $FN name")


# ------------------------------------------------------------------------------------------------ driver
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "fuzz" / "cases"))
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    out = Path(a.out)
    base_log = (BASE_DIR / "$LogFile").read_bytes()
    base_mft = (BASE_DIR / "$MFT").read_bytes()
    check_base(Log(base_log))
    if not a.only:
        for d in out.glob(f"{FAMILY}-[0-9][0-9][0-9]-*"):
            shutil.rmtree(d)
    written = []
    for n, c in enumerate(CASES, 1):
        cid = f"{FAMILY}-{n:03d}-{c['slug']}"
        if a.only and a.only not in cid:
            continue
        rnd = random.Random(f"{a.seed}:{c['slug']}")
        L = Log(base_log)
        M = Mft(base_mft)
        c["fn"](L, M, rnd)
        assert L.muts or M.muts, cid
        d = out / cid
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        (d / "$LogFile").write_bytes(bytes(L.b))
        mutation = {"seed": a.seed, "log_patches": L.muts}
        if c["mft"]:
            (d / "$MFT").write_bytes(bytes(M.b))
            mutation["mft_patches"] = M.muts
        else:
            assert not M.muts, cid
        cj = {"utc": c["utc"], "dst": c["dst"], "mft": c["mft"], "family": FAMILY, "desc": c["desc"],
              "base": "samples/synth-01/$LogFile" + (" + samples/synth-01/$MFT" if c["mft"] else ""),
              "mutation": mutation}
        (d / "case.json").write_text(json.dumps(cj, indent=1, ensure_ascii=False), encoding="utf-8")
        written.append(cid)
    print("\n".join(written))
    print(f"{len(written)} cases")


if __name__ == "__main__":
    main()
