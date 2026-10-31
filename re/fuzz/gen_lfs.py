"""Family "lfs": structural mutations of $LogFile pages and records (fuzz corpus for the differential campaign).

  python -I re/fuzz/gen_lfs.py [--seed N] [--out fuzz/cases] [--only SUBSTR] [--list]

Deterministic: the same --seed always writes byte-identical cases. Every case lands in
fuzz/cases/lfs-<NNN>-<slug>/ with "$LogFile", optional "$MFT" and case.json (see re/fuzz/campaign.py). Existing
lfs-* case folders are replaced. Nothing here runs the original or the port.

Bases: samples/synth-01 ($LogFile 2.6 MB LFS 2.0, seq_number_bits 0x2d, 176 RCRD pages, + its $MFT),
a wrap-around slice of samples/user-01 (RSTR pages + the 0x20 tail-copy pages + 2x160 regular pages around the
physical wrap point; seq_number_bits 0x28, LSNs >= 2^24 so the hi40 tests are live), and "built" logs: the 4247
synth-01 records re-laid out in fresh RCRD pages by Builder (original LSNs kept, so the $MFT V40 correlation still
works) with filler Noop records to put chosen records at chosen page offsets.

Targeted behaviours of ParseLogFile 0x40e340 (re/spec/02-logfile-structure.md, 01-driver.md 2.11):
  Restart pages (2.2-2.4)
  - strict RSTR match (usa 0x1e/9, chkdsk_lsn 0, page sizes 0x1000), LAST strict page in file order wins, no
    current_lsn/fixup check; strict-ness broken separately by usa_ofs, usa_count, chkdsk_lsn, sys/log page size;
    RSTR at 0 or 0x1000 missing (silent return 2); a stale strict RSTR page later in the file overriding both.
  - LFS 1.1 vs 2.0 vs other versions ("not supported"); 1.1 at one page only.
  - seq_number_bits (RA+0x10) -> shift = 0x40 - snb used only by FindFirst through _aullshr 0x5589d0, which uses
    CL ONLY (shift mod 256; >= 64 gives 0): snb 0x140 / 0x12d / 0x13c alias to shifts 0 / 19 / 4.
  - restart_area_offset not bounds-checked (RA near the page end, unaligned, inside the header); RA file_size and
    other RA fields ignored.
  RCRD page set (2.3, 2.6)
  - v2.0 needs >= 0x20 RCRD pages (else AfxThrowInvalidArgException = process death), v1.1 needs >= 2; exactly
    0x20 (no regular pages: every non-zero special goes to F0), 0x21, 2, 3 pages.
  - RCRD signature variants ("BAAD", zero pages, foreign signatures, usa_ofs/usa_count != 0x28/9) shift the b4
    ordinals, so which pages are "special" (b4[0..0x1f]) moves.
  - partial last page (file length not a multiple of 0x1000): Read keeps stale buffer bytes (scan: previous file
    page raw; traversal: previously listed page after its fixup; first listed page: whatever the scan / the v1.1
    buffer-page re-reads left), a 4-byte "RCRD" tail classified with stale bytes, trailing garbage pages.
  Page ordering (2.5, 2.6, edge 24)
  - runs of non-decreasing last_lsn, zero last_lsn joins the run, backwards last_lsn starts a group, unstable
    MSVC qsort (CUTOFF 8, median of three) of group keys with many ties whose pages differ in content, DC/F0
    lists with ties, last_lsn == min / == max boundaries, last_lsn 0xFFFF... as max, permuted / reversed /
    rotated regular pages, tail-copy duplicates with edited content (duplicate LSNs: first insert wins; a record
    spilling from one listed copy into the next, non-contiguous, copy).
  - v1.1 buffer-page choice (M vs A/B last_end_lsn, ties), prevB = A leftover.
  Record traversal (2.8-2.13)
  - header splits for many k = 0x1000 - savedOff (aligned and unaligned), body spans q=0 ending at many offsets,
    EXACT_END, multi-page records q=1..3 (+1 page when < 0x30 left), HS_BODY_SPAN, HS_EXACT_END (span stays 1:
    self-perpetuating stale path A), zero-tail header split and HS cdl < 0x28 (32-bit wrap -> q = 0x104103 ends
    the traversal), HS q=0 completion reading past the page (remaining > 0xfc0), flag bump on the first regular
    page, this_lsn == PI.last_lsn (curOff carried to the next page), 16-zero-byte page end vs 15, hi40 crossing
    (END_HOOD / neighbourhood FindFirst recovery), order recovery (cdl 0, LSN < prevB), LSN ~0, LSN 0 with fip,
    LSN >= 2^63 (REAL in SQLite), cdl not a multiple of 8, lying cdl (multi-page skip of 15 pages resuming on a
    real record; 0xffffffff -> q = 0x104103 ends the traversal), cdl < redo_offset, negative recovery memcpy,
    redo/undo offsets and lengths out of range, unknown op codes (0x%x names), record_type/flags values.
  - FindFirst near the page end (off 0xfd0/0xfd8) and unbounded 0x58-byte recovery copies, which read past the
    0x1000 page buffer into tmpHdr (the last split header) in the original (edge 22).
  USA / fixup (2.8)
  - blind fixup: USN never compared (torn sectors), USA words planted into record headers/bodies at sector ends,
    USA entries randomised.
"""
import argparse
import json
import random
import shutil
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"
PAGE = 0x1000
RCRD = b"RCRD\x28\x00\x09\x00"
FAMILY = "lfs"


# ----------------------------------------------------------------------------------------------- byte helpers
def g16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def g32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def g64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def p16(b, o, v):
    struct.pack_into("<H", b, o, v & 0xFFFF)


def p32(b, o, v):
    struct.pack_into("<I", b, o, v & 0xFFFFFFFF)


def p64(b, o, v):
    struct.pack_into("<Q", b, o, v & 0xFFFFFFFFFFFFFFFF)


def unprotect(page):
    """The parser's blind fixup: USA words +0x2a..+0x38 copied to the 8 sector ends."""
    b = bytearray(page)
    for s in range(8):
        b[0x200 * s + 0x1FE:0x200 * s + 0x200] = page[0x2A + 2 * s:0x2C + 2 * s]
    return b


def protect(page, usn):
    """Inverse of unprotect for a logical RCRD page: sector ends -> USA, USN written at the sector ends."""
    b = bytearray(page)
    p16(b, 0x28, usn)
    for s in range(8):
        e = 0x200 * s + 0x1FE
        b[0x2A + 2 * s:0x2C + 2 * s] = b[e:e + 2]
        p16(b, e, usn)
    return b


def is_rcrd(data, off):
    return data[off:off + 8] == RCRD


def b4_offsets(data):
    """File offsets of the RCRD pages in scan order (full pages only)."""
    return [o for o in range(0, len(data) - PAGE + 1, PAGE) if is_rcrd(data, o)]


# ----------------------------------------------------------------------------------------------- bases
class Base:
    _cache = {}

    @classmethod
    def synth(cls):
        if "synth" not in cls._cache:
            d = (SAMPLES / "synth-01" / "$LogFile").read_bytes()
            m = (SAMPLES / "synth-01" / "$MFT").read_bytes()
            cls._cache["synth"] = (d, m)
        return cls._cache["synth"]

    @classmethod
    def user01_wrap(cls, side=160):
        """RSTR pages + physical pages 2..0x21 (the 0x20 tail copies) + `side` regular pages before and after the
        physical wrap point (last_lsn drop) of samples/user-01. Result: 2 groups (wrap), LSNs with hi40 0x4a16/0x4a17."""
        key = ("u01", side)
        if key not in cls._cache:
            src = SAMPLES / "user-01" / "$LogFile"
            with open(src, "rb") as f:
                d = f.read()
            offs = b4_offsets(d)
            reg = offs[0x20:]
            wrap = next(k for k in range(1, len(reg)) if g64(d, reg[k] + 8) < g64(d, reg[k - 1] + 8))
            keep = list(range(0, 0x22 * PAGE, PAGE)) + reg[wrap - side:wrap + side]
            out = bytearray()
            for o in keep:
                out += d[o:o + PAGE]
            cls._cache[key] = (bytes(out), {"wrap_index_in_slice": 0x22 + side, "src_pages": f"0..0x21, regular "
                               f"{hex(reg[wrap - side])}..{hex(reg[wrap + side - 1])}"})
        return cls._cache[key]

    @classmethod
    def synth_records(cls):
        """All synth-01 records found at the file position their LSN encodes, reassembled across pages, LSN order."""
        if "srecs" not in cls._cache:
            d, _ = cls.synth()
            snb = g32(d, 0x1000 + g16(d, 0x1018) + 0x10)
            mask = (1 << (64 - snb)) - 1
            pages = {o: unprotect(d[o:o + PAGE]) for o in range(0x22000, len(d) - PAGE + 1, PAGE) if is_rcrd(d, o)}
            recs = {}
            for off in sorted(pages):
                p = pages[off]
                for pos in range(0x40, PAGE - 0x30 + 1, 8):
                    lsn, _prev, _un, cdl, _cid, rt = struct.unpack_from("<QQQIII", p, pos)
                    if lsn == 0 or (lsn & mask) * 8 != off + pos or rt not in (1, 2) or cdl > 0x10000:
                        continue
                    total = 0x30 + cdl
                    body = bytearray(p[pos:pos + total])
                    nxt = off + PAGE
                    while len(body) < total and nxt in pages:
                        body += pages[nxt][0x40:0x40 + total - len(body)]
                        nxt += PAGE
                    if len(body) == total:
                        recs[lsn] = bytes(body)
            cls._cache["srecs"] = [recs[k] for k in sorted(recs)]
        return cls._cache["srecs"]


def rec_lsn(r):
    return g64(r, 0)


def rec_ops(r):
    return (g16(r, 0x30), g16(r, 0x32)) if len(r) >= 0x34 else (None, None)


# ----------------------------------------------------------------------------------------------- record builder
def mkrec(lsn, cdl, client=b"", prev=0, undo_next=0, rtype=1, tid=0, flags=0, cid=(0, 0)):
    """LFS record: 0x30-byte header + cdl bytes of client data (client is padded with zeros / truncated)."""
    h = struct.pack("<QQQIHHIIH6x", lsn, prev, undo_next, cdl, cid[0], cid[1], rtype, tid, flags)
    body = bytes(client[:cdl]) + bytes(max(0, cdl - len(client)))
    return h + body


def noop_client(cdl, redo=0, undo=0):
    """NTFS client header for a Noop/Noop filler: redo/undo offsets 0x28 when they fit, else 0."""
    o = 0x28 if cdl >= 0x28 else 0
    return struct.pack("<HHHHHH", redo, undo, o, 0, o, 0)


def with_cdl(r, cdl):
    """Same record with a new client_data_length (body zero-padded or truncated)."""
    b = bytearray(r[:0x30 + cdl]) + bytes(max(0, 0x30 + cdl - len(r)))
    p32(b, 0x18, cdl)
    return bytes(b)


class Builder:
    """Lays out records contiguously in the data area (0x40..0x1000) of fresh RCRD pages, like the parser walks them:
    next = start + 0x30 + cdl (no alignment), a record never STARTS with fewer than 0x30 bytes left in a page (the
    parser's END_LT30 rule), overflow continues at +0x40 of the next page. Pages are kept unprotected (logical
    content) until file assembly."""

    def __init__(self):
        self.pages, self.starts, self.ends = [], [], []
        self.recs = []  # (lsn, page, off, total)
        self.fill_lsn = None
        self._new_page()

    def _new_page(self):
        self.pages.append(bytearray(PAGE))
        self.starts.append([])
        self.ends.append([])
        self.pi, self.off = len(self.pages) - 1, 0x40

    def next_page(self):
        """Leave the rest of the current page zero and continue at +0x40 of a new page."""
        if self.off > 0x40 or self.starts[self.pi] or self.ends[self.pi]:
            self._new_page()

    def _write(self, b):
        i = 0
        while i < len(b):
            if self.off >= PAGE:
                self._new_page()
            n = min(PAGE - self.off, len(b) - i)
            self.pages[self.pi][self.off:self.off + n] = b[i:i + n]
            self.off += n
            i += n

    def add(self, r, lsn=None):
        lsn = rec_lsn(r) if lsn is None else lsn
        if PAGE - self.off < 0x30:
            self._new_page()
        start = (self.pi, self.off)
        self.starts[self.pi].append((self.off, lsn))
        self._write(r)
        self.ends[self.pi].append(lsn)
        self.recs.append((lsn, start[0], start[1], len(r)))
        self.last_lsn = lsn
        return start

    def raw(self, b, here=False):
        """Write raw bytes at the current position (not a record; the parser will see them as a header).
        here=True writes them even when fewer than 0x30 bytes remain in the page."""
        if PAGE - self.off < 0x30 and not here:
            self._new_page()
        start = (self.pi, self.off)
        self._write(b)
        return start

    def skip_to(self, off):
        """Leave zeros up to page offset `off` of the current page (no record there)."""
        assert off >= self.off, (hex(off), hex(self.off))
        self.off = off

    def filler_lsn(self):
        self.fill_lsn = max(self.fill_lsn or 0, self.last_lsn) + 1
        return self.fill_lsn

    def filler(self, total):
        """A Noop/Noop record of `total` bytes (total >= 0x38 so that cdl >= 8 and the order test passes)."""
        assert total >= 0x38, total
        return self.add(mkrec(self.filler_lsn(), total - 0x30, noop_client(total - 0x30)))

    def place_at(self, target, extra_pages=0):
        """Insert one filler so that the next record starts at page offset `target` (this page if possible, else
        the next one; `extra_pages` more pages later on request, giving a multi-page filler)."""
        if PAGE - self.off < 0x30:
            self._new_page()
        if target >= self.off + 0x38 and not extra_pages:
            d = target - self.off
        else:
            d = (PAGE - self.off) + (target - 0x40) + 0xFC0 * extra_pages
            if d < 0x38:
                d += 0xFC0
        self.filler(d)
        if self.off >= PAGE:
            self._new_page()
        assert self.off == target, (hex(self.off), hex(target))

    def page_headers(self):
        """(last_lsn, last_end_lsn, next_record_offset) per page, NTFS-like."""
        out, cur = [], 0
        for i in range(len(self.pages)):
            st = self.starts[i]
            if st:
                cur = st[-1][1]
            last = cur
            le = self.ends[i][-1] if self.ends[i] else last
            nro = st[-1][0] if st else 0
            out.append((last, le, nro))
        return out


def rcrd_page(logical, last_lsn, last_end_lsn, nro=0, count=1, pos=1):
    p = bytearray(logical)
    p[0:8] = RCRD
    p64(p, 8, last_lsn)
    p32(p, 0x10, 0)
    p16(p, 0x14, count)
    p16(p, 0x16, pos)
    p16(p, 0x18, nro)
    p64(p, 0x20, last_end_lsn)
    return p


def builder_pages(builder, hdr_override=None):
    """The builder's pages as logical RCRD pages (headers filled in, not yet protected)."""
    hdrs = builder.page_headers()
    out = []
    for i, lp in enumerate(builder.pages):
        last, le, nro = hdrs[i]
        if hdr_override and i in hdr_override:
            last, le = hdr_override[i]
        out.append(rcrd_page(lp, last, le, nro))
    return out


def default_specials(regs):
    """0x20 copies of regular pages 1..n-2: last_lsn inside [min, max], so v2.0 drops them all."""
    n = len(regs)
    assert n >= 0x23, n
    return [regs[1 + (k * (n - 2)) // 0x20] for k in range(0x20)]


def file_from(regs, specials=None, rstr=None, usn_base=0x10):
    """$LogFile = 2 RSTR pages (synth-01's unless given) + special RCRD pages + regular RCRD pages (protected)."""
    sd, _ = Base.synth()
    out = bytearray(rstr if rstr is not None else sd[:2 * PAGE])
    specials = default_specials(regs) if specials is None else specials
    for k, sp in enumerate(specials):
        out += protect(sp, usn_base + k)
    for i, rp in enumerate(regs):
        out += protect(rp, (usn_base + len(specials) + i) % 0xFFFF or 1)
    return out


def assemble(builder, **kw):
    return file_from(builder_pages(builder), **kw)


# ----------------------------------------------------------------------------------------------- mutation log
class Mut:
    """Applies and documents byte edits: every edit is listed in case.json with offset, size, old and new value."""

    def __init__(self):
        self.edits = []

    def put(self, d, off, size, val, what):
        val &= (1 << (8 * size)) - 1
        old = int.from_bytes(d[off:off + size], "little")
        d[off:off + size] = val.to_bytes(size, "little")
        self.edits.append({"off": hex(off), "size": size, "what": what, "old": hex(old), "new": hex(val)})

    def note(self, **kw):
        self.edits.append({k: (hex(v) if isinstance(v, int) and not isinstance(v, bool) else v) for k, v in kw.items()})


RSTR_F = {"usa_ofs": (4, 2), "usa_count": (6, 2), "chkdsk_lsn": (8, 8), "sys_page_size": (0x10, 4),
          "log_page_size": (0x14, 4), "ra_offset": (0x18, 2), "minor": (0x1A, 2), "major": (0x1C, 2)}
RA_F = {"current_lsn": (0, 8), "log_clients": (8, 2), "client_free_list": (0xA, 2), "client_in_use": (0xC, 2),
        "ra_flags": (0xE, 2), "seq_number_bits": (0x10, 4), "ra_length": (0x14, 2), "client_array_offset": (0x16, 2),
        "file_size": (0x18, 8), "last_lsn_data_length": (0x20, 4), "rec_hdr_len": (0x24, 2),
        "log_page_data_offset": (0x26, 2), "open_count": (0x28, 4)}


def set_rstr(d, m, page, **kw):
    """Edit RSTR header fields (RSTR_F) and restart-area fields (RA_F, at the page's current ra_offset)."""
    for k, v in kw.items():
        if k in RSTR_F:
            o, n = RSTR_F[k]
            m.put(d, page + o, n, v, f"RSTR@{hex(page)}.{k}")
        else:
            o, n = RA_F[k]
            ra = g16(d, page + 0x18)
            m.put(d, page + ra + o, n, v, f"RSTR@{hex(page)}.RA(+{hex(ra)}).{k}")


def edit_page(d, off, fn):
    """Edit the logical (fixed-up) content of RCRD page `off` and re-protect it with its own USN."""
    usn = g16(d, off + 0x28)
    lp = unprotect(d[off:off + PAGE])
    fn(lp)
    d[off:off + PAGE] = protect(lp, usn)


SNB_SYNTH = 0x2D
ROWOPS = {2, 3, 5, 6, 7, 9}  # redo ops that produced rows on synth-01 (InitFRS, DeallocFRS, Create/DeleteAttr, URV, UMP)


def page_recs(d, off, snb=SNB_SYNTH):
    """Record headers that start in page `off` at the position their LSN encodes (logical content)."""
    mask = (1 << (64 - snb)) - 1
    p = unprotect(d[off:off + PAGE])
    out = []
    for pos in range(0x40, PAGE - 0x30 + 1, 8):
        lsn, prev, _un, cdl, _cid, rt = struct.unpack_from("<QQQIII", p, pos)
        if lsn and (lsn & mask) * 8 == off + pos and rt in (1, 2):
            redo = g16(p, pos + 0x30) if pos + 0x34 <= PAGE else None
            out.append({"pos": pos, "lsn": lsn, "cdl": cdl, "redo": redo, "prev": prev})
    return out


def synth_regular():
    d, _ = Base.synth()
    return b4_offsets(d)[0x20:]


def ranked_pages(min_recs=4):
    """Regular synth-01 pages ranked by the number of row-producing records (ties: file order)."""
    d, _ = Base.synth()
    out = []
    for off in synth_regular():
        rs = page_recs(d, off)
        if len(rs) >= min_recs:
            out.append((-sum(1 for r in rs if r["redo"] in ROWOPS), off, rs))
    out.sort(key=lambda t: (t[0], t[1]))
    return [(off, rs) for _, off, rs in out]


def mft_lsns():
    _, m = Base.synth()
    s = {g64(m, o + 8) for o in range(0, len(m) - 0x3FF, 0x400) if m[o:o + 4] == b"FILE"}
    s.discard(0)
    return s


def shift_lsns(r, delta):
    """Record with this_lsn, client_previous_lsn and client_undo_next_lsn shifted by delta (nonzero ones)."""
    b = bytearray(r)
    for o in (0, 8, 0x10):
        v = g64(b, o)
        if v or o == 0:
            p64(b, o, v + delta)
    return bytes(b)


def row_recs(recs):
    return [i for i, r in enumerate(recs) if rec_ops(r)[0] in ROWOPS]


CASES = []


def case(slug, base):
    def deco(fn):
        CASES.append((slug, base, fn))
        return fn
    return deco


def synth_copy():
    d, _ = Base.synth()
    return bytearray(d)


def walk_headers(lp, ok):
    """Header positions of a page found by walking: 8-byte scan until ok(pos), then follow cdl."""
    pos, out = 0x40, []
    while pos + 0x46 <= PAGE:
        cdl = g32(lp, pos + 0x18)
        if not ok(lp, pos) or cdl == 0:
            pos += 8
            continue
        out.append(pos)
        pos += 0x30 + cdl
    return out


# =============================================================================================== restart pages
def _v11(d, m, a=None, b=None):
    set_rstr(d, m, 0, major=1, minor=1)
    set_rstr(d, m, PAGE, major=1, minor=1)
    b4 = b4_offsets(d)
    if a is not None:
        m.put(d, b4[0] + 0x20, 8, a, "b4[0] (bp1) last_end_lsn = A")
    if b is not None:
        m.put(d, b4[1] + 0x20, 8, b, "b4[1] (bp2) last_end_lsn = B")


@case("v11-both", "synth-01")
def c_v11_both(rng):
    d, m = synth_copy(), Mut()
    _v11(d, m)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "M = 0x1186e8 > A, B: no buffer page "
                "appended; regular = b4[2..] (tail copies included); prevB = A = 0x118186"},
                desc="LFS 1.1 in both RSTR pages: v1.1 ordering (regular = b4[2..], buffer pages by last_end_lsn "
                     "vs M, prevB = A leftover makes the first page fail the order test); no v1.1 sample exists")


@case("v11-bp2-a-lt-b", "synth-01")
def c_v11_ab(rng):
    d, m = synth_copy(), Mut()
    _v11(d, m, a=0x118800, b=0x118900)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "branch": "M < A < B -> append bp2 (b4[1]); prevB = A "
                "above every LSN -> FindFirst recovery on the first page"},
                desc="v1.1 buffer-page choice, else-branch with A < B: bp2 appended at the end, huge prevB leftover")


@case("v11-bp1-tie", "synth-01")
def c_v11_tie(rng):
    d, m = synth_copy(), Mut()
    _v11(d, m, a=0x118800, b=0x118800)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "branch": "A == B > M -> (A < B) false -> bp1 (b4[0])"},
                desc="v1.1 buffer-page choice with A == B (tie): bp1 appended")


@case("v11-m-gt-a", "synth-01")
def c_v11_ma(rng):
    d, m = synth_copy(), Mut()
    _v11(d, m, a=0x104000, b=0x118900)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "branch": "A < M < B -> 'M > A' -> bp2; prevB = A small"},
                desc="v1.1 buffer-page choice via M > A (bp2), small prevB leftover")


@case("v11-m-gt-b", "synth-01")
def c_v11_mb(rng):
    d, m = synth_copy(), Mut()
    _v11(d, m, a=0x118900, b=0x104000)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "branch": "B < M < A -> 'M > B' -> bp1; prevB = A huge"},
                desc="v1.1 buffer-page choice via M > B (bp1)")


@case("v11-2pages", "synth-01")
def c_v11_2p(rng):
    d, m = synth_copy()[:0x5000], Mut()
    m.note(op="truncate", new_length=0x5000, rcrd_pages="0x2000, 0x4000 (0x3000 is an 0xFF page)")
    _v11(d, m)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "branch": "no regular pages, M = 0 -> A < B -> bp2 only"},
                desc="v1.1 with exactly 2 RCRD pages: empty regular set, list = [bp2] only")


@case("v11-1page", "synth-01")
def c_v11_1p(rng):
    d, m = synth_copy()[:0x3000], Mut()
    m.note(op="truncate", new_length=0x3000, rcrd_pages="0x2000")
    _v11(d, m)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "AfxThrowInvalidArgException at 0x40ef77 "
                "(b4.size <= 1) -> process death"},
                desc="v1.1 with a single RCRD page: InvalidArg throw after the bp1 re-read (crash candidate)")


@case("v11-3pages", "synth-01")
def c_v11_3p(rng):
    d, m = synth_copy()[:0x6000], Mut()
    m.note(op="truncate", new_length=0x6000, rcrd_pages="0x2000, 0x4000, 0x5000")
    _v11(d, m)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "branch": "one regular page (0x5000), M > A, B -> none"},
                desc="v1.1 with 3 RCRD pages: one regular page, no buffer page appended")


@case("rstr-last-wins", "synth-01")
def c_last_wins(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, 0, major=1, minor=1, seq_number_bits=0x40)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "page 0x1000 (2.0, snb 0x2d) wins: output "
                "identical to synth-01; any use of page 0 would switch to v1.1 / shift 0"},
                desc="strict RSTR at 0 says LFS 1.1 + snb 0x40, strict RSTR at 0x1000 unchanged: last strict page wins")


@case("rstr-ns-usaofs", "synth-01")
def c_ns_usaofs(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, PAGE, usa_ofs=0x28)
    set_rstr(d, m, 0, major=1, minor=1)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "page 0x1000 not strict -> page 0 (v1.1)"},
                desc="RSTR at 0x1000 non-strict (usa_ofs 0x28), so the v1.1 page at 0 is used")


@case("rstr-ns-chkdsk", "synth-01")
def c_ns_chkdsk(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, PAGE, chkdsk_lsn=1)
    set_rstr(d, m, 0, seq_number_bits=0x40)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "page 0 used: shift = 0 (FindFirst needs "
                "this_lsn == last_end_lsn exactly)"},
                desc="RSTR at 0x1000 non-strict (chkdsk_lsn 1); page 0 strict with seq_number_bits 0x40 (shift 0)")


@case("rstr-ns-pagesize", "synth-01")
def c_ns_pagesize(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, PAGE, log_page_size=0x2000)
    set_rstr(d, m, 0, major=2, minor=1)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "page 0 used: LFS 2.1 -> not supported"},
                desc="RSTR at 0x1000 non-strict (log page size 0x2000); strict page 0 says LFS 2.1 (unsupported)")


@case("rstr-both-nonstrict", "synth-01")
def c_both_ns(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, 0, sys_page_size=0x200)
    set_rstr(d, m, PAGE, usa_count=8)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "no strict RSTR: version 0.0 -> not supported"},
                desc="both RSTR pages present but non-strict (sys page size 0x200 / usa_count 8): version 0.0")


@case("rstr-stale-late-v11", "synth-01")
def c_stale_late(rng):
    d, m = synth_copy(), Mut()
    dst = 0x200000
    assert d[dst:dst + 8] == b"\xff" * 8
    d[dst:dst + PAGE] = d[PAGE:2 * PAGE]
    m.note(op="copy_page", src=PAGE, dst=dst, why="strict RSTR copy in an unused 0xFF page late in the file")
    set_rstr(d, m, dst, major=1, minor=1, seq_number_bits=0x2C)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "last strict RSTR in file order (0x200000) "
                "wins: v1.1 with shift 20"},
                desc="stale strict RSTR page (LFS 1.1, snb 0x2c) deep inside the file overrides both real restart pages")


def _snb(val, mft, note):
    def fn(rng):
        d, m = synth_copy(), Mut()
        set_rstr(d, m, 0, seq_number_bits=val)
        set_rstr(d, m, PAGE, seq_number_bits=val)
        sh = (0x40 - val) & 0xFFFFFFFF
        return dict(log=d, mft=mft, mutation={"edits": m.edits, "shift_dword": hex(sh), "aullshr_cl": hex(sh & 0xFF),
                                              "note": note},
                    desc=f"seq_number_bits {hex(val)} in both RSTR pages: shift dword {hex(sh)}, _aullshr 0x5589d0 "
                         f"uses CL only ({hex(sh & 0xFF)}): {note}")
    return fn


case("snb-40-shift0", "synth-01")(_snb(0x40, False, "shift 0, FindFirst needs this_lsn == last_end_lsn"))
case("snb-0-shift64", "synth-01")(_snb(0, True, "CL 0x40 gives 0 for every value: any slot with plausible "
                                        "type/flags passes FindFirst"))
case("snb-140-cl0", "synth-01")(_snb(0x140, False, "dword >= 64 but CL = 0: the original shifts by 0"))
case("snb-12d-cl13", "synth-01")(_snb(0x12D, True, "dword >= 64 but CL = 0x13: the original shifts by 19 like "
                                        "the unmodified sample"))


@case("ra-offset-fe0", "synth-01")
def c_ra_fe0(rng):
    d, m = synth_copy(), Mut()
    for pg in (0, PAGE):
        set_rstr(d, m, pg, ra_offset=0xFE0)
        m.put(d, pg + 0xFF0, 4, 0x30, f"RSTR@{hex(pg)} dword at ra+0x10 (0xff0) = seq_number_bits")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "RA copy of 0x30 bytes runs past the page "
                "buffer, only RA+0x10 (in page) is used: shift 0x10"},
                desc="restart_area_offset 0xfe0 (not bounds-checked; the 0x30-byte copy crosses the page end), snb 0x30")


@case("ra-offset-8", "synth-01")
def c_ra_8(rng):
    d, m = synth_copy(), Mut()
    set_rstr(d, m, PAGE, ra_offset=8)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "RA+0x10 = header dword at 0x18 = "
                "ra_offset | minor << 16 = 8 -> shift 0x38"},
                desc="restart_area_offset 8 in the winning RSTR: seq_number_bits read from the RSTR header itself")


@case("ra-fields-ignored", "synth-01")
def c_ra_ign(rng):
    d, m = synth_copy(), Mut()
    for pg in (0, PAGE):
        set_rstr(d, m, pg, current_lsn=0xDEADBEEF00, log_clients=5, ra_flags=0xFFFF, file_size=0x10000,
                 last_lsn_data_length=0x1234, rec_hdr_len=0x58, log_page_data_offset=0x80, open_count=0xFFFFFFFF)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "only RA+0x10 is used: output = synth-01"},
                desc="restart-area fields other than seq_number_bits (current_lsn, file_size, data offset...) "
                     "rewritten: must be ignored")


# =============================================================================================== RCRD page set
@case("pages-exact-0x20", "synth-01")
def c_exact20(rng):
    d, m = synth_copy()[:0x30000], Mut()
    m.note(op="truncate", new_length=0x30000, rcrd_pages=0x20)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "no regular page: min = max = 0, every "
                "special with last_lsn != 0 goes to F0 (9 tied pairs), prevB = |F0|"},
                desc="v2.0 with exactly 0x20 RCRD pages: empty regular set, all specials in F0 with equal-key ties")


@case("pages-0x21", "synth-01")
def c_21(rng):
    d, m = synth_copy()[:0x31000], Mut()
    m.note(op="truncate", new_length=0x31000, rcrd_pages=0x21)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "one regular page: min = max = its last_lsn"},
                desc="v2.0 with 0x21 RCRD pages: a single regular page decides DC/F0")


@case("pages-baad", "synth-01")
def c_baad(rng):
    d, m = synth_copy(), Mut()
    for off in (0xD000, 0xE000, 0x17000, 0x18000, 0x19000):
        m.put(d, off, 4, int.from_bytes(b"BAAD", "little"), f"page {hex(off)} signature RCRD -> BAAD")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "5 fewer RCRD pages before 0x20: the first "
                "5 regular pages become specials (DC)"},
                desc="'BAAD' signatures on 5 tail-copy pages shift the b4 ordinals: regular pages move into the "
                     "special set")


@case("pages-zeroed", "synth-01")
def c_zeroed(rng):
    d, m = synth_copy(), Mut()
    for off in (0x24000, 0x50000, 0x51000):
        d[off:off + PAGE] = bytes(PAGE)
        m.note(op="zero_page", off=off)
    return dict(log=d, mft=False, mutation={"edits": m.edits},
                desc="zero-filled pages (one special, two regular): ignored by the scan, spans into them break")


@case("pages-foreign-sig", "synth-01")
def c_foreign(rng):
    d, m = synth_copy(), Mut()
    sigs = [(0x60000, b"RCRD\x28\x00\x08\x00"), (0x61000, b"RCRD\x30\x00\x09\x00"), (0x70000, b"RCRD\x28\x00\x09\x01"),
            (0x71000, b"rcrd\x28\x00\x09\x00"), (0x80000, b"FILE0\x00\x03\x00"), (0x90000, b"RSTR\x1e\x00\x09\x00")]
    for off, sg in sigs:
        old = bytes(d[off:off + 8])
        d[off:off + 8] = sg
        m.note(op="signature", off=off, old=old.hex(), new=sg.hex())
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "all six pages ignored (not 'RCRD' 28 00 09 00, "
                "and the RSTR one is not strict)"},
                desc="foreign signatures / usa variants (usa_count 8, usa_ofs 0x30, count 0x109, 'rcrd', FILE, RSTR)")


@case("partial-last-0x800", "synth-01")
def c_partial800(rng):
    d, m = synth_copy()[:0xBF800], Mut()
    m.note(op="truncate", new_length=0xBF800, last_page=0xBF000)
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "last RCRD page half read: bytes 0x800.. are "
                "stale (scan: raw 0xbe000; traversal: fixed-up previous listed page)"},
                desc="file length not a multiple of 0x1000: last RCRD page cut at 0x800, stale buffer tail")


@case("partial-rcrd4", "synth-01")
def c_partial4(rng):
    d, m = synth_copy()[:0xC0000], Mut()
    d += b"RCRD"
    m.note(op="truncate+append", new_length=len(d), tail="'RCRD' (4 bytes)")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "bytes 4..8 come from the previous page "
                "(28 00 09 00): classified RCRD with 0xbf000's header; traversal re-parses the stale buffer"},
                desc="4-byte 'RCRD' tail page: signature completed by stale buffer bytes, a phantom duplicate page")


@case("trailing-garbage", "synth-01")
def c_garbage(rng):
    d, m = synth_copy(), Mut()
    reg = synth_regular()
    kinds = ["random", "rcrd+random", "ff", "zero", "copy+last_lsn+0x10", "copy+random tail"]
    for k in range(24):
        kind = k % 6
        if kind == 0:
            pg = bytes(rng.getrandbits(8) for _ in range(PAGE))
        elif kind == 1:
            pg = bytearray(rng.getrandbits(8) for _ in range(PAGE))
            pg[0:8] = RCRD
            p64(pg, 8, rng.choice([0x117FF7 + k, 0x105000 + k, rng.getrandbits(64), 0]))
            p64(pg, 0x20, 0x100000 + rng.getrandbits(20))
        elif kind == 2:
            pg = b"\xff" * PAGE
        elif kind == 3:
            pg = bytes(PAGE)
        elif kind == 4:
            src = rng.choice(reg)
            pg = bytearray(d[src:src + PAGE])
            p64(pg, 8, g64(pg, 8) + 0x10)
        else:
            src = rng.choice(reg)
            pg = bytearray(d[src:src + PAGE])
            pg[0x200:0x1000] = bytes(rng.getrandbits(8) for _ in range(0xE00))
        m.note(op="append_page", index=k, kind=kinds[kind], off=len(d))
        d += pg
    return dict(log=d, mft=False, mutation={"edits": m.edits},
                desc="24 trailing pages: random, RCRD-signed random (various last_lsn), 0xFF, zero, edited copies")


def _partial_first():
    """Pieces for the 'partial last page listed first' cases (see c_partial_first)."""
    recs = Base.synth_records()
    L = 0x800
    P = Builder()
    i = 0
    while P.off + len(recs[i]) <= L - 0x38:
        P.add(recs[i])
        i += 1
    P.filler(L - P.off)
    hf = i
    hid = Builder()
    hid.skip_to(L)
    while len(recs[i]) > PAGE - 0x40 - L:  # records too long for the hidden half are dropped
        i += 1
    hs = i
    while hid.off + len(recs[i]) <= PAGE - 0x40:
        hid.add(recs[i])
        i += 1
    ht = i
    assert ht > hs
    main = Builder()
    for r in recs[i + 5:]:
        main.add(r)
    regs = builder_pages(main)
    q = Builder()
    q.last_lsn = main.last_lsn
    q.filler(0x70)
    qlog = builder_pages(q)[0]
    plog = builder_pages(P)[0]
    p64(plog, 8, rec_lsn(recs[0]) - 0x100)  # smallest last_lsn: own group, listed first, DC stays empty
    return L, hf, hs, ht, regs, qlog, bytearray(hid.pages[0]), plog


@case("partial-first-listed", "built(synth-01 records)")
def c_partial_first(rng):
    L, hf, hs, ht, regs, qlog, hidden, plog = _partial_first()
    qlog[L:] = hidden[L:]  # Q carries the hidden records after a zero gap (unreachable when Q itself is walked)
    plog[L:] = qlog[L:]  # P's USA for sectors >= L then holds Q's logical sector-end bytes
    out = file_from(regs + [qlog])
    out += protect(plog, 0x7777)[:L]
    return dict(log=out, mft=True, mutation={
        "layout": "RSTR(synth) + 0x20 dropped copies + built pages + Q + partial page P (0x800 bytes)",
        "P": f"records idx 0..{hf - 1} + Noop filler ending at 0x800; last_lsn forced below every page (own group, "
             f"listed first, no DC)",
        "Q": f"last full page: one Noop record, zeros, then records idx {hs}..{ht - 1} at 0x800.. (records idx "
             f"{hf}..{hs - 1} are too long and are left out)",
        "expect": "original: the first listed page P is read into the buffer that still holds Q (scan leftover), so "
                  "P[0x800:] = Q[0x800:] and the hidden records are parsed; a zero-initialised buffer ends P at 0x800"},
        desc="partial last page listed FIRST: its stale tail is the scan's leftover (previous file page), which "
             "holds hidden valid records")


@case("v11-partial-first", "built(synth-01 records)")
def c_v11_partial_first(rng):
    L, hf, hs, ht, regs, qlog, hidden, plog = _partial_first()
    sd, _ = Base.synth()
    rstr = bytearray(sd[:2 * PAGE])
    m = Mut()
    set_rstr(rstr, m, 0, major=1, minor=1)
    set_rstr(rstr, m, PAGE, major=1, minor=1)
    bp1 = bytearray(regs[3])
    p64(bp1, 0x20, 1)
    bp2 = bytearray(regs[4])
    bp2[L:] = hidden[L:]
    p64(bp2, 0x20, 2)
    plog[L:] = bp2[L:]
    out = file_from(regs + [qlog], specials=[bp1, bp2], rstr=rstr)
    out += protect(plog, 0x7777)[:L]
    return dict(log=out, mft=False, mutation={
        "edits": m.edits,
        "layout": "RSTR v1.1 + bp1 + bp2 + built pages + Q + partial page P (0x800 bytes)",
        "bp": f"bp1 = copy of page 3 with A = 1, bp2 = copy of page 4 with records idx {hs}..{ht - 1} at 0x800.. "
              f"and B = 2; M > A, B -> neither appended, prevB = 1",
        "expect": "original: the v1.1 bp1/bp2 re-reads use the page buffer, so P (first listed, partial) inherits "
                  "bp2[0x800:] and parses the hidden records"},
        desc="v1.1: partial last page listed first inherits the bp2 re-read left in the page buffer")


# =============================================================================================== page ordering
@case("order-reverse", "synth-01")
def c_reverse(rng):
    d, m = synth_copy(), Mut()
    reg = synth_regular()
    pages = [bytes(d[o:o + PAGE]) for o in reg]
    for o, pg in zip(reg, reversed(pages)):
        d[o:o + PAGE] = pg
    m.note(op="reverse_regular_pages", first=reg[0], last=reg[-1], count=len(reg))
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "every page its own group (decreasing): "
                "144-element qsort (median-of-three partitions) restores LSN order"},
                desc="regular pages physically reversed: one group per page, large MSVC qsort of group keys")


@case("order-shuffle-blocks", "synth-01")
def c_shuffle(rng):
    d, m = synth_copy(), Mut()
    reg = synth_regular()
    pages = [bytes(d[o:o + PAGE]) for o in reg]
    blocks, k = [], 0
    while k < len(pages):
        n = rng.randint(1, 8)
        blocks.append(list(range(k, min(k + n, len(pages)))))
        k += n
    rng.shuffle(blocks)
    order = [i for b in blocks for i in b]
    for o, i in zip(reg, order):
        d[o:o + PAGE] = pages[i]
    m.note(op="shuffle_regular_blocks", new_order_src_offsets=[hex(reg[i]) for i in order])
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="regular pages shuffled in blocks of 1..8: many runs/groups, spans broken at block edges")


@case("order-dup-group-ties", "synth-01")
def c_dup_ties(rng):
    d, m = synth_copy(), Mut()
    reg = synth_regular()
    x_off, xr = ranked_pages(6)[0]
    hi = reg[-1]
    base = 0xC0000
    delta = 8 << 19
    xpage = unprotect(d[x_off:x_off + PAGE])
    for c in range(12):
        hdst, cdst = base + 2 * c * PAGE, base + (2 * c + 1) * PAGE
        d[hdst:hdst + PAGE] = d[hi:hi + PAGE]
        lp = bytearray(xpage)
        for r in xr:
            for fo in (0, 8, 0x10):
                if r["pos"] + fo + 8 <= PAGE:
                    v = g64(lp, r["pos"] + fo)
                    if v:
                        p64(lp, r["pos"] + fo, v + delta)
            if r["pos"] + 0x46 <= PAGE:
                p16(lp, r["pos"] + 0x44, 0x100 + c)
        p64(lp, 0x20, g64(lp, 0x20) + delta)
        d[cdst:cdst + PAGE] = protect(lp, 0x4000 + c)
        m.note(op="copy", high_page_src=hi, high_page_dst=hdst, copy_of=x_off, copy_dst=cdst, copy_index=c)
    m.note(edit_in_copies="LSN/prev/undo_next of the copied page's records + 0x400000 (new LSNs, same in every "
           "copy), cluster_block_offset = 0x100 + copy index, last_end_lsn + 0x400000, last_lsn unchanged")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "12 groups [copy_c, high] with the SAME key "
                "after the main group: the MSVC qsort tie order picks which copy inserts the new LSNs first "
                "(MFT_ClusterIndex 0x100+c shows the winner)"},
                desc="12 equal-key groups (CUTOFF 8 exceeded: median-of-three partition) whose pages differ: "
                     "unstable qsort tie order decides first-insert-wins")


def _plausible(lp, pos):
    return g64(lp, pos) >> 19 == g64(lp, 0x20) >> 19 and g32(lp, pos + 0x20) in (1, 2) and g64(lp, pos) != 0


@case("order-dc-ties-edited", "synth-01")
def c_dc_ties(rng):
    d, m = synth_copy(), Mut()
    b4 = b4_offsets(d)
    for a in range(8, 17):
        b = a + 13
        assert g64(d, b4[a] + 8) == g64(d, b4[b] + 8)
        for idx, val in ((a, 0x8000), (b, 0x9000)):
            off = b4[idx]

            def fn(lp, idx=idx, val=val, off=off):
                for pos in walk_headers(lp, _plausible):
                    p16(lp, pos + 0x44, val + idx)
                    m.note(page=off, b4=idx, rec=pos, lsn=g64(lp, pos), field="cluster_block_offset", new=val + idx)
            edit_page(d, off, fn)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "DC has 9 equal-last_lsn pairs (b4[k], "
                "b4[k+13]); the MSVC order (21,8),(22,9),(23,10),(11,24)... decides which copy inserts first"},
                desc="synth-01 DC tie pairs made distinguishable (cluster_block_offset 0x8000+k vs 0x9000+k): "
                     "verbatim qsort tie order on real data")


@case("order-f0-ties", "synth-01")
def c_f0_tie(rng):
    d, m = synth_copy(), Mut()
    b4 = b4_offsets(d)
    m.put(d, b4[0] + 8, 8, g64(d, b4[5] + 8), "b4[0] last_lsn = b4[5] last_lsn (F0 tie)")
    m.put(d, b4[7] + 8, 8, g64(d, b4[6] + 8), "b4[7] last_lsn = b4[6] last_lsn (F0 tie)")
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "F0 (6 pages) shortsort with two ties: order of "
                "different tail pages at the end of the list"},
                desc="F0 pages with equal last_lsn but different content: shortsort tie order at the list end")


@case("order-zero-lastlsn", "synth-01")
def c_zero_last(rng):
    d, m = synth_copy(), Mut()
    for off in (0x50000, 0x51000, 0x80000):
        m.put(d, off + 8, 8, 0, f"page {hex(off)} last_lsn = 0")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "zero last_lsn joins the current run and "
                "drives min to 0: DC becomes empty (26 tail pages dropped)"},
                desc="zero last_lsn on 3 regular pages: joins the run, min = 0 empties the DC list")


@case("order-backwards", "synth-01")
def c_backwards(rng):
    d, m = synth_copy(), Mut()
    m.put(d, 0x70000 + 8, 8, 0x104000, "page 0x70000 last_lsn below every other page")
    m.put(d, 0x90000 + 8, 8, g64(d, 0x8F000 + 8) - 1, "page 0x90000 last_lsn = predecessor - 1")
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "groups [0x30000..), [0x70000..), "
                "[0x90000..): key 0x104000 sorts first, DC shrinks (min = 0x104000)"},
                desc="last_lsn going backwards: one page below min (its run is listed first), one just below its "
                     "predecessor")


@case("order-max-ffff", "synth-01")
def c_max_ffff(rng):
    d, m = synth_copy(), Mut()
    m.put(d, 0x60000 + 8, 8, 0xFFFFFFFFFFFFFFFF, "page 0x60000 last_lsn = ~0")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "max = ~0: F0 empty (newest tail pages "
                "dropped), prevB = 0; the next page starts a new group"},
                desc="regular last_lsn 0xFFFFFFFFFFFFFFFF: max saturates, F0 empty, group split after it")


@case("order-dcf0-boundaries", "synth-01")
def c_bounds(rng):
    d, m = synth_copy(), Mut()
    b4 = b4_offsets(d)
    reg = b4[0x20:]
    mn = min(g64(d, o + 8) for o in reg)
    mx = max(g64(d, o + 8) for o in reg)
    m.put(d, b4[3] + 8, 8, mn, "b4[3] last_lsn = min (dropped)")
    m.put(d, b4[4] + 8, 8, mn - 1, "b4[4] last_lsn = min-1 (DC)")
    m.put(d, b4[16] + 8, 8, mx, "b4[16] last_lsn = max (dropped)")
    m.put(d, b4[17] + 8, 8, mx + 1, "b4[17] last_lsn = max+1 (F0: old content listed at the end)")
    return dict(log=d, mft=True, mutation={"edits": m.edits, "min": hex(mn), "max": hex(mx)},
                desc="special pages at the DC/F0 boundaries: last_lsn == min, min-1, == max, max+1")


@case("u01-wrap-slice", "user-01 slice")
def c_u01(rng):
    d, info = Base.user01_wrap()
    return dict(log=bytearray(d), mft=False, mutation={"slice": info, "expect": "2 groups (wrap), hi40 change "
                "0x4a16 -> 0x4a17 at the group switch (neighbourhood recovery)"},
                desc="user-01 wrap-around slice (2 groups, large LSNs, live hi40 tests), unmodified")


@case("u01-group-3tie", "user-01 slice")
def c_u01_tie(rng):
    d, info = Base.user01_wrap()
    d, m = bytearray(d), Mut()
    w = info["wrap_index_in_slice"]
    k = min(g64(d, o + 8) for o in range(0x22 * PAGE, len(d), PAGE)) - 1
    for idx, why in ((0x22, "first regular page (group A1 key)"), (0x22 + 80, "mid A: starts group A2"),
                     (w, "wrap page: group B key")):
        m.put(d, idx * PAGE + 8, 8, k, f"slice page {hex(idx)} last_lsn = K ({why})")
    return dict(log=d, mft=False, mutation={"edits": m.edits, "slice": info, "expect": "3 groups with key K: shortsort "
                "of 3 equal keys gives [A2, B, A1] (stable: A1, A2, B; unmodified: B, A1+A2)"},
                desc="user-01 slice with three equal group keys: shortsort tie order changes the traversal order")


def _u01_hdr_ok(lp, pos):
    return g64(lp, pos) >> 24 == g64(lp, 8) >> 24 and g64(lp, pos) and g32(lp, pos + 0x20) in (1, 2)


def _u01_dups(n_f0, ranked=False):
    d, info = Base.user01_wrap()
    d, m = bytearray(d), Mut()
    w = info["wrap_index_in_slice"]
    regs = list(range(0x22 * PAGE, len(d), PAGE))
    mn = min(g64(d, o + 8) for o in regs)
    mx = max(g64(d, o + 8) for o in regs)
    if ranked:  # pages richest in InitFRS / DeallocFRS / Create- / DeleteAttribute records (stable sort by offset)
        sc = sorted(regs, key=lambda o: -sum(1 for q in walk_headers(unprotect(d[o:o + PAGE]), _u01_hdr_ok)
                                             if g16(unprotect(d[o:o + PAGE]), q + 0x30) in (2, 3, 5, 6)))
        srcs = sc[:4 + n_f0]
    else:
        srcs = [(w + 5 + 3 * j) * PAGE for j in range(4)] + [(0x22 + 40 + 3 * j) * PAGE for j in range(n_f0)]
    for j, src in enumerate(srcs):
        dst = (2 + j) * PAGE
        lp = unprotect(d[src:src + PAGE])
        n = 0
        for pos in walk_headers(lp, _u01_hdr_ok):
            p16(lp, pos + 0x44, 0xA00 + j)
            n += 1
        p64(lp, 8, (mn - 1 - j) if j < 4 else (mx + 1 + j))
        d[dst:dst + PAGE] = protect(lp, 0x5000 + j)
        m.note(op="tail_copy", src=src, dst=dst, edited_records=n, new_last_lsn=g64(lp, 8),
               edit="cluster_block_offset = 0xa00+j on walked records",
               listed="DC (first: edited copy inserts first)" if j < 4 else "F0 (last: duplicates rejected)")
    return d, m, info


@case("u01-tail-dups", "user-01 slice")
def c_u01_dups(rng):
    d, m, info = _u01_dups(4)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "slice": info},
                desc="tail-copy pages duplicating regular pages with edited content: DC copies insert first, F0 "
                     "copies are rejected duplicates (first insert wins); consecutive F0 copies are not contiguous, "
                     "so a record spilling from one copy into the next lands on unrelated bytes")


@case("u01-tail-dups-1f0", "user-01 slice")
def c_u01_dups_1f0(rng):
    d, m, info = _u01_dups(1, ranked=True)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "slice": info,
                                            "sources": "the 5 regular pages with the most redo ops 2/3/5/6"},
                desc="as u01-tail-dups with a single F0 copy (listed last, nothing after it) and row-rich source "
                     "pages: DC copies insert first, the F0 copy's records are rejected duplicates (first insert "
                     "wins)")


# =============================================================================================== traversal (synth)
def _pick(rp, n, pred):
    out = []
    for off, rs in rp:
        if pred(off, rs):
            out.append((off, rs))
            if len(out) == n:
                break
    return out


@case("t-lastlsn-mid", "synth-01")
def c_lastlsn_mid(rng):
    d, m = synth_copy(), Mut()
    for off, rs in _pick(ranked_pages(6), 3, lambda o, rs: rs[2]["pos"] + 0x30 + rs[2]["cdl"] < 0xF00):
        m.put(d, off + 8, 8, rs[2]["lsn"], f"page {hex(off)} last_lsn = LSN of its 3rd record (at {hex(rs[2]['pos'])})")
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "this_lsn == PI.last_lsn after the 3rd record: "
                "NEXT_PAGE with curOff kept, the next page starts at that offset"},
                desc="page last_lsn equal to a mid-page record's LSN (edge 7): rest of page skipped, curOff carried")


@case("t-zero16-vs-15", "synth-01")
def c_zero16(rng):
    d, m = synth_copy(), Mut()
    picks = _pick(ranked_pages(6)[3:], 3, lambda o, rs: rs[3]["pos"] + 0x58 <= PAGE)
    for k, (off, rs) in enumerate(picks):
        pos = rs[3]["pos"]

        def fn(lp, pos=pos, k=k, off=off):
            if k == 0:
                lp[pos:pos + 16] = bytes(16)
                m.note(page=off, rec=pos, what="16 zero bytes at the header (END_ZERO)")
            elif k == 1:
                lp[pos:pos + 16] = bytes(15) + b"\x01"
                m.note(page=off, rec=pos, what="15 zero bytes + 0x01 (not END_ZERO; then LSN 0 with fip 0)")
            else:
                lp[pos:pos + 8] = bytes(8)
                m.note(page=off, rec=pos, what="LSN 0 only, prev LSN kept")
        edit_page(d, off, fn)
    return dict(log=d, mft=False, mutation={"edits": m.edits},
                desc="16 zero bytes vs 15 zero bytes vs zero LSN after a record (END_ZERO vs this_lsn == 0 && !fip)")


@case("t-cdl0", "synth-01")
def c_cdl0(rng):
    d, m = synth_copy(), Mut()
    rp = ranked_pages(5)
    mid = _pick(rp[6:], 1, lambda o, rs: True)[0]
    first = _pick(rp[6:], 2, lambda o, rs: rs[0]["pos"] == 0x40)[-1]

    def fmid(lp):
        p32(lp, mid[1][2]["pos"] + 0x18, 0)
        m.note(page=mid[0], rec=mid[1][2]["pos"], what="cdl = 0 (mid page, fip 0 -> next page)")
    edit_page(d, mid[0], fmid)

    def ffirst(lp):
        pos = first[1][0]["pos"]
        p32(lp, pos + 0x18, 0)
        p16(lp, pos + 0x34, 0)
        m.note(page=first[0], rec=pos, what="first record of the page: cdl = 0, redo_offset = 0 (order recovery; "
               "FindFirst returns the same header, accepted with cdl 0)")
    edit_page(d, first[0], ffirst)
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="client_data_length 0 mid-page (order test) and on a page's first record (FindFirst accepts it)")


@case("t-lsn-backwards", "synth-01")
def c_lsn_back(rng):
    d, m = synth_copy(), Mut()
    rp = ranked_pages(5)
    mid = _pick(rp[9:], 1, lambda o, rs: True)[0]
    first = _pick(rp[9:], 2, lambda o, rs: rs[0]["pos"] == 0x40)[-1]

    def fmid(lp):
        r = mid[1][3]
        p64(lp, r["pos"], mid[1][2]["lsn"] - 1)
        m.note(page=mid[0], rec=r["pos"], what="LSN = previous record's LSN - 1", old=r["lsn"])
    edit_page(d, mid[0], fmid)
    prev_last = g64(d, first[0] - PAGE + 8)

    def ffirst(lp):
        r = first[1][0]
        p64(lp, r["pos"], prev_last - 1)
        m.note(page=first[0], rec=r["pos"], what="first record LSN = previous page last_lsn - 1 (< prevB, fip 1)",
               old=r["lsn"])
    edit_page(d, first[0], ffirst)
    return dict(log=d, mft=False, mutation={"edits": m.edits},
                desc="LSN below prevB mid-page (next page) and on a page's first record (FindFirst bypasses the "
                     "order test)")


@case("t-lsn-ff", "synth-01")
def c_lsn_ff(rng):
    d, m = synth_copy(), Mut()
    mid = _pick(ranked_pages(5)[12:], 1, lambda o, rs: True)[0]

    def fmid(lp):
        p64(lp, mid[1][3]["pos"], 0xFFFFFFFFFFFFFFFF)
        m.note(page=mid[0], rec=mid[1][3]["pos"], what="LSN = ~0 mid page")
    edit_page(d, mid[0], fmid)
    hs = [(off, r) for off in synth_regular() for r in page_recs(d, off) if r["pos"] + 0x58 > PAGE]
    off, r = hs[len(hs) // 2]

    def fhs(lp):
        p64(lp, r["pos"], 0xFFFFFFFFFFFFFFFF)
        m.note(page=off, rec=r["pos"], what="header-split record LSN = ~0 (prevA = prevB = ~0, path A stops)")
    edit_page(d, off, fhs)
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="LSN 0xFFFFFFFFFFFFFFFF on a normal record and on a header-split record (path A ~0 exit)")


@case("t-unknown-ops", "synth-01")
def c_ops(rng):
    d, m = synth_copy(), Mut()
    ml = mft_lsns()
    pairs = [(0x10, 0x11), (0x17, 0x18), (0x1D, 0x1E), (0x22, 0), (0xFF, 0x100), (0xFFFF, 0xFFFF), (0x21, 0x1F),
             (0x1C, 0x1B), (0x12, 0x10), (0x100, 0x2), (0x8000, 0x7), (0x1B, 0x1B)]
    cands = [(off, r) for off in synth_regular() for r in page_recs(d, off)
             if r["pos"] + 0x34 <= PAGE and r["lsn"] in ml]
    step = max(1, len(cands) // len(pairs))
    for (redo, undo), (off, r) in zip(pairs, cands[::step]):
        def fn(lp, r=r, redo=redo, undo=undo):
            p16(lp, r["pos"] + 0x30, redo)
            p16(lp, r["pos"] + 0x32, undo)
        edit_page(d, off, fn)
        m.note(page=off, rec=r["pos"], lsn=r["lsn"], redo=redo, undo=undo, old_redo=r["redo"],
               why="LSN has an $MFT FILE record: row kept through FileName even without an event")
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="redo/undo op codes outside the name table (0x10, 0x17, 0x1d, 0x22, 0xff, 0x100, 0xffff...) on "
                     "rows kept by the $MFT FileName: RedoInfo '0x%x'")


@case("t-rtype-flags", "synth-01")
def c_rtype(rng):
    d, m = synth_copy(), Mut()
    first = b4_offsets(d)[18]  # first listed page (DC[0]): FindFirst runs here
    edits = [("rtype", 3), ("flags", 2), ("rtype", 0xFFFFFFFF), ("flags", 0xFFFF)]

    def ff(lp):
        for (f, v), pos in zip(edits, walk_headers(lp, _plausible)):
            if f == "rtype":
                p32(lp, pos + 0x20, v)
            else:
                p16(lp, pos + 0x28, v)
            m.note(page=first, rec=pos, lsn=g64(lp, pos), field=f, new=v)
    edit_page(d, first, ff)
    for off, rs in _pick(ranked_pages(5)[15:], 2, lambda o, rs: True):
        def fn(lp, rs=rs, off=off):
            for j, r in enumerate(rs[1:4]):
                if r["pos"] + 0x24 <= PAGE:
                    p32(lp, r["pos"] + 0x20, [0, 2, 7][j])
                    m.note(page=off, rec=r["pos"], field="rtype", new=[0, 2, 7][j])
        edit_page(d, off, fn)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "FindFirst on the first listed page skips "
                "records whose record_type is not 1/2 or flags not 0/1; mid-page values are not tested"},
                desc="record_type 0/3/7/~0 and flags 2/0xffff: FindFirst rejects them, the normal walk does not")


@case("t-cdl-lt-redo", "synth-01")
def c_cdl_lt_redo(rng):
    d, m = synth_copy(), Mut()
    off, rs = ranked_pages(6)[20]

    def fn(lp):
        r = rs[3]
        m.note(page=off, rec=r["pos"], what="cdl 0x10 < redo_offset (memcpy size cdl - redo_off negative)",
               old=r["cdl"], redo_off=g16(lp, r["pos"] + 0x34))
        p32(lp, r["pos"] + 0x18, 0x10)
    edit_page(d, off, fn)
    return dict(log=d, mft=False, mutation={"edits": m.edits, "expect": "memcpy at 0x411001 with a huge size: crash"},
                desc="client_data_length below redo_offset on an in-page record (edge 11, crash candidate)")


@case("t-redo-undo-oob", "synth-01")
def c_redo_oob(rng):
    d, m = synth_copy(), Mut()
    ml = mft_lsns()
    cands = [(off, r) for off in synth_regular() for r in page_recs(d, off)
             if r["pos"] + 0x30 + r["cdl"] <= PAGE and r["redo"] in (2, 0xE, 7, 3) and r["cdl"] > 0x30]
    step = max(1, len(cands) // 6)
    whats = ["redo_length 0xffff", "redo_offset = cdl (empty redo buffer)", "undo_offset 0xfff8, undo_length 0xffff",
             "redo_offset = cdl - 8 (8 bytes of redo data)", "redo_offset 0x29 (odd)",
             "redo_length 4*cdl (past the record and the page)"]
    for k, (off, r) in enumerate(cands[::step][:6]):
        def fn(lp, r=r, k=k):
            pos, cdl = r["pos"], r["cdl"]
            if k == 0:
                p16(lp, pos + 0x36, 0xFFFF)
            elif k == 1:
                p16(lp, pos + 0x34, cdl)
            elif k == 2:
                p16(lp, pos + 0x38, 0xFFF8)
                p16(lp, pos + 0x3A, 0xFFFF)
            elif k == 3:
                p16(lp, pos + 0x34, cdl - 8)
            elif k == 4:
                p16(lp, pos + 0x34, 0x29)
            else:
                p16(lp, pos + 0x36, cdl * 4)
        edit_page(d, off, fn)
        m.note(page=off, rec=r["pos"], lsn=r["lsn"], redo_op=r["redo"], what=whats[k], mft_v40=r["lsn"] in ml)
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="redo/undo offsets and lengths out of range on row-producing records (buffer starts at "
                     "redo_offset, length cdl - redo_offset)")


# =============================================================================================== traversal (built logs)
class Lay:
    """Builder over the synth-01 records in LSN order, with helpers to reach a record index and document layout."""

    def __init__(self):
        self.recs = Base.synth_records()
        self.rows = row_recs(self.recs)
        self.b = Builder()
        self.i = 0
        self.notes = []

    def upto(self, t):
        while self.i < t:
            self.b.add(self.recs[self.i])
            self.i += 1

    def take(self):
        r = self.recs[self.i]
        self.i += 1
        return r

    def rest(self):
        self.upto(len(self.recs))

    def note(self, **kw):
        self.notes.append({k: (hex(v) if isinstance(v, int) and not isinstance(v, bool) else v) for k, v in kw.items()})

    def at(self):
        return {"page": len(self.b.pages) - 1, "off": hex(self.b.off)}

    def row_at(self, frac):
        return self.rows[int(len(self.rows) * frac)]


def built(lay, mft, desc, **extra):
    return dict(log=assemble(lay.b), mft=mft, desc=desc,
                mutation=dict(layout="RSTR(synth-01) + 0x20 copies of regular pages (dropped) + built pages; page N "
                                     "of the notes is at file offset (0x22 + N) * 0x1000", notes=lay.notes, **extra))


@case("b-hsplit-sweep", "built(synth-01 records)")
def c_hsplit(rng):
    L = Lay()
    ks = [0x30, 0x31, 0x33, 0x36, 0x37, 0x38, 0x3C, 0x41, 0x44, 0x48, 0x4F, 0x50, 0x54, 0x55, 0x57, 0x58]
    for n, k in enumerate(ks):
        L.upto(L.row_at(0.1 + 0.05 * n))
        L.b.place_at(PAGE - k)
        st = L.b.add(L.take())
        L.note(rec=L.i - 1, lsn=rec_lsn(L.recs[L.i - 1]), page=st[0], header_at=st[1], k=k,
               what="header split (k = bytes of the 0x58-byte header left in the page)" if k < 0x58 else
               "header exactly fits (0xfa8, no split)")
    L.rest()
    return built(L, True, "header splits at k = 0x30..0x58 (aligned and unaligned savedOff), each on a "
                          "row-producing record")


@case("b-bodyspan-sweep", "built(synth-01 records)")
def c_bodyspan(rng):
    L = Lay()
    ends = [0x48, 0x70, 0x101, 0x400, 0x7FF, 0xC00, 0xFA8, 0xFA9, 0xFB0, 0xFCF, 0xFD0, 0xFD1, 0xFF8, 0xFFF, 0x1000]
    for n, e in enumerate(ends):
        L.upto(L.row_at(0.08 + 0.055 * n))
        r = L.take()
        cdl2 = max(len(r) - 0x30, (e - 0x40) + PAGE - 0xFA8 - 0x30)
        s = PAGE + (e - 0x40) - (0x30 + cdl2)
        L.b.place_at(s)
        st = L.b.add(with_cdl(r, cdl2))
        L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=st[1], cdl=cdl2, ends_next_page_at=e,
               path="q=1 multi-page (ends exactly at the next page end)" if e == PAGE else
               "BODY_SPAN q=0" + ("; next header split" if 0xFA8 < e <= 0xFD0 else "") +
               ("; < 0x30 left -> next page" if e > 0xFD0 else ""))
    L.upto(L.row_at(0.93))
    r = L.take()
    L.b.place_at(PAGE - len(r))
    st = L.b.add(r)
    L.note(rec=L.i - 1, page=st[0], header_at=st[1], path="EXACT_END (record ends at 0x1000 of its own page)")
    L.rest()
    return built(L, False, "body spans ending at many offsets of the next page (0x48..0xfff, 0x1000 = q 1) and "
                           "EXACT_END; spanning records padded to the needed client_data_length")


@case("b-multipage", "built(synth-01 records)")
def c_multipage(rng):
    L = Lay()
    ml = mft_lsns()
    v40 = [i for i in L.rows if rec_lsn(L.recs[i]) in ml]
    plan = [(1, 0x300, True), (2, 0x800, True), (3, 0x100, True), (1, 0xFE0, True), (2, 0x500, False),
            (1, 0xFD8, False)]
    for n, (q, e, want_v40) in enumerate(plan):
        if want_v40:
            t = next(i for i in v40 if i >= L.row_at(0.1 + 0.13 * n))
        else:
            t = next(i for i in L.rows if i >= L.row_at(0.1 + 0.13 * n) and rec_lsn(L.recs[i]) not in ml)
        L.upto(t)
        r = L.take()
        s = 0x200
        ovf = q * 0xFC0 + (e - 0x40)
        cdl2 = ovf + 0xFD0 - s
        L.b.place_at(s)
        st = L.b.add(with_cdl(r, cdl2))
        L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=s, cdl=cdl2, q=q, ends_at=e, mft_v40=want_v40,
               path="multi-page skip (no ProcessLogRecord; emitted only with a V40 FileName)" +
               ("; < 0x30 left -> one more page" if e > 0xFD0 else ""))
    L.rest()
    return built(L, True, "multi-page records q = 1, 2, 3 (+1 page when < 0x30 bytes are left), with and without "
                          "an $MFT V40 FileName")


def _hs_exact(k):
    L = Lay()
    L.upto(L.row_at(0.35))
    r = L.take()
    saved = PAGE - k
    cdl2 = 0x1F90 - saved
    L.b.place_at(saved)
    st = L.b.add(with_cdl(r, cdl2))
    L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=saved, k=k, cdl=cdl2,
           path="HS_EXACT_END: span stays 1, every later page re-runs path A with the stale savedOff/tmpHdr")
    L.rest()
    return L


@case("b-hs-exact-end", "built(synth-01 records)")
def c_hs_exact(rng):
    return built(_hs_exact(0x50), True, "header-split record ending exactly at the next page end (edge 8): span "
                                        "is not cleared, the stale header is re-accepted on every later page")


@case("b-hs-exact-end-k30", "built(synth-01 records)")
def c_hs_exact30(rng):
    return built(_hs_exact(0x30), False, "HS_EXACT_END with k = 0x30 < 0x36: the stale header's redo_offset comes "
                                         "from each new page")


def _zero_tail(e):
    L = Lay()
    L.upto(L.row_at(0.4))
    r = L.take()
    cdl2 = max(len(r) - 0x30, (e - 0x40) + PAGE - 0xFA8 - 0x30)
    s = PAGE + (e - 0x40) - (0x30 + cdl2)
    L.b.place_at(s)
    st = L.b.add(with_cdl(r, cdl2))
    L.b.next_page()
    L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=s, cdl=cdl2, span_ends_at=e,
           then="zeros to the page end: HDR_SPLIT of a zero header (k = %#x), path A accepts LSN 0 / cdl 0, "
                "HS dispatch with cdl < 0x28 wraps in 32 bits (q = 0x104103) and ends the traversal" % (PAGE - e))
    L.rest()
    return L


@case("b-zero-tail-split", "built(synth-01 records)")
def c_zero_tail(rng):
    return built(_zero_tail(0xFB0), False, "zero-tail header split (edge 20): body span completes at 0xfb0, rest "
                                           "of page zero -> zero header accepted -> cdl < 0x28 wrap stops traversal")


@case("b-zero-tail-split-mft", "built(synth-01 records)")
def c_zero_tail_mft(rng):
    return built(_zero_tail(0xFB0), True, "zero-tail header split with $MFT: the zero header's V40 lookup uses key "
                                          "0 (5 FILE records of the $MFT have LSN 0)")


@case("b-hs-cdl-small", "built(synth-01 records)")
def c_hs_small(rng):
    L = Lay()
    L.upto(L.row_at(0.45))
    L.b.place_at(0xFC0)
    lsn = L.b.filler_lsn()
    r = mkrec(lsn, 0x20, struct.pack("<HHHHHH", 0, 0, 0x10, 0x10, 0x10, 0))
    st = L.b.add(r, lsn)
    L.note(page=st[0], header_at=st[1], lsn=lsn, cdl=0x20, redo_offset=0x10,
           path="header split k = 0x40, path A accepts (cdl >= redo_off), HS dispatch with cdl < 0x28: 32-bit "
                "wrap -> q = 0x104103 -> traversal ends")
    L.rest()
    return built(L, False, "header-split record with client_data_length 0x20 (< 0x28): the dropped carry of "
                           "cdl - 0x28 ends the traversal (edge 21)")


@case("b-hs-span-overread", "built(synth-01 records)")
def c_hs_over(rng):
    L = Lay()
    L.upto(L.row_at(0.5))
    r = L.take()
    L.b.place_at(0xFB0)
    st = L.b.add(with_cdl(r, 0x1F60))
    L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=0xFB0, cdl=0x1F60,
           path="header split + body span q = 0 with remaining = cdl - 0xf90 = 0xfd0 > 0xfc0: the completion "
                "memcpy reads 0x10 bytes past the page buffer (tmpHdr in the original)")
    L.rest()
    return built(L, True, "header split + body span whose completion reads past the 0x1000 page (edge 12)")


def _ff_tail(slot, cdl_fake):
    L = Lay()
    L.upto(L.row_at(0.5))
    while not (rec_lsn(L.recs[L.i]) >> 8) & 0xFF or not 0x60 <= len(L.recs[L.i]) <= 0x300:
        L.b.add(L.take())
    L.b.place_at(0xFB0)
    h = L.take()
    st = L.b.add(h)
    L.note(rec=L.i - 1, lsn=rec_lsn(h), page=st[0], header_at=0xFB0,
           what="last header split before the probe page: tmpHdr = this header (LSN byte 1 = %#x, byte 3 = %#x)"
                % ((rec_lsn(h) >> 8) & 0xFF, (rec_lsn(h) >> 24) & 0xFF))
    for _ in range(3):
        L.b.add(L.take())
    L.b.next_page()
    probe = L.b.pi
    bad = mkrec(L.b.filler_lsn(), 0, rtype=0)[:0x30]
    L.b.raw(bad)
    L.b.skip_to(slot)
    fake = mkrec(L.b.filler_lsn(), cdl_fake, rtype=1)[:PAGE - slot]
    L.b.raw(fake, here=True)
    L.note(page=probe, at=0x40, what="header with cdl 0 and record_type 0: order test fails with fip 1 -> "
           "FindFirst; FindFirst skips it (record_type)")
    L.note(page=probe, at=slot, what="FindFirst candidate whose fields past 0x1000 come from tmpHdr in the original "
           "(zeros in a zero-padded buffer)", cdl=cdl_fake)
    L.rest()
    return L


@case("b-findfirst-tail-fd0", "built(synth-01 records)")
def c_ff_fd0(rng):
    L = _ff_tail(0xFD0, 0x2000)
    return built(L, False, "FindFirst candidate at 0xfd0: bytes +0x31/+0x33 lie past the page (tmpHdr[1], [3] = "
                           "split LSN bytes): original rejects it, a zero tail would accept it and skip 2 pages",
                 expect="original: FindFirst 0 -> next page parsed normally")


@case("b-findfirst-tail-fd8", "built(synth-01 records)")
def c_ff_fd8(rng):
    L = _ff_tail(0xFD8, 0x2000)
    return built(L, False, "FindFirst candidate at 0xfd8: its flags dword is read from tmpHdr[0..4] (split LSN low "
                           "dword) in the original: rejected there, accepted with a zero tail",
                 expect="original: FindFirst 0 -> next page parsed normally")


@case("b-recover-negcopy", "built(synth-01 records)")
def c_negcopy(rng):
    L = Lay()
    L.upto(L.row_at(0.55))
    L.b.next_page()
    probe = L.b.pi
    L.b.raw(mkrec(L.b.filler_lsn(), 0, rtype=0)[:0x30])
    L.b.skip_to(0xFC8)
    L.b.raw(mkrec(L.b.filler_lsn(), 0x20, rtype=1)[:0x30])
    L.note(page=probe, what="cdl-0 header at 0x40 (order recovery), FindFirst returns 0xfc8 (fields in page), "
           "record cdl 0x20 crosses the page: BODY_SPAN q 0 with copied = 0xfa8 - 0xfc8 < 0")
    L.rest()
    return built(L, False, "order recovery returning an offset > 0xfa8: unbounded 0x58 copy then memcpy with "
                           "negative size (edge 10, crash candidate)")


@case("b-hood-split-k38", "built(synth-01 records)")
def c_hood(rng):
    L = Lay()
    L.upto(L.row_at(0.6))
    L.b.next_page()
    probe = L.b.pi
    L.b.raw(mkrec(0x1000000 + L.b.last_lsn, 0x10, rtype=1)[:0x30])
    L.b.skip_to(0xFC8)
    while len(L.recs[L.i]) < 0x60:
        L.i += 1
    r = L.take()
    L.b.add(r)
    L.note(page=probe, at=0x40, what="hi40 = 1 header: neighbourhood failure with fip 1 -> FindFirst")
    L.note(page=probe, at=0xFC8, lsn=rec_lsn(r), what="FindFirst hit at 0xfc8 -> HDR_SPLIT_AT(0xfc8), k = 0x38, "
           "path A on the next page")
    L.rest()
    return built(L, True, "neighbourhood recovery whose FindFirst hit needs a header split (0x41152a path, k 0x38)")


@case("b-flag-bump", "built(synth-01 records)")
def c_flag(rng):
    L = Lay()
    while L.b.pi == 0 and L.b.off < 0xE00:
        L.b.add(L.take())
    while not 0x60 <= len(L.recs[L.i]) <= 0x200:
        L.b.add(L.take())
    L.b.place_at(0xFB0)
    r = L.take()
    st = L.b.add(r)
    L.note(rec=L.i - 1, lsn=rec_lsn(r), page=st[0], header_at=0xFB0,
           what="page 0 ends with this header split; page 0 becomes a DC special page, page 1 is b4[0x20] (flag 1)")
    L.rest()
    pages = builder_pages(L.b)
    regs = pages[1:]
    specials = [pages[0]] + default_specials(regs)[:31]
    return dict(log=file_from(regs, specials=specials), mft=False,
                desc="first regular page (PageInfo flag 1) begins with a header-split continuation: flag bump "
                     "prevA = (hi40+1) << 24 ends that page (edge 15)",
                mutation={"layout": "RSTR + [built page 0 as b4[0] (DC)] + 31 dropped copies + built pages 1..",
                          "notes": L.notes})


def _shifted(delta_fn, desc, mft=False, **extra):
    L = Lay()
    probe = Builder()
    for r in L.recs:
        probe.add(r)
    x = int(len(L.recs) * 0.45)
    while probe.recs[x][2] == 0x40 or probe.recs[x - 1][1] != probe.recs[x][1]:
        x += 1
    delta = delta_fn(rec_lsn(L.recs[x]))
    L.recs = [shift_lsns(r, delta) for r in L.recs]
    L.note(delta=delta, pivot_record=x, pivot_page=probe.recs[x][1], pivot_off=probe.recs[x][2],
           pivot_new_lsn=rec_lsn(L.recs[x]))
    L.rest()
    return built(L, mft, desc, **extra)


@case("b-hi40-cross", "built(synth-01 records)")
def c_hi40(rng):
    return _shifted(lambda p: (1 << 24) - p, "all LSNs shifted so that a 2^24 boundary (hi40 change) falls "
                    "mid-page: END_HOOD, then neighbourhood recovery on the next page")


@case("b-lsn-2p63", "built(synth-01 records)")
def c_2p63(rng):
    return _shifted(lambda p: 1 << 63, "all LSNs >= 2^63: '%I64u' text above INT64_MAX is a REAL in SQLite "
                    "(PRIMARY KEY collisions within 2048, ORDER BY / CSV of REAL values)")


@case("b-lsn-cross-2p63", "built(synth-01 records)")
def c_x2p63(rng):
    return _shifted(lambda p: (1 << 63) - p, "LSNs crossing 2^63 mid-page: INTEGER rows then REAL rows (mixed "
                    "ORDER BY), hi40 change at the boundary")


@case("b-lsn-zero-fip", "built(synth-01 records)")
def c_zero_fip(rng):
    L = Lay()
    L.upto(L.row_at(0.3))
    while not 0x60 <= len(L.recs[L.i]) <= 0x200:
        L.b.add(L.take())
    L.b.place_at(0xFB0)
    L.b.add(L.take())
    z = bytearray(L.take())
    p64(z, 0, 0)
    st = L.b.add(bytes(z), 0)
    L.note(page=st[0], at=st[1], what="LSN 0 right after a header-split continuation (fip still 1): passes the "
           "zero test, fails the order test -> FindFirst recovery")
    L.upto(L.row_at(0.5))
    while L.b.off < 0x300:
        L.b.add(L.take())
    z = bytearray(L.take())
    p64(z, 0, 0)
    st = L.b.add(bytes(z), 0)
    L.note(page=st[0], at=st[1], what="LSN 0 mid page with fip 0 -> next page")
    L.upto(L.row_at(0.7))
    L.b.next_page()
    z = bytearray(L.take())
    p64(z, 0, 0)
    st = L.b.add(bytes(z), 0)
    L.note(page=st[0], at=st[1], what="LSN 0 as the first header of a page (fip 1) -> order recovery")
    L.rest()
    return built(L, True, "this_lsn 0 after a header-split continuation (fip 1), mid page (fip 0) and first in page")


@case("b-unaligned", "built(synth-01 records)")
def c_unaligned(rng):
    L = Lay()
    a = L.row_at(0.3)
    L.upto(a)
    for j in range(160):
        r = L.take()
        L.b.add(with_cdl(r, len(r) - 0x30 + 1 + j % 7))
        if j == 80:
            L.b.next_page()
            pg = L.b.pi
            L.b.raw(mkrec(L.b.filler_lsn(), 0, rtype=0)[:0x30] + b"\0\0\0")
            L.note(page=pg, what="cdl-0 header of 0x33 bytes at 0x40: order recovery, but every following header is "
                   "unaligned and FindFirst only probes multiples of 8")
    L.b.next_page()
    L.note(records=f"{a}..{a + 159}", what="client_data_length + 1..7 (unaligned next-record positions)")
    L.rest()
    return built(L, False, "records with client_data_length not a multiple of 8 (unaligned headers) and a "
                           "FindFirst recovery that cannot see them")


def lying_header(lsn, cdl):
    """0x58-byte Noop record header whose client_data_length claims `cdl` (the body is not written)."""
    h = bytearray(mkrec(lsn, 0x28, noop_client(0x28)))
    p32(h, 0x18, cdl)
    return bytes(h)


@case("b-cdl-huge", "built(synth-01 records)")
def c_cdl_huge(rng):
    L = Lay()
    L.upto(L.row_at(0.3))
    L.b.place_at(0x400)
    lsn = L.b.filler_lsn()
    ph, oh = L.b.raw(lying_header(lsn, 0))
    pt = ph + 16  # landing page: q = 15 pages skipped after the header's own page
    while len(L.b.pages) <= pt or not L.b.starts[pt]:
        L.b.add(L.take())
    ot = L.b.starts[pt][0][0]
    q = pt - ph - 1
    cdl = q * 0xFC0 + ot - 0x40 + 0xFD0 - oh
    p32(L.b.pages[ph], oh + 0x18, cdl)
    L.note(page=ph, header_at=oh, lsn=lsn, cdl=cdl, landing_page=pt, landing_off=ot, landing_lsn=L.b.starts[pt][0][1],
           what="Noop header (0x58 bytes, body not written) whose cdl claims %d bytes: q = (off + cdl - 0xfd0) / 0xfc0 = "
                "%d pages skipped without parsing, resume at the first real record start of page %#x" % (cdl, q, pt))
    L.upto(L.row_at(0.7))
    L.b.place_at(0x400)
    lsn = L.b.filler_lsn()
    ph, oh = L.b.raw(lying_header(lsn, 0xFFFFFFFF))
    L.note(page=ph, header_at=oh, lsn=lsn, cdl=0xFFFFFFFF,
           what="q = (0x400 + 0xffffffff - 0xfd0) / 0xfc0 = 0x104103: the list index jumps past the end, the "
                "traversal ends (later records unparsed)")
    L.rest()
    return built(L, False, "client_data_length lies: a multi-page skip of 15 pages that resumes on a real record, "
                           "then 0xffffffff (ends the traversal)")


# =============================================================================================== USA / fixup
@case("usa-blind", "synth-01")
def c_usa_blind(rng):
    d, m = synth_copy(), Mut()
    b4 = b4_offsets(d)
    for off in b4:
        d[off + 0x28:off + 0x2A] = b"\xef\xbe"
    m.note(what="USN (+0x28) = 0xbeef on every RCRD page; sector ends keep the old USN (torn pages)", pages=len(b4))
    reg = synth_regular()
    for off in rng.sample(reg, 10):
        for s in range(8):
            e = off + 0x200 * s + 0x1FE
            d[e:e + 2] = rng.getrandbits(16).to_bytes(2, "little")
        m.note(page=off, what="all 8 raw sector-end words randomised (USA unchanged)")
    return dict(log=d, mft=True, mutation={"edits": m.edits, "expect": "blind fixup: USN never compared, sector ends "
                "always overwritten from the USA -> output = synth-01"},
                desc="update sequence numbers that do not match the sector ends (torn pages): never verified")


@case("usa-entries-random", "synth-01")
def c_usa_rand(rng):
    d, m = synth_copy(), Mut()
    for off, rs in ranked_pages(5)[:8]:
        for s in range(8):
            v = rng.getrandbits(16)
            m.put(d, off + 0x2A + 2 * s, 2, v, f"page {hex(off)} USA[{s}] (lands at {hex(0x200 * s + 0x1fe)})")
    return dict(log=d, mft=True, mutation={"edits": m.edits},
                desc="USA entries randomised on 8 row-rich pages: the blind fixup plants them into records")


@case("usa-into-header", "built(synth-01 records)")
def c_usa_hdr(rng):
    L = Lay()
    plan = [(0x1F8, 0, 0x0001, "LSN bytes 6..7 = 0x0001 -> LSN + 2^48, hi40 mismatch"),
            (0x3E6, 1, None, "client_data_length low word + 0x100 (chain misaligned)"),
            (0x5CE, 2, 0x0099, "redo_op = 0x99 (unknown op name)"),
            (0x7D0, 3, 0xFFFF, "reserved bytes +0x2e (no effect expected)")]
    hits = []
    for n, (pos, s, val, what) in enumerate(plan):
        L.upto(L.row_at(0.2 + 0.15 * n))
        L.b.next_page()
        L.b.place_at(pos)
        r = L.take()
        st = L.b.add(r)
        hits.append((st[0], pos, s, val, what, r))
    L.rest()
    out = assemble(L.b)
    m = Mut()
    for pg, pos, s, val, what, r in hits:
        foff = (2 + 0x20 + pg) * PAGE
        cur = g16(out, foff + 0x2A + 2 * s)
        if val is None:
            val = cur + 0x100
        m.put(out, foff + 0x2A + 2 * s, 2, val, f"built page {pg}: USA[{s}] -> sector end {hex(0x200 * s + 0x1fe)} "
              f"inside the header at {hex(pos)} (lsn {rec_lsn(r)}): {what}")
    return dict(log=out, mft=False, mutation={"notes": L.notes, "edits": m.edits},
                desc="USA words planted into record headers by the blind fixup (LSN high bytes, cdl, redo_op)")


# =============================================================================================== driver
TZ = [(-12, False), (14, True), (0, False), (-3, False), (9, False), (9, True), (-3, True), (5, False), (-7, False),
      (14, False), (-12, True), (3, True), (12, False), (-10, False), (1, True), (0, True), (-5, True), (7, False)]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out", default=str(ROOT / "fuzz" / "cases"))
    ap.add_argument("--only", default="", help="only write cases whose slug contains this text")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    if a.list:
        for n, (slug, base, _) in enumerate(CASES, 1):
            print(f"{FAMILY}-{n:03d}-{slug}  [{base}]")
        return
    out.mkdir(parents=True, exist_ok=True)
    if not a.only:
        for old in out.glob(f"{FAMILY}-*"):
            shutil.rmtree(old)
    _, mft_bytes = Base.synth()
    for n, (slug, base, fn) in enumerate(CASES, 1):
        if a.only and a.only not in slug:
            continue
        r = fn(random.Random(f"{a.seed}:{slug}"))
        utc, dst = TZ[(n - 1 + a.seed) % len(TZ)]
        cdir = out / f"{FAMILY}-{n:03d}-{slug}"
        if cdir.exists():
            shutil.rmtree(cdir)
        cdir.mkdir()
        (cdir / "$LogFile").write_bytes(bytes(r["log"]))
        if r["mft"]:
            (cdir / "$MFT").write_bytes(mft_bytes)
        cj = {"utc": utc, "dst": dst, "mft": bool(r["mft"]), "family": FAMILY, "desc": r["desc"], "base": base,
              "mutation": r["mutation"], "seed": a.seed, "size": len(r["log"])}
        (cdir / "case.json").write_text(json.dumps(cj, indent=1), encoding="utf-8")
        print(f"{cdir.name}  {len(r['log']):>8}  utc={utc}{' dst' if dst else ''}{' mft' if r['mft'] else ''}")


if __name__ == "__main__":
    main()
