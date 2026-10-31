"""Generic NTFS $LogFile (LFS 2.0, 4 KiB pages) record dumper used to correlate the original's rows with raw records.

  python lfsdump.py <$LogFile> [--jsonl out.jsonl]

Walks every RCRD page after the two restart and two buffer pages, applies update-sequence fixups, and follows
records (including records continued on the next page by page_count / next-page order of LSN). Emits one JSON
object per record: lsn, prev, undo_next, client_data_length, record_type, transaction_id, flags, redo/undo ops,
target attr/vcn/lcn fields, and the file offset of the record header.
"""
import argparse
import json
import struct

PAGE = 4096


def fixup(p):
    usa_off, usa_cnt = struct.unpack_from("<HH", p, 4)
    b = bytearray(p)
    for i in range(1, usa_cnt):
        b[i * 512 - 2:i * 512] = b[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(b)


def pages(data):
    for off in range(4 * PAGE, len(data) - PAGE + 1, PAGE):
        p = data[off:off + PAGE]
        if p[:4] == b"RCRD":
            yield off, fixup(p)


def records(data):
    """Yield (file_offset, record_bytes) for every record header found at the file position its own LSN encodes.

    LFS 2.0: an LSN is (sequence << file_bits) | (file_offset / 8), file_bits = 64 - seq_number_bits (restart area
    +0x10). Scanning every 8-byte slot of every RCRD page and keeping only self-consistent headers finds all
    records regardless of page order; a record longer than the rest of its page continues at +0x40 of the next
    page (wrapping to the first log page)."""
    ra = struct.unpack_from("<H", data, 0x18)[0]
    seq_bits = struct.unpack_from("<I", data, ra + 0x10)[0]
    file_bits = 64 - seq_bits
    mask = (1 << file_bits) - 1
    file_pages = dict(pages(data))
    first_log, end = 4 * PAGE, len(data)
    for off, p in sorted(file_pages.items()):
        for pos in range(0x40, PAGE - 0x30 + 1, 8):
            lsn, prev, undo_next, cdl, cid, rtype = struct.unpack_from("<QQQIII", p, pos)
            if lsn == 0 or (lsn & mask) * 8 != off + pos or rtype not in (1, 2) or cdl > 0x100000:
                continue
            total = 0x30 + cdl
            body = p[pos:pos + total]
            nxt = off + PAGE
            while len(body) < total:
                if nxt >= end:
                    nxt = first_log
                if nxt not in file_pages:
                    break
                body += file_pages[nxt][0x40:0x40 + total - len(body)]
                nxt += PAGE
            yield off + pos, body


def decode(off, b):
    lsn, prev, undo_next, cdl, cid, rtype, tid, flags = struct.unpack_from("<QQQIIIIH", b, 0)
    r = {"off": off, "lsn": lsn, "prev": prev, "undo_next": undo_next, "cdl": cdl, "client": cid, "rtype": rtype,
         "tid": tid, "flags": flags}
    if len(b) >= 0x58:
        (redo, undo, redo_off, redo_len, undo_off, undo_len, tattr, lcns, rec_off, attr_off, cbo) = struct.unpack_from(
            "<HHHHHHHHHHH", b, 0x30)
        tvcn, = struct.unpack_from("<Q", b, 0x48)
        r.update(redo=redo, undo=undo, redo_off=redo_off, redo_len=redo_len, undo_off=undo_off, undo_len=undo_len,
                 tattr=tattr, lcns=lcns, rec_off=rec_off, attr_off=attr_off, cbo=cbo, tvcn=tvcn)
        if lcns:
            r["lcn"] = struct.unpack_from("<Q", b, 0x50)[0]
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("--jsonl")
    a = ap.parse_args()
    data = open(a.logfile, "rb").read()
    out = [decode(o, b) for o, b in records(data)]
    if a.jsonl:
        with open(a.jsonl, "w", encoding="utf-8") as f:
            for r in out:
                f.write(json.dumps(r) + "\n")
    print(f"{len(out)} records, lsn {min(r['lsn'] for r in out)}..{max(r['lsn'] for r in out)}")


if __name__ == "__main__":
    main()
