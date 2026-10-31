"""Copy $LogFile (MFT record 2, unnamed $DATA) from a live NTFS volume by raw reads (read-only, needs admin).

  python extract_logfile.py C: out\\$LogFile
"""
import struct
import sys


def runs(attr):
    off = struct.unpack_from("<H", attr, 0x20)[0]
    pos, lcn, out = off, 0, []
    while attr[pos]:
        h = attr[pos]
        ln_sz, off_sz = h & 0xF, h >> 4
        length = int.from_bytes(attr[pos + 1:pos + 1 + ln_sz], "little")
        delta = int.from_bytes(attr[pos + 1 + ln_sz:pos + 1 + ln_sz + off_sz], "little", signed=True)
        lcn += delta
        out.append((lcn, length))
        pos += 1 + ln_sz + off_sz
    return out


def fixup(rec, sector):
    usa_off, usa_cnt = struct.unpack_from("<HH", rec, 4)
    rec = bytearray(rec)
    for i in range(1, usa_cnt):
        rec[i * sector - 2:i * sector] = rec[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(rec)


def main():
    vol, dst = sys.argv[1].rstrip("\\:"), sys.argv[2]
    recno = int(sys.argv[sys.argv.index("--record") + 1]) if "--record" in sys.argv else 2  # 0 = $MFT
    with open(rf"\\.\{vol}:", "rb", buffering=0) as f:
        boot = f.read(512)
        bps = struct.unpack_from("<H", boot, 11)[0]
        cluster = bps * boot[13]
        mft_lcn = struct.unpack_from("<q", boot, 0x30)[0]
        crs = struct.unpack_from("<b", boot, 0x40)[0]
        rec_size = cluster * crs if crs > 0 else 1 << -crs
        start = mft_lcn * cluster + recno * rec_size
        f.seek(start - start % 4096)
        blk = f.read(8192)
        rec = fixup(blk[start % 4096:start % 4096 + rec_size], bps)
        assert rec[:4] == b"FILE", f"MFT record {recno} signature"
        pos = struct.unpack_from("<H", rec, 0x14)[0]
        while True:
            typ, ln = struct.unpack_from("<II", rec, pos)
            if typ == 0xFFFFFFFF:
                raise SystemExit("no $DATA")
            if typ == 0x80 and rec[pos + 9] == 0:
                attr = rec[pos:pos + ln]
                break
            pos += ln
        assert attr[8] == 1, "non-resident $DATA expected"
        size = struct.unpack_from("<q", attr, 0x30)[0]
        with open(dst, "wb") as o:
            left = size
            for lcn, n in runs(attr):
                f.seek(lcn * cluster)
                chunk = f.read(n * cluster)
                o.write(chunk[:left])
                left -= min(left, len(chunk))
    print(f"{dst}: {size} bytes")


if __name__ == "__main__":
    main()
