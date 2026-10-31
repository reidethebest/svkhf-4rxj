package nlt

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPageInfoBytes(t *testing.T) {
	pi := pageInfo{ord: 0x102, lastLSN: 0x1000, lastEndLSN: 0x1010, pageCount: 3, pagePos: 2, off: 0x23000, flag: 1}
	b := pi.bytes()
	le := binary.LittleEndian
	for _, c := range []struct {
		off  int
		got  uint64
		want uint64
	}{
		{0, le.Uint64(b[0:]), 0x102},
		{8, le.Uint64(b[8:]), 0x1000},
		{0x10, le.Uint64(b[0x10:]), 0x1010},
		{0x18, le.Uint64(b[0x18:]), 3},
		{0x20, uint64(le.Uint16(b[0x20:])), 2},
		{0x28, le.Uint64(b[0x28:]), 0x1010 + 10*3 + 2}, // max(last, last_end) + 10*page_count + page_position
		{0x30, le.Uint64(b[0x30:]), 0x23000},
		{0x38, uint64(le.Uint32(b[0x38:])), 1},
	} {
		if c.got != c.want {
			t.Errorf("PageInfo+%#x = %#x, want %#x", c.off, c.got, c.want)
		}
	}
}

// logFile builds a $LogFile of two strict RSTR pages (LFS major.minor) followed by one RCRD page per last_lsn.
func logFile(major, minor uint16, lastLSNs ...uint64) []byte {
	out := make([]byte, (2+len(lastLSNs))*pageSize)
	for k := 0; k < 2; k++ {
		r := out[k*pageSize:]
		copy(r, rstrStrict)
		binary.LittleEndian.PutUint16(r[0x18:], 0x30) // restart_area_offset
		binary.LittleEndian.PutUint16(r[0x1a:], minor)
		binary.LittleEndian.PutUint16(r[0x1c:], major)
		binary.LittleEndian.PutUint32(r[0x30+0x10:], 0x30) // seq_number_bits
	}
	for k, l := range lastLSNs {
		r := out[(2+k)*pageSize:]
		copy(r, rcrdSig)
		binary.LittleEndian.PutUint64(r[8:], l)
		binary.LittleEndian.PutUint64(r[0x20:], l+8)
		binary.LittleEndian.PutUint16(r[0x14:], 1)
	}
	return out
}

// TestOrderingScratchInTmpHdr checks edge case 22: after the ordering, the bytes right after the page buffer
// (tmpHdr[0x18..0x58)) hold the last PageInfo copied to the scratch slot [ebp-0x54].
func TestOrderingScratchInTmpHdr(t *testing.T) {
	b4 := func(ord int, last uint64) pageInfo {
		return pageInfo{ord: uint64(ord), lastLSN: last, lastEndLSN: last + 8, pageCount: 1, off: uint64(2+ord) * pageSize}
	}
	v20 := func(first map[int]uint64, regular ...uint64) []uint64 {
		l := make([]uint64, 0x20)
		for k, v := range first {
			l[k] = v
		}
		return append(l, regular...)
	}
	cases := []struct {
		name string
		data []byte
		want pageInfo
	}{
		{"v1.1 bp1", logFile(1, 1, 50, 60, 100), b4(0, 50)},
		{"v2.0 last F0", logFile(2, 0, v20(map[int]uint64{5: 400, 3: 300}, 100, 200)...), b4(5, 400)},
		// groups {500, 600} and {100} sort to {100}, {500, 600}: the last group page copied is 600 (flag 0).
		{"v2.0 last group page", logFile(2, 0, v20(map[int]uint64{4: 150}, 500, 600, 100)...), b4(0x21, 600)},
		{"v2.0 b4[0x1f]", logFile(2, 0, v20(nil)...), b4(0x1f, 0)},
	}
	for _, c := range cases {
		p := &parser{data: c.data}
		if _, _, _, err := p.pageOrder(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		tmpHdr := p.frame[framePage+pageSize:]
		if !bytes.Equal(tmpHdr[0x18:0x58], c.want.bytes()) {
			t.Errorf("%s: tmpHdr[0x18..0x58) = % x, want % x", c.name, tmpHdr[0x18:0x58], c.want.bytes())
		}
		if !bytes.Equal(tmpHdr[:0x18], make([]byte, 0x18)) {
			t.Errorf("%s: tmpHdr[0..0x18) must stay zero (uninitialised stack)", c.name)
		}
	}
}
