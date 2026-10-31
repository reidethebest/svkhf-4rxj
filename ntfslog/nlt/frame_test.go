package nlt

import (
	"encoding/binary"
	"strings"
	"testing"
)

// A run length size of 13..15 reaches the saved Parser* [ebp-0x147c]; 9..12 only the unused [ebp-0x1480].
func TestDecodeRunsSmash(t *testing.T) {
	for _, c := range []struct {
		lenSz int
		want  bool
	}{{8, false}, {12, false}, {13, true}, {15, true}} {
		run := make([]byte, 0x40)
		run[0] = 0x10 | byte(c.lenSz)
		run[1] = 7
		run[1+c.lenSz] = 1 // offset size 1
		if _, sm := decodeRunsA(run); sm != c.want {
			t.Errorf("A lenSz %d: smashed %v, want %v", c.lenSz, sm, c.want)
		}
		if _, sm := decodeRunsF(run, 0x40); sm != c.want {
			t.Errorf("F lenSz %d: smashed %v, want %v", c.lenSz, sm, c.want)
		}
	}
}

// aData builds an A record (Initialize File Record Segment after Add Index Entry) whose redo FILE record holds
// one non-resident $DATA attribute of the given length and mapping-pairs offset.
func aData(attrLen uint32, mp uint16) (p *parser, err any) {
	p = &parser{store: NewStore(nil)}
	rec := make([]byte, 0x58)
	binary.LittleEndian.PutUint16(rec[0x30:], 2)
	binary.LittleEndian.PutUint16(rec[0x36:], 0xffff)
	buf := make([]byte, frameSize)
	copy(buf, "FILE")
	binary.LittleEndian.PutUint32(buf[0x38:], 0x80)
	binary.LittleEndian.PutUint32(buf[0x3c:], attrLen)
	buf[0x40] = 1
	binary.LittleEndian.PutUint16(buf[0x58:], mp)
	buf[0x38+int(mp)] = 0x11 // one run: length 1 byte, offset 1 byte
	buf[0x38+int(mp)+1], buf[0x38+int(mp)+2] = 4, 9
	prev := Record{RedoInfo: "Add Index Entry Root"}
	var cur Record
	defer func() { err = recover() }()
	p.processLogRecord(&prev, rec, &cur, buf)
	return p, nil
}

// memcpy(run1418, ..., lastLen-mp): up to 0x1404 bytes fit below the /GS cookie, more or a negative size kill
// the original.
func TestADataCopyLength(t *testing.T) {
	for _, c := range []struct {
		n     int32
		crash bool
	}{{0x40, false}, {0x1404, false}, {0x1405, true}, {-8, true}} {
		mp := uint16(0x48)
		if c.n < 0 {
			mp -= uint16(c.n) // the attribute length stays >= 0x48 (0x413041)
		}
		_, err := aData(uint32(int32(mp)+c.n), mp)
		if got := err != nil && strings.Contains(err.(string), ErrOriginalCrash.Error()); got != c.crash {
			t.Errorf("n=%#x: crash %v (%v), want %v", c.n, got, err, c.crash)
		}
	}
}

// The $MFT pre-pass reads past the 0x400-byte record into the never-written (zero) rest of its malloc(0xa00000).
func TestParseMFTFarOffsets(t *testing.T) {
	r := make([]byte, 0x400)
	copy(r, "FILE")
	binary.LittleEndian.PutUint16(r[4:], 0x7f30) // usa_ofs far past the record
	binary.LittleEndian.PutUint16(r[6:], 3)
	binary.LittleEndian.PutUint16(r[0x14:], 0x38)
	binary.LittleEndian.PutUint32(r[0x38:], 0x30)
	binary.LittleEndian.PutUint32(r[0x3c:], 0x68)
	binary.LittleEndian.PutUint16(r[0x38+0x14:], 0xffff) // value offset far past the record
	binary.LittleEndian.PutUint32(r[0xa0:], 0xffffffff)
	p := &parser{}
	if err := p.parseMFT(r); err != nil {
		t.Fatal(err)
	}
	if len(p.v40) != 0 || len(p.dir) != 0 {
		t.Errorf("zero memory past the record gives no name: v40 %v dir %v", p.v40, p.dir)
	}
}
