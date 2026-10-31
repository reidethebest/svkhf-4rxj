package nlt

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// This file reproduces ParseLogFile (0x40e340): the page scan, the page order and the record traversal, in the
// binary's branch order. Specification: re/spec/02-logfile-structure.md.

const pageSize = 0x1000

// slack after fixed buffers: the original reads past some buffers into adjacent stack memory; here those bytes
// read as zero.
const slack = 0x200

// ParseLogFile's stack frame holds three buffers back to back, so every read past the end of one of them sees
// the next (re/spec/02 section 2.1 and edge case 22):
//
//	[ebp-0x306c] clientBuf, 0x2000 bytes: the client data handed to ProcessLogRecord (memset 0x40e56d..0x40e587)
//	[ebp-0x106c] page, 0x1000 bytes: every Read of the $LogFile (scan 0x40e7c6, v1.1 re-reads, traversal 0x40f145)
//	[ebp-0x6c]   tmpHdr, 0x58 bytes: header-split assembly (0x40fdc4, 0x41153a, 0x4121e7). The ordering's 0x40-byte
//	             PageInfo scratch slot [ebp-0x54] overlaps tmpHdr[0x18..0x58).
//
// frame models them as one slice from [ebp-0x306c] up: clientBuf[0x2000+x] == page[x], page[0x1000+x] ==
// tmpHdr[x]. Above tmpHdr lie the /GS cookie [ebp-0x14], the EH registration and the callers' frames, and
// tmpHdr[0..0x18) is uninitialised until the first header split: none of that is reproducible, so it reads as
// zero here. The size covers the longest read through clientBuf (u16 lengths, attribute walks up to ~0x10260).
const (
	frameClient = 0
	framePage   = 0x2000
	frameTmpHdr = framePage + pageSize
	frameSize   = 0x10000 + pageSize + slack
)

type pageInfo struct {
	ord, lastLSN, lastEndLSN, pageCount uint64
	pagePos                             uint16
	off                                 uint64
	flag                                uint32
}

// bytes is the 0x40-byte PageInfo as the scan builds it at [ebp-0x345c] (0x40e9dd..0x40eaf2). +0x28 is
// max(last_lsn, last_end_lsn) + 10*page_count + page_position (0x40ea56..0x40eac9, never read by the parser).
// +0x22..+0x27 and +0x3c..+0x3f are never written (stale stack, zero here); so is the flag +0x38 of pages taken
// directly from b4 (the port's flag 0 there).
func (pi pageInfo) bytes() []byte {
	b := make([]byte, 0x40)
	le := binary.LittleEndian
	le.PutUint64(b[0:], pi.ord)
	le.PutUint64(b[8:], pi.lastLSN)
	le.PutUint64(b[0x10:], pi.lastEndLSN)
	le.PutUint64(b[0x18:], pi.pageCount)
	le.PutUint16(b[0x20:], pi.pagePos)
	le.PutUint64(b[0x28:], max(pi.lastLSN, pi.lastEndLSN)+10*pi.pageCount+uint64(pi.pagePos))
	le.PutUint64(b[0x30:], pi.off)
	le.PutUint32(b[0x38:], pi.flag)
	return b
}

// ErrNotSupported mirrors "This $LogFile version is not supported." (no rows are produced).
var ErrNotSupported = errors.New("this $LogFile version is not supported")

// ErrOriginalCrash marks inputs on which the original crashes or throws, so it has no reference output.
var ErrOriginalCrash = errors.New("input makes the original fail")

type parser struct {
	data  []byte
	tz    int
	store *Store

	rows []Record // p+0x118: escaped copies of every emitted record
	txn  []Record // p+0x12c: unescaped copies of the current transaction's records with an Event

	v40       map[uint64][]v40Entry // p+0x10, key = MFT record LSN
	dir       map[uint64][]dirEntry // p+0x00, key = file reference
	mftCreate string                // p+0x1a8
	path      string                // p+0x184
	frame     []byte                // 0x40e340's clientBuf, page and tmpHdr, contiguous (see frameSize)

	// Stack memory holding SYSTEMTIME locals whose content outlives one record (see fileTimeToSlot). Before the
	// first write it is uninitialised stack, which differs between runs and reads as zero here.
	v40ST [0x40]byte     // 0x40e340's [ebp-0x320c, ebp-0x31cc): the four V40 slots (mft.go v40Time)
	st412 [st412Len]byte // 0x412710's [ebp-0x1468, ebp-0x14): time slots, query objects, run and name buffers (events.go)
}

func le16(b []byte, o int) uint16 { return binary.LittleEndian.Uint16(b[o:]) }
func le32(b []byte, o int) uint32 { return binary.LittleEndian.Uint32(b[o:]) }
func le64(b []byte, o int) uint64 { return binary.LittleEndian.Uint64(b[o:]) }

// readAt is CFile::Seek + Read into a persistent buffer: bytes past EOF keep the buffer's previous content.
func (p *parser) readAt(buf []byte, off uint64, n int) int {
	if off >= uint64(len(p.data)) {
		return 0
	}
	return copy(buf[:n], p.data[off:])
}

var rstrStrict = []byte{'R', 'S', 'T', 'R', 0x1e, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x10, 0, 0}
var rcrdSig = []byte{'R', 'C', 'R', 'D', 0x28, 0, 9, 0}

// findFirstRecordInPage is 0x416230.
func findFirstRecordInPage(page []byte, shift uint) int {
	// _aullshr (0x5589d0) takes the count in CL: only its low byte counts, and CL >= 64 gives 0.
	cl := uint8(shift)
	sh := func(v uint64) uint64 {
		if cl >= 64 {
			return 0
		}
		return v >> cl
	}
	target := sh(le64(page, 0x20))
	for off := 0x40; off < pageSize; off += 8 {
		if sh(le64(page, off)) != target {
			continue
		}
		if prev := le64(page, off+8); prev != 0 && sh(prev) != target {
			continue
		}
		if undo := le64(page, off+0x10); undo != 0 && sh(undo) != target {
			continue
		}
		if page[off+0x31] != 0 || page[off+0x33] != 0 {
			continue
		}
		if rt := le32(page, off+0x20); rt != 2 && rt != 1 {
			continue
		}
		if fl := le32(page, off+0x28); fl != 1 && fl != 0 {
			continue
		}
		return off
	}
	return 0
}

// pageOrder builds the list p+0xc8 (section 2.5/2.6). prevB is the leftover value the traversal starts with.
func (p *parser) pageOrder() (list []pageInfo, shift uint, prevB uint64, err error) {
	if len(p.data) < 0x1004 || string(p.data[0:4]) != "RSTR" || string(p.data[0x1000:0x1004]) != "RSTR" {
		return nil, 0, 0, fmt.Errorf("%w: no RSTR pages at 0 and 0x1000", ErrNotSupported)
	}
	// The scan, the v1.1 re-reads and the page loop all use page [ebp-0x106c] (0x40e7c6, 0x40ef3a, 0x40efb2,
	// 0x40f145): a short read keeps the previous content of the buffer, including for the first listed page.
	p.frame = make([]byte, frameSize)
	page := p.frame[framePage:]
	var b4 []pageInfo
	var major, minor uint16
	var ord uint64
	for pos := uint64(0); p.readAt(page, pos, pageSize) != 0; pos += pageSize {
		switch {
		case bytes.Equal(page[:0x18], rstrStrict):
			major, minor = le16(page, 0x1c), le16(page, 0x1a)
			// 0x40e95e..0x40e97c: the 0x30-byte restart area is copied from the page BUFFER at restart_area_offset
			// (not bounds-checked), so a short last read sees the previous page's stale bytes there. Past the buffer
			// the original reads tmpHdr (still uninitialised during the scan) and then the cookie and the callers'
			// frames: not reproducible, zero here.
			ra := int(le16(page, 0x18))
			var snb uint32
			if ra+0x14 <= len(page) {
				snb = le32(page, ra+0x10)
			}
			shift = uint(0x40 - snb)
		case bytes.Equal(page[:8], rcrdSig):
			pi := pageInfo{ord: ord, lastLSN: le64(page, 8), lastEndLSN: le64(page, 0x20),
				pageCount: uint64(le16(page, 0x14)), pagePos: le16(page, 0x16), off: pos}
			ord++
			b4 = append(b4, pi)
		}
	}
	type group struct {
		key   uint64
		pages []pageInfo
	}
	groupPages := func(regular []pageInfo) (groups []*group, min, max uint64) {
		var prevPI pageInfo
		for k, cur := range regular {
			if k == 0 {
				max, min = cur.lastLSN, cur.lastLSN
				cur.flag = 1
				groups = append(groups, &group{key: cur.lastLSN, pages: []pageInfo{cur}})
				prevPI = cur
				continue
			}
			if cur.lastLSN > max {
				max = cur.lastLSN
			}
			if cur.lastLSN < min {
				min = cur.lastLSN
			}
			g := groups[len(groups)-1]
			switch {
			case prevPI.lastLSN <= cur.lastLSN:
				cur.flag = 0
				g.pages = append(g.pages, cur)
				if cur.lastLSN != 0 {
					prevPI = cur
				}
			case cur.lastLSN == 0:
				cur.flag = 0
				g.pages = append(g.pages, cur)
			default:
				cur.flag = 0
				groups = append(groups, &group{key: cur.lastLSN, pages: []pageInfo{cur}})
				prevPI = cur
			}
		}
		msvcQsort(groups, func(a, b **group) int { return cmpU64((*a).key, (*b).key) })
		return groups, min, max
	}
	flatten := func(groups []*group) (out []pageInfo) {
		for _, g := range groups {
			out = append(out, g.pages...)
		}
		return out
	}
	byLast := func(a, b *pageInfo) int { return cmpU64(a.lastLSN, b.lastLSN) }

	// scratch is the PageInfo slot [ebp-0x54] (prevPI, bp1, element copies): its last value stays in
	// tmpHdr[0x18..0x58) until the traversal's first header split overwrites it (edge case 22).
	var scratch pageInfo
	switch {
	case major == 1 && minor == 1:
		var regular []pageInfo
		if len(b4) > 2 {
			regular = b4[2:]
		}
		groups, _, m := groupPages(regular)
		list = flatten(groups)
		if len(b4) < 2 {
			return nil, 0, 0, fmt.Errorf("%w: fewer than 2 RCRD pages (AfxThrowInvalidArgException)", ErrOriginalCrash)
		}
		scratch = b4[0] // bp1 (0x40ef1e)
		hdr := page
		p.readAt(hdr, b4[0].off, pageSize)
		a := le64(hdr, 0x20)
		p.readAt(hdr, b4[1].off, pageSize)
		b := le64(hdr, 0x20)
		prevB = a
		switch {
		case m > a && m > b:
		case m > a:
			list = append(list, b4[1])
		case m > b:
			list = append(list, b4[0])
		case a < b:
			list = append(list, b4[1])
		default:
			list = append(list, b4[0])
		}
	case major == 2 && minor == 0:
		var regular []pageInfo
		if len(b4) > 0x20 {
			regular = b4[0x20:]
		}
		var min, max uint64
		groups, gmin, gmax := groupPages(regular)
		if len(regular) > 0 {
			min, max = gmin, gmax
		}
		var dc, f0 []pageInfo
		for k := 0; k < 0x20; k++ {
			if k >= len(b4) {
				return nil, 0, 0, fmt.Errorf("%w: fewer than 0x20 RCRD pages (AfxThrowInvalidArgException)", ErrOriginalCrash)
			}
			if max < b4[k].lastLSN {
				f0 = append(f0, b4[k])
			} else if min > b4[k].lastLSN {
				dc = append(dc, b4[k])
			}
		}
		msvcQsort(dc, byLast)
		msvcQsort(f0, byLast)
		// The DC pages are appended directly (0x40f618); the group pages (0x40f6f0) and the F0 pages (0x40f88e)
		// go through the scratch slot, after the loop above left b4[0x1f] there (0x40f54f).
		ordered := flatten(groups)
		scratch = b4[0x1f]
		if n := len(ordered); n > 0 {
			scratch = ordered[n-1]
		}
		if n := len(f0); n > 0 {
			scratch = f0[n-1]
		}
		list = append(append(dc, ordered...), f0...)
		prevB = uint64(len(f0))
	default:
		return nil, 0, 0, fmt.Errorf("%w: LFS %d.%d", ErrNotSupported, major, minor)
	}
	copy(p.frame[frameTmpHdr+0x18:frameTmpHdr+0x58], scratch.bytes())
	return list, shift, prevB, nil
}

func hi40(v uint64) uint64 { return v >> 24 }

func zero16(b []byte, off int) bool {
	for _, c := range b[off : off+16] {
		if c != 0 {
			return false
		}
	}
	return true
}

// run is the record traversal (sections 2.8 to 2.14).
func (p *parser) run() error {
	list, shift, prevB, err := p.pageOrder()
	if err != nil {
		return err
	}
	// One frame (see frameSize): every read past the page end (FindFirst up to 0x102b, the unbounded recovery
	// copies up to 0x104f, the HS q == 0 completion up to 0x1055) sees tmpHdr, and every client-data read past
	// 0x2000 (ProcessLogRecord's attribute walks, A runs, E1 scans) sees the current page and then tmpHdr.
	clientBuf := p.frame[frameClient:]
	page := p.frame[framePage:]
	tmpHdr := p.frame[frameTmpHdr:]
	rec := make([]byte, 0x58+slack)
	clearClient := func() { clear(clientBuf[:0x2000]) }

	var cur, prev Record
	foundFirst, newPage, pending, fip := false, true, false, false
	span := 0
	var startOff, curOff, savedOff, firstPageIdx int
	var remaining, copied int
	var prevA uint64

	emitIf := func() {
		if cstr(cur.FileName) != "" || cur.Event != "" { // wcscmp 0x40f9c2..0x40fa3d: a blanked name is empty
			p.store.InsertLogFileRow(&cur)
			p.rows = append(p.rows, cur)
		}
	}
	process := func() { p.processLogRecord(&prev, rec, &cur, clientBuf) }

	for i := 0; i < len(list); i++ {
		pi := list[i]
		p.readAt(page, pi.off, pageSize)
		posAfterRead := pi.off + pageSize
		if bytes.Equal(page[:8], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) {
			break
		}
		for s := 0; s < 8; s++ { // blind USA fixup
			copy(page[0x200*s+0x1fe:0x200*s+0x200], page[0x2a+2*s:0x2c+2*s])
		}
		if !foundFirst {
			startOff = findFirstRecordInPage(page, shift)
			if startOff == 0 {
				continue
			}
			foundFirst, firstPageIdx = true, i
		}
		if newPage {
			curOff, newPage = startOff, false
		}
		if pending {
			copy(clientBuf[copied:copied+remaining], page[0x40:0x40+remaining])
			process()
			clearClient()
			prev = cur
			emitIf()
			pending, remaining, copied = false, 0, 0
			if pageSize-curOff < 0x30 {
				newPage, startOff, span = true, 0x40, 0
				continue
			}
		}
		fip = true

		// hdrSplit is HDR_SPLIT: the 0x58-byte header crosses the page end.
		hdrSplit := func(off int) {
			k := pageSize - off
			copy(tmpHdr[:k], page[off:pageSize])
			copy(rec[:k], page[off:pageSize])
			prevA = le64(rec, 0)
			prevB = prevA
			savedOff, span = off, 1
		}

	recordLoop:
		for {
			cur.reset()
			if span == 1 {
				n := savedOff - 0xfa8
				copy(tmpHdr[pageSize-savedOff:pageSize-savedOff+n], page[curOff:curOff+n])
				copy(rec[:0x58], tmpHdr[:0x58])
				if le64(rec, 0) == ^uint64(0) {
					span, curOff = 0, 0x40
					break recordLoop
				}
				if !(le32(rec, 0x18) >= uint32(le16(rec, 0x34))) {
					off := findFirstRecordInPage(page, shift)
					curOff, span = off, 0
					if off == 0 {
						curOff = 0x40
						break recordLoop
					}
					copy(rec[:0x58], page[off:off+0x58])
				}
			} else {
				if curOff+0x58 > pageSize {
					hdrSplit(curOff)
					curOff = 0x40
					break recordLoop
				}
				copy(rec[:0x58], page[curOff:curOff+0x58])
				lsn := le64(rec, 0)
				if lsn == ^uint64(0) || (lsn == 0 && !fip) {
					curOff = 0x40
					break recordLoop
				}
				if hi40(lsn) == hi40(prevA) || i == firstPageIdx {
					if !(lsn >= prevB && le32(rec, 0x18) != 0) {
						if !fip {
							curOff = 0x40
							break recordLoop
						}
						off := findFirstRecordInPage(page, shift)
						curOff = off
						if off == 0 {
							curOff = 0x40
							break recordLoop
						}
						copy(rec[:0x58], page[off:off+0x58])
					}
				} else {
					if !fip {
						curOff = 0x40
						break recordLoop
					}
					off := findFirstRecordInPage(page, shift)
					curOff = off
					if off == 0 {
						curOff = 0x40
						break recordLoop
					}
					if off+0x58 > pageSize {
						hdrSplit(off)
						curOff = 0x40
						break recordLoop
					}
					copy(rec[:0x58], page[off:off+0x58])
				}
				span, fip = 0, false
			}

			// ACCEPT
			lsn := le64(rec, 0)
			prevA, prevB = lsn, lsn
			cdl := int(le32(rec, 0x18))
			redoOff, undoOff := int(le16(rec, 0x34)), int(le16(rec, 0x38))
			cur.LSN = strconv.FormatUint(lsn, 10)
			cur.RedoInfo = opName(le16(rec, 0x30))
			cur.UndoInfo = opName(le16(rec, 0x32))
			cur.TargetVCN = fmt.Sprintf("0x%X", le32(rec, 0x48))
			p.v40Lookup(&cur, lsn)
			cur.RedoFileOff = posAfterRead + uint64(curOff) + uint64(redoOff) - 0xfd0
			cur.RedoLen = uint64(le16(rec, 0x36))
			cur.UndoFileOff = posAfterRead + uint64(curOff) + uint64(undoOff) - 0xfd0
			cur.UndoLen = uint64(le16(rec, 0x3a))
			cur.ClusterBlockOffset = uint64(le16(rec, 0x44))

			if span == 0 {
				end := curOff + 0x30 + cdl
				switch {
				case end > pageSize: // BODY_SPAN
					ovf := curOff + cdl - 0xfd0
					q := ovf / 0xfc0
					if uint32(q) == 0 {
						remaining, copied, pending = ovf, 0xfa8-curOff, true
						copy(clientBuf[:copied], page[curOff+0x58:pageSize])
						curOff, span = ovf+0x40, 0
						break recordLoop
					}
					i += int(uint32(q))
					curOff, span = ovf-q*0xfc0+0x40, 0
					if pageSize-curOff < 0x30 {
						i++
						newPage, startOff, span = true, 0x40, 0
					}
					prev = cur
					emitIf()
					break recordLoop
				case end == pageSize: // EXACT_END
					if cdl < redoOff {
						return fmt.Errorf("%w: client_data_length < redo_offset at LSN %d", ErrOriginalCrash, lsn)
					}
					copy(clientBuf, page[curOff+0x30+redoOff:curOff+0x30+cdl])
					process()
					clearClient()
					curOff = 0x40
					prev = cur
					emitIf()
					break recordLoop
				}
				if cdl < redoOff {
					return fmt.Errorf("%w: client_data_length < redo_offset at LSN %d", ErrOriginalCrash, lsn)
				}
				copy(clientBuf, page[curOff+0x30+redoOff:curOff+0x30+cdl])
				process()
				clearClient()
				curOff = end
				if pageSize-curOff < 0x30 || zero16(page, curOff) || hi40(le64(page, curOff)) != hi40(prevA) {
					newPage, startOff, span = true, 0x40, 0
					prev = cur
					emitIf()
					break recordLoop
				}
				prev = cur
				emitIf()
				if lsn == pi.lastLSN {
					break recordLoop // next page keeps curOff
				}
				continue
			}

			// span == 1: header-split record. cdl - 0x28 is 32-bit and its carry is dropped (0x41123a add ecx,-0x28;
			// 0x411c92 lea ebx,[eax-0x28]): cdl < 0x28 always goes to HS_BODY_SPAN with q = 0x104103, which ends the
			// traversal (edge cases 20/21).
			t := int(uint32(cdl - 0x28))
			end := t + savedOff - 0xf68
			switch {
			case end > pageSize: // HS_BODY_SPAN
				ovf2 := t + savedOff + curOff - 0x1fa8
				q := ovf2 / 0xfc0
				i += int(uint32(q))
				if q == 0 {
					remaining = cdl + curOff - 0xfd0
					copied = cdl - remaining - 0x28
					copy(clientBuf[:copied], page[curOff+0x58:curOff+0x58+copied])
					pending = true
					curOff, span = ovf2+0x40, 0
					break recordLoop
				}
				curOff, span = ovf2-q*0xfc0+0x40, 0
				if pageSize-curOff < 0x30 {
					i++
					newPage, startOff, span = true, 0x40, 0
				}
				prev = cur
				emitIf()
				break recordLoop
			case end == pageSize: // HS_EXACT_END (span stays 1)
				src := curOff + savedOff + redoOff - 0xfd0
				copy(clientBuf, page[src:src+cdl-redoOff])
				process()
				clearClient()
				curOff = 0x40
				prev = cur
				emitIf()
				break recordLoop
			}
			src := curOff + savedOff + redoOff - 0xfd0
			if cdl < redoOff || src < 0 {
				return fmt.Errorf("%w: unsupported header-split layout at LSN %d", ErrOriginalCrash, lsn)
			}
			copy(clientBuf, page[src:src+cdl-redoOff])
			process()
			clearClient()
			span = 0
			curOff = curOff + (cdl - 0x28) + savedOff - 0xfa8
			if pageSize-curOff < 0x30 || zero16(page, curOff) {
				newPage, startOff = true, 0x40
				prev = cur
				emitIf()
				break recordLoop
			}
			if pi.flag == 1 && fip {
				prevA = ((prevA >> 24) + 1) << 24
				fip = false
			}
			if hi40(le64(page, curOff)) != hi40(prevA) {
				newPage, startOff = true, 0x40
				prev = cur
				emitIf()
				break recordLoop
			}
			prev = cur
			emitIf()
		}
	}
	return nil
}

var opNames = map[uint16]string{
	0: "Noop", 1: "Compensation Log Record", 2: "Initialize File Record Segment", 3: "Deallocate File Record Segment",
	4: "Write End of File Record Segment", 5: "Create Attribute", 6: "Delete Attribute", 7: "Update Resident Value",
	8: "Update Nonresident Value", 9: "Update Mapping Pairs", 0xa: "Delete Dirty Clusters", 0xb: "Set New Attribute Sizes",
	0xc: "Add Index Entry Root", 0xd: "Delete Index Entry Root", 0xe: "Add Index Entry Allocation",
	0xf: "Delete Index Entry Allocation", 0x12: "Set Index Entry VCN Allocation", 0x13: "Update File Name Root",
	0x14: "Update File Name Allocation", 0x15: "Set Bits In Nonresident Bit Map", 0x16: "Clear Bits In Nonresident Bit Map",
	0x19: "Prepare Transaction", 0x1a: "Commit Transaction", 0x1b: "Forget Transaction", 0x1c: "OpenNonresidentAttribute",
	0x1f: "Dirty Page Table Dump", 0x20: "Transaction Table Dump", 0x21: "Update Record Data Root",
}

// opName is the redo/undo operation name chain (0x4107e7..0x410d54); unknown values are "0x%x".
func opName(op uint16) string {
	if s, ok := opNames[op]; ok {
		return s
	}
	return fmt.Sprintf("0x%x", op)
}
