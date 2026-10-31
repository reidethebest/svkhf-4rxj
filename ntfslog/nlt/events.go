package nlt

import (
	"fmt"
	"strconv"
	"strings"
)

// Offsets in parser.st412, which models [ebp-0x1468, ebp-0x14) of ProcessLogRecord's frame. All five calls of
// 0x412710 (0x40f995, 0x41102d, 0x4112c5, 0x411964, 0x411eec) push four arguments from 0x40e340's fixed esp, so
// every record gets the same frame, and these bytes keep what the previous record left there (no slot is ever
// initialised; the oracle shows a value from an earlier record surviving the INSERTs in between, sem-025/026).
// The SYSTEMTIME output slot of each conversion is fixed per branch (lea of the second argument):
//
//	st1460 [ebp-0x1460]: A MFT-Modified (0x412c02), C/D Modified (0x4139bb, 0x414397)
//	st1448 [ebp-0x1448]: A Access (0x412ccf), C/D Create (0x4138ba, 0x414312), E2 (0x414c7e)
//	st1438 [ebp-0x1438]: A Modified (0x412b35), C/D MFT-Modified (0x413a93, 0x414405)
//	st1428 [ebp-0x1428]: A Create (0x412a62), C/D Access (0x413b6b, 0x414473)
//
// Two CppSQLite3Query objects (0x18 bytes, see updateQuery) share the area: the E2 UPDATE's at [ebp-0x1468]
// (0x414f94) spans st1460 with its bytes 8..0x18, the H Move(Before) UPDATE's at [ebp-0x1450] (0x415f89) spans
// st1448 the same way. Nothing else in 0x412710 addresses [ebp-0x1468, ebp-0x1418).
//
// Above them, up to the /GS cookie [ebp-0x14]:
//
//	run1418 [ebp-0x1418]: A's mapping-pairs buffer, 0x1000 bytes (memset 0x413079..0x413091, memcpy 0x4130b4)
//	name418 [ebp-0x418]:  C/D/H $FILE_NAME name copy (0x413da1, 0x4145e1, 0x415b7b), 2*len bytes + u16 0
//	name218 [ebp-0x218]:  A/G $FILE_NAME name copy (0x412e03, 0x41572e), 2*len bytes + u16 0
//	        [ebp-0x180, ebp-0x20): a 0x160-byte Record the look-back loops construct (0x4078b0, 0x405260,
//	        0x405d60) and destroy within one call; its CStrings are heap pointers, not reproducible, so this
//	        port leaves whatever the A copy wrote there. Every one of its fields is written before it is read.
//
// Nothing in that range is read before it is written except by A's run decoder, which reads past the run buffer
// until it meets a zero header byte, so the name copies are kept here for it (see the A $DATA case).
const (
	q1468    = 0x00
	st1460   = 0x08
	q1450    = 0x18
	st1448   = 0x20
	st1438   = 0x30
	st1428   = 0x40
	run1418  = 0x50
	name418  = run1418 + 0x1000
	name218  = run1418 + 0x1200
	cookie14 = run1418 + 0x1404 // the /GS cookie, checked on return (0x416198 -> 0x41619d)
	st412Len = cookie14 + slack // the slack (zero) stops A's run decoder past the cookie
)

// updateQuery leaves at st412[q] what execQuery (0x403dc0) and ~CppSQLite3Query (0x404000) write when an UPDATE
// is run as a query: {+0 vtable, +4 mpDB, +8 mpVM, +0xc bool mbEof, +0x10 mnCols, +0x14 bool mbOwnVM}. The step
// returns SQLITE_DONE, so mbEof = 1 (0x403f69..0x403f77); sqlite3_column_count of an UPDATE is 0 (PRAGMA
// count_changes=OFF); mbOwnVM = 1; the destructor finalizes the statement and zeroes mpVM (0x404050). A bool is
// one byte, so the three bytes after it keep their old content. The vtable (relocated image) and mpDB (heap) never
// overlap a slot and are not modelled.
func (p *parser) updateQuery(q int) {
	b := p.st412[q:]
	clear(b[8:0xc])
	b[0xc] = 1
	clear(b[0x10:0x14])
	b[0x14] = 1
}

// processLogRecord is ProcessLogRecord (0x412710): classify one record by (redo_op, undo_op), fill cur, look back
// over earlier records and issue UPDATEs. Specification: re/spec/05-postprocess.md section 4.
func (p *parser) processLogRecord(prev *Record, rec []byte, cur *Record, buf []byte) {
	cur.Event = ""
	if le64(rec, 8) == 0 {
		p.txn = p.txn[:0]
	}
	r, u := le16(rec, 0x30), le16(rec, 0x32)
	redoLen := int32(le16(rec, 0x36))
	recOff, attrOff := le16(rec, 0x40), le16(rec, 0x42)
	fmtRaw := func(slot int, ft uint64) string { return fileTimeToSlot(p.st412[slot:slot+0x10], ft) }
	fmtAdj := func(slot int, ft uint64) string { a, _ := adjustTimeString(fmtRaw(slot, ft), p.tz); return a }
	smashed := false // a run decoder overwrote the saved Parser* (see runLenSmash)

	switch {
	case r == 2 && u == 0: // A: File / Directory Creation
		if !(prev.RedoInfo == "Add Index Entry Allocation" || prev.RedoInfo == "Add Index Entry Root") {
			break
		}
		if string(buf[0:4]) != "FILE" {
			break
		}
		off := int32(0x38)
		var lastLen uint32
		if 0x38 < redoLen {
		walk:
			for {
				t := le32(buf, int(off))
				switch t {
				case 0x10:
					lastLen = le32(buf, int(off)+4)
					if lastLen == 0 {
						break walk
					}
					cur.AttrName = attrName(le32(buf, int(off)+0x38))
					p.checkParser(smashed) // 0x412ad2 reads the time zone through the Parser*
					cur.CreateTime = fmtAdj(st1428, le64(buf, int(off)+0x18))
					cur.ModifiedTime = fmtAdj(st1438, le64(buf, int(off)+0x20))
					cur.MFTModifiedTime = fmtAdj(st1460, le64(buf, int(off)+0x28))
					cur.AccessTime = fmtAdj(st1448, le64(buf, int(off)+0x30))
				case 0x30:
					lastLen = le32(buf, int(off)+4)
					if lastLen == 0 {
						break walk
					}
					name := p.copyName(name218, buf, int(off)+0x58, int(off)+0x5a) // 0x412e0a
					pr := le64(buf, int(off)+0x18)
					if isDos83ShortName(name) {
						off += int32(lastLen)
						if off < redoLen {
							continue walk
						}
						break walk
					}
					if !isRootRef(pr) { // 0x412e89: a root parent needs no lookup
						p.checkParser(smashed) // 0x412ece: the directory map is reached through the Parser*
					}
					cur.FileName = fmtName(name) // 0x412e5a
					cur.ParentRef = pr
					p.fullPathFor(cur, pr)
					cur.Detail = ""
					cur.EventTime = cur.CreateTime
					cur.Event = "File Creation"
				case 0x80:
					lastLen = le32(buf, int(off)+4)
					if lastLen == 0 {
						break walk
					}
					if buf[off+8] != 1 {
						break walk
					}
					mp := le16(buf, int(off)+0x20)
					if mp == 0 {
						break walk
					}
					if int32(lastLen) >= 0x48 {
						// memset(run1418, 0, 0x1000), then memcpy(run1418, buf+off+mp, lastLen-mp) (0x4130b4).
						// Up to 0x1404 bytes the overflow lands in the dead locals above the buffer (see st412)
						// and only the decoder sees it. More reaches the /GS cookie: the process is killed when
						// 0x412710 returns, before the caller's INSERT. A negative size is a ~4 GiB memcpy that
						// faults. Neither path issues a statement first (branch A has none).
						run := p.st412[run1418:]
						clear(run[:pageSize])
						n := int32(lastLen - uint32(mp))
						if n < 0 || n > cookie14-run1418 {
							panic(fmt.Sprintf("%v: $DATA mapping-pairs copy of %d bytes into the 0x1000-byte run buffer",
								ErrOriginalCrash, n))
						}
						if src := int(off) + int(mp); src < len(buf) {
							// Past ParseLogFile's frame lie its cookie and the callers' frames: zero here.
							copy(run[:n], buf[src:])
						}
						runs, sm := decodeRunsA(run)
						smashed = smashed || sm
						if runs != "" {
							cur.Detail = "Data Runs(in Volume) : " + runs
						}
					}
				case 0x90:
					if cur.FileName == "" || cur.FileName[0] != '$' {
						cur.Event = "Directory Creation"
					}
				case 0xFFFFFFFF:
					break walk
				}
				if lastLen == 0 {
					break walk
				}
				off += int32(lastLen)
				if !(off < redoLen) {
					break walk
				}
			}
		}
		cur.MftVCN, cur.MftBlock = prev.MftVCN, prev.MftBlock

	case r == 3 && u == 2: // B: File / Directory Deletion
		for i := range p.txn {
			l := &p.txn[i]
			// FileName != "" is a wcscmp (0x41354b): a name blanked by fmtName counts as empty.
			if (l.RedoInfo == "Delete Index Entry Allocation" || l.RedoInfo == "Delete Index Entry Root") && cstr(l.FileName) != "" {
				cur.AttrName = l.AttrName
				if cur.AttrName == "Directory" {
					cur.Event = "Directory Deletion"
				} else {
					cur.Event = "File Deletion"
				}
				cur.FullPath, cur.FileName = l.FullPath, l.FileName
				cur.CreateTime, cur.ModifiedTime = l.CreateTime, l.ModifiedTime
				cur.MFTModifiedTime, cur.AccessTime = l.MFTModifiedTime, l.AccessTime
				if l.Abnormal == 1 {
					cur.Detail = "Abnormal Timestamp"
					if l.AbnormalTime != "" {
						cur.Detail += fmt.Sprintf(" (%s)", l.AbnormalTime)
					}
				}
				cur.MftVCN, cur.MftBlock = l.MftVCN, l.MftBlock
				break
			}
		}

	case (r == 0xf && u == 0xe) || (r == 0xd && u == 0xc): // C: Delete Index Entry
		pr := le64(buf, 0x10)
		cur.ParentRef = pr
		sC := fmtRaw(st1448, le64(buf, 0x18))
		cur.CreateTime, _ = adjustTimeString(sC, p.tz)
		cur.ModifiedTime = fmtAdj(st1460, le64(buf, 0x20))
		cur.MFTModifiedTime = fmtAdj(st1438, le64(buf, 0x28))
		cur.AccessTime = fmtAdj(st1428, le64(buf, 0x30))
		if p.mftCreate != "" {
			if wcsGreater(p.mftCreate, sC) {
				cur.Abnormal, cur.AbnormalTime = 1, cur.CreateTime
			} else {
				cur.Abnormal = 0
			}
		} else if allStart20(cur) {
			cur.Abnormal = 0
		} else {
			cur.Abnormal, cur.AbnormalTime = 1, sC
		}
		cur.FileName = fmtName(p.copyName(name418, buf, 0x50, 0x52)) // 0x413dc2
		p.fullPathFor(cur, pr)
		mftLoc(cur, pr)
		cur.AttrName = attrName(le32(buf, 0x48))
		// 0x40e0f0 runs on the formatted copy: for a blank name it reads two units of the uninitialised tail, but
		// both outcomes leave a FileName that every later use reads as "".
		if isDos83ShortName(cur.FileName) {
			cur.FileName = ""
		}
		cur.Event = "Temp Event"

	case (r == 0xe && u == 0xf) || (r == 0xc && u == 0xd): // D: Add Index Entry
		pr := le64(buf, 0x10)
		cur.ParentRef = pr
		cur.CreateTime, cur.ModifiedTime = fmtRaw(st1448, le64(buf, 0x18)), fmtRaw(st1460, le64(buf, 0x20))
		cur.MFTModifiedTime, cur.AccessTime = fmtRaw(st1438, le64(buf, 0x28)), fmtRaw(st1428, le64(buf, 0x30))
		if allStart20(cur) {
			cur.FileName = fmtName(p.copyName(name418, buf, 0x50, 0x52)) // 0x41460a
			p.fullPathFor(cur, pr)
			mftLoc(cur, pr)
			cur.Event = "Temp Event"
		} else {
			cur.CreateTime, cur.ModifiedTime, cur.MFTModifiedTime, cur.AccessTime = "", "", "", ""
		}

	case r == 7 && u == 7: // E: Update Resident Value
		switch {
		case recOff >= 0xf8 && attrOff == 0x18: // E1: resident content write
			redoNZ, undoZero, useOfs := false, true, false
			if cur.RedoFileOff>>32 == 0 && uint32(cur.RedoFileOff) < le32(rec, 0x18) {
				for i := int32(0); uint64(int64(i)) < cur.RedoLen; i++ {
					if buf[i] != 0 {
						redoNZ = true
					}
				}
				for i := int32(le16(rec, 0x38)) - 0x28; uint64(int64(i)) < cur.UndoLen; i++ {
					if buf[i] != 0 {
						undoZero = false
					}
				}
				useOfs = redoNZ && undoZero
			}
			cur.Event = "Writing Content of Resident File"
			if useOfs {
				cur.Detail = "Data Offset(in $LogFile) : " + strconv.FormatUint(cur.RedoFileOff, 10)
			} else {
				cur.Detail = fmt.Sprintf("Writing Size : %d", int64(cur.RedoLen))
			}
			p.scanCreation(cur, 30)
		case recOff == 0x38 && attrOff == 0x20: // E2: $STANDARD_INFORMATION time update
			t := fmtAdj(st1448, le64(buf, 8))
			n := len(p.rows)
			if n == 0 {
				break
			}
			counter := 1
			for j := 1; ; {
				l := p.rows[n-j]
				if l.Event != "" {
					m := l.MftVCN == cur.TargetVCN && l.MftBlock == cur.ClusterBlockOffset
					if m && strings.Contains(l.Event, "File Creation") {
						if t != l.CreateTime {
							p.store.UpdateTimeEventDetail(l.LSN, t, "File Creation(File System Tunneling)", l.Detail)
							p.updateQuery(q1468)
						}
						break
					}
					if m && (strings.Contains(l.Event, "Deletion") || strings.Contains(l.Event, "Renaming") ||
						strings.Contains(l.Event, "Moving")) {
						p.store.UpdateEventTime(l.LSN, t)
						p.updateQuery(q1468)
						break
					}
					counter++
				}
				j++
				if n-j < 0 || counter == 10 {
					break
				}
			}
		}

	case r == 9 && u == 9: // F: Update Mapping Pairs
		if !(recOff > 0xf8 && attrOff == 0x40) {
			break
		}
		runs, sm := decodeRunsF(buf, redoLen)
		smashed = sm
		cur.Runs = runs
		if strings.Contains(runs, "(") {
			p.checkParser(smashed) // 0x41553a: the look-back reads the row list through the Parser*
			cur.Detail = "Data Runs(in Volume) : " + runs
			cur.Event = "Writing Content of Non-Resident File"
			p.scanCreation(cur, 30)
		}

	case r == 6 && u == 5: // G: Delete Attribute $FILE_NAME
		if !(recOff >= 0x98 && attrOff == 0 && le32(buf, 0) == 0x30) {
			break
		}
		name := fmtName(p.copyName(name218, buf, 0x58, 0x5a)) // 0x41575a (the copy wcsstr tests), 0x4157a9 (FileName)
		if strings.Contains(name, "~") {
			break
		}
		cur.FileName = name
		pr := le64(buf, 0x18)
		cur.ParentRef = pr
		p.fullPathFor(cur, pr)
		cur.Event = "Temp Event"
		if (prev.RedoInfo == "Delete Index Entry Allocation" && prev.UndoInfo == "Add Index Entry Allocation") ||
			(prev.RedoInfo == "Delete Index Entry Root" && prev.UndoInfo == "Add Index Entry Root") {
			cur.MftVCN = prev.MftVCN
		}
		cur.MftBlock = prev.MftBlock

	case r == 5 && u == 6: // H: Create Attribute $FILE_NAME (rename / move)
		if !(recOff >= 0x98 && attrOff == 0 && le32(buf, 0) == 0x30) {
			break
		}
		cur.AttrName = attrName(le32(buf, 0x50))
		name := fmtName(p.copyName(name418, buf, 0x58, 0x5a)) // 0x415b9e (the copy wcsstr tests), 0x415bf3 (FileName)
		if strings.Contains(name, "~") {
			break
		}
		cur.FileName = name
		pr := le64(buf, 0x18)
		cur.ParentRef = pr
		p.fullPathFor(cur, pr)
		n := len(p.rows)
		if n == 0 {
			break
		}
		counter := 1
		for j := 1; ; {
			l := &p.rows[n-j]
			if l.RedoInfo == "Delete Attribute" && l.TargetVCN == cur.TargetVCN && l.ClusterBlockOffset == cur.ClusterBlockOffset {
				prev.FileName, prev.ParentRef, prev.MftVCN, prev.MftBlock = l.FileName, l.ParentRef, l.MftVCN, l.MftBlock
				if cur.ParentRef == prev.ParentRef {
					cur.Detail = prev.FileName + " -> " + cur.FileName
					if cur.AttrName == "Directory" {
						cur.Event = "Renaming Directory"
					} else {
						cur.Event = "Renaming File"
					}
				} else {
					p.store.UpdateEvent(l.LSN, "Move(Before)")
					p.updateQuery(q1450)
					cur.Event = "Move(After)"
				}
				cur.MftVCN, cur.MftBlock = prev.MftVCN, prev.MftBlock
				break
			}
			counter++
			j++
			if n-j < 0 {
				break
			}
			if counter == 10 {
				cur.Event = "Temp Event"
				break
			}
		}

	default:
		cur.Event = ""
	}
	if cur.Event != "" {
		p.checkParser(smashed) // 0x416150: push_back on Parser+0x12c
		p.txn = append(p.txn, *cur)
	}
}

// runLenSmash is the smallest run length size that reaches the saved Parser*: both decoders memcpy lenSz bytes
// into the 8-byte length [ebp-0x1488] (A 0x413123, F 0x415273); [ebp-0x1480] is unused, [ebp-0x147c] holds the
// Parser* stored at entry (0x41274f), and 15 bytes end before the CString at [ebp-0x1478].
const runLenSmash = 13

// checkParser is a dereference of the saved Parser* after a run decoder overwrote its low bytes with run data.
// The corrupted pointer lands somewhere near the heap object; the oracle shows the process dying (sem-046), and
// what it would read instead depends on heap addresses, so this is the original's failure point. The next call
// stores the pointer again, so a smash that is never dereferenced is harmless.
func (p *parser) checkParser(smashed bool) {
	if smashed {
		panic(ErrOriginalCrash.Error() + ": run length field of 13..15 bytes overwrote the saved Parser*")
	}
}

// copyName is the memcpy of a $FILE_NAME name (2*len bytes) into the frame buffer st412[at], followed by the u16
// at [ebp-0x148c], which every branch that copies a name has set to 0 (0x41276d, 0x415735, 0x415a30).
func (p *parser) copyName(at int, buf []byte, lenOff, nameOff int) string {
	n := int(buf[lenOff])
	copy(p.st412[at:at+2*n], buf[nameOff:nameOff+2*n])
	p.st412[at+2*n], p.st412[at+2*n+1] = 0, 0
	return readName(buf, lenOff, nameOff)
}

// scanCreation copies FileName/FullPath from the newest "File Creation" row at the same MFT location (E1, F).
func (p *parser) scanCreation(cur *Record, limit int) {
	n := len(p.rows)
	if n == 0 {
		return
	}
	counter := 1
	for j := 1; ; {
		l := &p.rows[n-j]
		if l.Event != "" {
			if l.TargetVCN == cur.TargetVCN && l.ClusterBlockOffset == cur.ClusterBlockOffset && strings.Contains(l.Event, "File Creation") {
				cur.FileName, cur.FullPath = l.FileName, l.FullPath
				return
			}
			counter++
		}
		j++
		if n-j < 0 || counter == limit {
			return
		}
	}
}

func allStart20(r *Record) bool {
	return strings.HasPrefix(r.CreateTime, "20") && strings.HasPrefix(r.ModifiedTime, "20") &&
		strings.HasPrefix(r.MFTModifiedTime, "20") && strings.HasPrefix(r.AccessTime, "20")
}

// readName reads a $FILE_NAME name: length in characters at lenOff, UTF-16 at nameOff, cut at the first NUL.
func readName(buf []byte, lenOff, nameOff int) string {
	n := int(buf[lenOff])
	return cstr(utf16Str(buf[nameOff:nameOff+2*n], n))
}

// fmtName is Format("%s", name) (0x4035b0 -> FormatV 0x403530), through which every $FILE_NAME name passes:
// A 0x412e5a, C 0x413dc2, D 0x41460a, G 0x41575a/0x4157a9, H 0x415b9e/0x415bf3 and the $MFT pre-pass 0x41677c.
// FormatV takes the length from _vscwprintf (0x541db4), which only counts. vswprintf_s (0x541c2b, result ignored)
// writes through the CRT's _putwc_nolock, which returns the unit written: U+FFFF equals WEOF, so the write counts
// as failed and the output stops. vswprintf_s then stores NUL at [0] (and [len]), and FormatV keeps the counted
// length. The units after [0] are the name up to the U+FFFF and then uninitialised heap; no output can show them.
// Every pointer use (wcscmp, wcsstr, wcschr, "%s" into the INSERT) sees "", and CString concatenation keeps the
// leading NUL, so "\\" + name or path + "\\" + name show the prefix only and the H Detail "old -> new" with a blank
// old name shows "" (oracle sem-011, vhd-038, mft-012, audit-attr-time-mft-005). U+FFFE is written normally.
// The blank string is kept as "\x00": its users cut at the first NUL (cstr) or concatenate it.
func fmtName(name string) string {
	if strings.ContainsRune(name, 0xFFFF) {
		return "\x00"
	}
	return name
}

// isDos83ShortName is 0x40e0f0.
func isDos83ShortName(name string) bool {
	u := toUTF16(name)
	digit := func(c uint16) bool { return c >= '1' && c <= '9' }
	for i, c := range u {
		if c == '.' {
			if i < 2 || u[i-2] != '~' {
				return false
			}
			return digit(u[i-1])
		}
	}
	n := len(u)
	if n < 2 || u[n-2] != '~' {
		return false
	}
	return digit(u[n-1])
}

func isRootRef(r uint64) bool { return uint32(r) == 5 && (r>>32)&0xffff == 0 }

// mftLoc derives the MFT record's (VCN, cluster block offset) from a file reference, assuming 4 KiB clusters
// and 1 KiB records as the original does.
func mftLoc(cur *Record, ref uint64) {
	lo, hi := uint32(ref), uint32(ref>>32)&0xffff
	cur.MftBlock = uint64((lo & 3) * 2)
	cur.MftVCN = fmt.Sprintf("0x%X", uint32((uint64(hi)<<32|uint64(lo))>>2))
}

var attrNames = map[uint32]string{1: "ReadOnly", 2: "Hidden", 4: "System", 0x20: "Archive", 0x40: "Device",
	0x80: "Normal", 0x100: "Temporary", 0x200: "Sparse", 0x400: "ReparsePoint", 0x800: "Compressed",
	0x1000: "Offline", 0x2000: "NotIndexedContent", 0x4000: "Encrypted", 0x10000000: "Directory",
	0x20000000: "IndexView"}

func attrName(v uint32) string { return attrNames[v] }

// wcsGreater is operator>(CStringW, CStringW): ordinal comparison of UTF-16 code units.
func wcsGreater(a, b string) bool {
	ua, ub := toUTF16(a), toUTF16(b)
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] > ub[i]
		}
	}
	return len(ua) > len(ub)
}

func signExtend(b []byte) int64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	shift := uint(64 - 8*len(b))
	return int64(v<<shift) >> shift
}

func appendRun(out string, lcn int64, length uint64) string {
	if out == "" {
		return fmt.Sprintf("%d(%d)", uint64(lcn), length)
	}
	return out + fmt.Sprintf(",%d(%d)", uint64(lcn), length)
}

// decodeRunsA is the branch-A mapping-pairs decoder (length and offset reset for every run). smashed reports a
// length size of runLenSmash or more.
func decodeRunsA(src []byte) (out string, smashed bool) {
	var lcn int64
	i := 0
	for src[i] != 0 {
		h := src[i]
		i++
		ofsSz, lenSz := int(h>>4), int(h&0xf)
		if ofsSz == 0 || lenSz == 0 {
			break
		}
		var length uint64
		for k := 0; k < lenSz && k < 8; k++ { // bytes 8..11 land in the unused [ebp-0x1480]
			length |= uint64(src[i+k]) << (8 * k)
		}
		smashed = smashed || lenSz >= runLenSmash
		i += lenSz
		var off int64
		if ofsSz <= 8 {
			off = signExtend(src[i : i+ofsSz])
		}
		i += ofsSz
		lcn += off
		out = appendRun(out, lcn, length)
	}
	return out, smashed
}

// decodeRunsF is the branch-F decoder: length and offset keep bytes from the previous run, and the run that
// reaches redo_len is dropped. smashed as in decodeRunsA.
func decodeRunsF(buf []byte, redoLen int32) (out string, smashed bool) {
	var lcn, off int64
	var length uint64
	i := 0
	if buf[0] == 0 {
		return out, false
	}
	for {
		h := buf[i]
		i++
		ofsSz, lenSz := int(h>>4), int(h&0xf)
		if ofsSz == 0 || lenSz == 0 {
			break
		}
		for k := 0; k < lenSz && k < 8; k++ {
			length = length&^(uint64(0xff)<<(8*k)) | uint64(buf[i+k])<<(8*k)
		}
		smashed = smashed || lenSz >= runLenSmash
		i += lenSz
		if ofsSz >= 1 && ofsSz <= 8 {
			off = signExtend(buf[i : i+ofsSz])
		}
		i += ofsSz
		if int32(i) >= redoLen {
			break
		}
		lcn += off
		out = appendRun(out, lcn, length)
		if buf[i] == 0 {
			break
		}
	}
	return out, smashed
}
