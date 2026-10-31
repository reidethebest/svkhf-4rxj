package nlt

// $MFT correlation state (filled by the $MFT pre-pass 0x416310) and its consumers in the $LogFile pass.
// Specification: re/spec/04-attributes-time-paths.md.

// dirEntry is the value of multimap p+0x00 (key = the file's own reference).
type dirEntry struct {
	parentRef uint64
	isDir     byte
	name      string
}

// v40Entry is the value of multimap p+0x10 (key = LSN of the MFT FILE record).
type v40Entry struct {
	parentRef, ownRef                     uint64
	name                                  string
	create, modified, mftModified, access uint64
}

// v40Lookup runs for every accepted record (0x41007e): a FILE record whose LSN equals this record's LSN gives the
// record its name, path and $STANDARD_INFORMATION times.
func (p *parser) v40Lookup(cur *Record, lsn uint64) {
	es := p.v40[lsn]
	if len(es) == 0 {
		return
	}
	e := es[0]
	cur.FileName = e.name
	p.buildFullPath(e.ownRef, e.name)
	cur.FullPath = p.path
	cur.CreateTime, cur.ModifiedTime = p.v40Time(0x10, e.create), p.v40Time(0x20, e.modified)
	cur.MFTModifiedTime, cur.AccessTime = p.v40Time(0x30, e.mftModified), p.v40Time(0, e.access)
}

// v40Time converts one V40 FILETIME through its own SYSTEMTIME local of 0x40e340, slot = offset in p.v40ST:
// C [ebp-0x31fc] (0x41047a), M [ebp-0x31ec] (0x410548), MFT-M [ebp-0x31dc] (0x410616), A [ebp-0x320c] (0x4106e4),
// then AdjustTimeString (0x41050d, 0x4105db, 0x4106a9, 0x410777). Nothing else in 0x40e340 touches these locals,
// so a failed conversion (FILETIME >= 2^63) repeats the same field of the previous V40 hit in this parse.
func (p *parser) v40Time(slot int, ft uint64) string {
	a, _ := adjustTimeString(fileTimeToSlot(p.v40ST[slot:slot+0x10], ft), p.tz)
	return a
}

func (p *parser) findDir(ref uint64) (dirEntry, bool) {
	es := p.dir[ref]
	if len(es) == 0 {
		return dirEntry{}, false
	}
	return es[0], true
}

// buildFullPath is 0x41adf0; the result goes to p.path (p+0x184).
func (p *parser) buildFullPath(ref uint64, name string) {
	if isRootRef(ref) {
		p.path = "\\" + name
		return
	}
	p.path = name
	e, ok := p.findDir(ref)
	if !ok {
		p.path = ""
		return
	}
	it, ok := p.findDir(e.parentRef)
	if !ok {
		p.path = ""
		return
	}
	for steps := 0; ; steps++ {
		// Without a cycle the walk meets every directory-map key at most once. More steps mean a parent cycle:
		// the original prepends names forever right here (the hang only happens when a row needs this path).
		if steps > len(p.dir) {
			panic(ErrOriginalCrash.Error() + ": parent cycle in $MFT directory map (the original loops forever)")
		}
		if it.name == "." {
			p.path = "\\" + p.path
			return
		} else if it.isDir == 0 {
			return
		}
		p.path = it.name + "\\" + p.path
		pr := it.parentRef
		if isRootRef(pr) {
			p.path = "\\" + p.path
			return
		}
		if it, ok = p.findDir(pr); !ok {
			p.path = ""
			return
		}
	}
}

// fullPathFor sets cur.FullPath from a parent reference, or leaves it unchanged when the parent is unknown.
func (p *parser) fullPathFor(cur *Record, parentRef uint64) {
	if isRootRef(parentRef) {
		cur.FullPath = "\\" + cur.FileName
		return
	}
	e, ok := p.findDir(parentRef)
	if !ok {
		return
	}
	p.buildFullPath(parentRef, e.name)
	cur.FullPath = p.path + "\\" + cur.FileName
}

// mftReadSpan bounds every read of the $MFT pre-pass from its record buffer: attribute offset <= 0x400 (0x416857),
// value offset u16, then a $FILE_NAME name of up to 0xff UTF-16 units at +0x42; usa_ofs u16 plus the second fixup.
const mftReadSpan = 0x400 + 0x10000 + 0x42 + 0x200

// parseMFT is the $MFT pre-pass 0x416310: fills the V40 map (key = FILE record LSN) and the directory map
// (key = record number | sequence << 48, with the original's sequence-bit leak across skipped records).
func (p *parser) parseMFT(mft []byte) error {
	p.v40 = make(map[uint64][]v40Entry)
	p.dir = make(map[uint64][]dirEntry)
	// The record buffer is malloc(0xa00000) (0x41637b), allocated once and never freed or cleared; every record is
	// read into its first 0x400 bytes (0x416604) and nothing else writes it. A block that size comes straight from
	// VirtualAlloc, so the bytes past 0x400 are zero for the whole pre-pass. The walk reads far past the record:
	// usa_ofs up to 0xffff (+6), a value offset up to 0x400+0xffff (+0x42+0x1fe for the name), so mftReadSpan
	// covers every reachable byte and the rest of the buffer is never touched.
	r := make([]byte, mftReadSpan)
	var si [4]uint64
	siSeen := false
	var hiAcc uint32
	// st20 is the SYSTEMTIME [ebp-0x20] of p+0x1a8's conversion (0x4167b5), written by nothing else: a failed
	// conversion keeps an earlier $MFT $FN's value from the same record 0 (uninitialised before, zero here).
	var st20 [0x10]byte
	for i := 0; i < len(mft)>>10; i++ {
		copy(r, mft[i<<10:(i+1)<<10])
		if !(string(r[0:4]) == "FILE" && (r[4] == 0x30 || r[4] == 0x2a) && le16(r, 0x14) < 0x1f4) {
			hiAcc &= 0xffff
			continue
		}
		if le16(r, 6) > 0 {
			usa := int(le16(r, 4))
			usn := [2]byte{r[usa], r[usa+1]} // loaded once into ax (0x416665) and compared at both sector ends
			for k, end := range []int{0x1fe, 0x3fe} {
				if r[end] == usn[0] && r[end+1] == usn[1] {
					copy(r[end:end+2], r[usa+2*(k+1):usa+2*(k+1)+2])
				}
			}
		}
		hiAcc |= uint32(le16(r, 0x10)) << 16
		key := uint64(uint32(i)) | uint64(hiAcc)<<32
		name := ""
		var parent uint64
		off := int(le16(r, 0x14))
		for {
			alen := le32(r, off+4)
			if alen == 0 {
				break
			}
			typ := le32(r, off)
			v := off + int(le16(r, off+0x14))
			if r[off+8] != 0 {
				v = off + int(le16(r, off+0x20))
			}
			if typ == 0x10 {
				si = [4]uint64{le64(r, v), le64(r, v+8), le64(r, v+0x10), le64(r, v+0x18)}
				siSeen = true
			}
			if typ == 0x30 && r[v+0x40] != 0 && r[v+0x41] != 2 {
				parent = le64(r, v)
				n := int(r[v+0x40])
				// Format("%s") of the zero-padded copy (0x41677c). A blanked name (fmtName) is "" for every test
				// that follows (wcscmp 0x403290), so the record is skipped (0x41686d).
				name = cstr(fmtName(cstr(utf16Str(r[v+0x42:v+0x42+2*n], n))))
				if name == "$MFT" && i == 0 {
					p.mftCreate = fileTimeToSlot(st20[:], si[0])
				}
			}
			if alen > 0x400 || typ > 0xff {
				break
			}
			off += int(alen)
			if off > 0x400 || le32(r, off) == 0xffffffff {
				break
			}
		}
		if name == "" || !siSeen {
			continue
		}
		lsn := le64(r, 8)
		p.v40[lsn] = append(p.v40[lsn], v40Entry{parentRef: parent, ownRef: key, name: name,
			create: si[0], modified: si[1], mftModified: si[2], access: si[3]})
		f := le16(r, 0x16)
		switch {
		case (f == 2 || f == 3) && key != parent && name != ".":
			p.dir[key] = append(p.dir[key], dirEntry{parentRef: parent, isDir: 1, name: name})
		case (f == 0 || f == 1) && key != parent && name != ".":
			p.dir[key] = append(p.dir[key], dirEntry{parentRef: parent, isDir: 0, name: name})
		case name == ".":
			p.dir[key] = append(p.dir[key], dirEntry{parentRef: parent, isDir: 1, name: name})
		}
		hiAcc &= 0xffff
	}
	return nil
}
