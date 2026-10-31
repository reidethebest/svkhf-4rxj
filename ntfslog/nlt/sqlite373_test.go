package nlt

import "testing"

// w builds a WTF-8 string from UTF-16 units (lone surrogates allowed).
func w(u ...uint16) string { return fromUTF16(u) }

func TestSQLiteText(t *testing.T) {
	cases := []struct {
		name, in, want string
		ok             bool
	}{
		{"doubled quote", "it''s.txt", "it's.txt", true},
		{"valid pair", "\U0001F600.txt", "\U0001F600.txt", true},
		// sem-008: the lone D800 consumes 'c' and is stored as D800 DC63 (U+10063).
		{"lone high mid", "ab" + w(0xD800) + "cd.txt", "ab\U00010063d.txt", true},
		// mft-013: D83D consumes the path separator.
		{"lone high before backslash", "docs" + w(0xD83D) + `\x`, "docs\U0001F45Cx", true},
		{"lone low mid", w(0xDC00, 'a'), "\U00010061", true},
		// sem-009 / vhd-038 "end low DC00": the closing quote is consumed, the statement does not compile.
		{"lone low at end", "end low" + w(0xDC00), "", false},
		// sem-010 / vhd-038 "q D800 'x": the first quote of the doubled pair is consumed.
		{"lone high before quote", "q" + w(0xD800) + "''x", "", false},
		// Two high surrogates: the first consumes the second, the quote after them survives.
		{"surrogate consumes surrogate", w('a', 0xD800, 0xD801) + "''", "a\U00010001'", true},
		// READ_UTF8: U+FFFE and U+FFFF are stored as U+FFFD.
		{"nonchars", "a\uFFFEb\uFFFF", "a\uFFFDb\uFFFD", true},
	}
	for _, c := range cases {
		got, ok := sqliteText(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: sqliteText(%q) = %q, %v; want %q, %v", c.name, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestLSNKeyText(t *testing.T) {
	// REAL texts recorded in the CSVs of oracle lfs-069 and lfs-070 ("%!.15g" of float64(n - n%10)); the four
	// marked ones differ from a correctly rounded %.15g.
	cases := []struct {
		n    uint64
		text string
	}{
		{9223372036854775807, "9223372036854775807"},
		{1 << 63, "9.22337203685478e+18"},
		{1<<64 - 1, "1.84467440737096e+19"},
		{9223372036854776131, "9.22337203685478e+18"},
		{9223372036855847947, "9.22337203685585e+18"},
		{9223372036855872638, "9.22337203685588e+18"}, // %.15g: ...587e+18
		{9223372036855913579, "9.22337203685592e+18"}, // %.15g: ...591e+18
		{9223372036854793295, "9.2233720368548e+18"},  // %.15g: 9.22337203685479e+18
		{9223372036854803643, "9.22337203685481e+18"}, // %.15g: 9.2233720368548e+18
	}
	for _, c := range cases {
		if got := lsnKeyOf(c.n).text(); got != c.text {
			t.Errorf("lsnKeyOf(%d).text() = %q, want %q", c.n, got, c.text)
		}
	}
}

func insertRow(s *Store, lsn, name string) {
	s.InsertLogFileRow(&Record{LSN: lsn, Event: "File Creation", FileName: name})
}

func TestStoreLSNAbove2p63(t *testing.T) {
	s := NewStore(nil)
	insertRow(s, "9223372036855872817", "second") // REAL 9223372036855873536
	insertRow(s, "9223372036854775633", "int")    // INTEGER 2^63-175: a double 2^63, yet no collision
	insertRow(s, "9223372036854775808", "2^63")   // REAL 2^63
	insertRow(s, "9223372036855872638", "dup")    // same REAL as the first row: rejected
	s.UpdateEvent("9223372036855872638", "Move(Before)")
	if s.Conflicts() != 1 {
		t.Errorf("conflicts = %d, want 1", s.Conflicts())
	}
	byLSN, _ := s.Rows()
	var got []string
	for _, r := range byLSN {
		got = append(got, r.key.text()+" "+r.Cols[3]+" "+r.Cols[1])
	}
	want := []string{"9223372036854775633 int File Creation", "9.22337203685478e+18 2^63 File Creation",
		"9.22337203685588e+18 second Move(Before)"}
	if len(got) != len(want) {
		t.Fatalf("rows = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestStoreDroppedStatement(t *testing.T) {
	s := NewStore(nil)
	insertRow(s, "1", "a")
	insertRow(s, "2", "end"+w(0xD800)) // prepare16 fails: no row, no rowid
	insertRow(s, "3", "ab"+w(0xD800)+"c")
	_, byRowID := s.Rows()
	if len(byRowID) != 2 || byRowID[1].RowID != 2 || byRowID[1].LSN != 3 || byRowID[1].Cols[3] != "ab\U00010063" {
		t.Errorf("rows after a dropped statement: %+v", byRowID)
	}
}

func TestFmtName(t *testing.T) {
	if got := fmtName("it's \uFFFFere.txt"); got == "" || cstr(got) != "" {
		t.Errorf("fmtName with U+FFFF = %q, want a blank (leading NUL) name", got)
	}
	if got := fmtName("a\uFFFEb"); got != "a\uFFFEb" {
		t.Errorf("fmtName with U+FFFE = %q, want it unchanged", got)
	}
	if got := cstr("\\weird\\" + fmtName("\uFFFFnonchar")); got != `\weird\` {
		t.Errorf("path + blank name = %q, want the prefix only", got)
	}
}
