package nlt

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Store emulates the effect of the SQL statements the original executes against its LogFile table: rows keyed by
// LSN (PRIMARY KEY, so a second insert of the same LSN fails and the first row wins), rowids assigned to successful
// inserts in order, updates by LSN, and the final delete of the 'Temp Event' rows. Optionally it writes every
// statement, exactly as the original would prepare it, to a JSONL trace for statement-level comparison.
type Store struct {
	rows      map[lsnKey]*Row
	nextRowID int64
	conflicts int
	trace     *bufio.Writer
	TZ        struct{ UTC, DST int }
}

// Row is one LogFile table row as stored by SQLite.
type Row struct {
	RowID int64
	LSN   uint64 // the record's LSN ("%I64u")
	key   lsnKey // the value SQLite stores for it: INTEGER, or REAL from 2^63 on
	// EventTime, Event, Detail, FileName, FullPath, CreateTime, ModifiedTIme, MFT_ModifiedTime, AccessTime,
	// RedoInfo, TargetVCN, MFT_ClusterIndex.
	Cols [12]string
}

// ColumnNames are the LogFile columns in table order.
var ColumnNames = [13]string{"LSN", "EventTime", "Event", "Detail", "FileName", "FullPath", "CreateTime",
	"ModifiedTIme", "MFT_ModifiedTime", "AccessTime", "RedoInfo", "TargetVCN", "MFT_ClusterIndex"}

func NewStore(trace io.Writer) *Store {
	s := &Store{rows: make(map[lsnKey]*Row)}
	if trace != nil {
		s.trace = bufio.NewWriterSize(trace, 1<<16)
	}
	return s
}

func (s *Store) emit(sql string) {
	if s.trace == nil {
		return
	}
	s.trace.WriteString(`{"sql":`)
	s.trace.WriteString(jsonQuote(sql))
	s.trace.WriteString("}\n")
}

// Flush writes any buffered trace output.
func (s *Store) Flush() error {
	if s.trace == nil {
		return nil
	}
	return s.trace.Flush()
}

// Conflicts is the number of inserts rejected by the LSN primary key.
func (s *Store) Conflicts() int { return s.conflicts }

const insertFmt = "insert into LogFile (LSN, EventTime, Event, Detail,  FileName, FullPath, CreateTime, ModifiedTIme, MFT_ModifiedTime, AccessTime, RedoInfo, TargetVCN, MFT_ClusterIndex) \t\t\t\t\tvalues(%s, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"

// InsertLogFileRow is 0x41a7d0. It mutates the record's strings in place exactly like the original (quotes
// doubled, commas replaced by '/'), because later code reads the mutated copy. The row holds what SQLite 3.7.3
// stores for the statement (sqliteText, lsnKeyOf).
func (s *Store) InsertLogFileRow(r *Record) {
	cluster := strconv.FormatUint(r.ClusterBlockOffset, 10)
	fields := []*string{&r.LSN, &r.EventTime, &r.Event, &r.Detail, &r.FileName, &r.FullPath, &r.CreateTime,
		&r.ModifiedTime, &r.MFTModifiedTime, &r.AccessTime, &r.RedoInfo, &r.TargetVCN, &cluster}
	for _, f := range fields {
		*f = strings.ReplaceAll(*f, "'", "''")
	}
	for _, f := range fields {
		*f = strings.ReplaceAll(*f, ",", "/")
	}
	vals := make([]any, len(fields))
	for i, f := range fields {
		vals[i] = cstr(*f)
	}
	sql := fmt.Sprintf(insertFmt, vals...)
	s.emit(sql)

	var cols [12]string
	for i, v := range vals[1:] {
		t, ok := sqliteText(v.(string))
		if !ok {
			return // prepare16 fails (a lone surrogate consumed a quote): no row, no rowid
		}
		cols[i] = t
	}
	lsn, err := strconv.ParseUint(cstr(r.LSN), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("non-numeric LSN %q", r.LSN))
	}
	key := lsnKeyOf(lsn)
	if _, dup := s.rows[key]; dup {
		s.conflicts++
		return
	}
	s.nextRowID++
	s.rows[key] = &Row{RowID: s.nextRowID, LSN: lsn, key: key, Cols: cols}
}

// sqlUnquote is the value SQLite stores for the literal '<v>' where v already has its quotes doubled.
func sqlUnquote(v string) string { return strings.ReplaceAll(v, "''", "'") }

func (s *Store) update(lsn string, sql string, set func(*Row)) {
	s.emit(sql)
	n, err := strconv.ParseUint(lsn, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("non-numeric LSN %q in update", lsn))
	}
	if r, ok := s.rows[lsnKeyOf(n)]; ok {
		set(r)
	}
}

// literal is the value SQLite stores for the text the original formats between quotes. The original never escapes
// UPDATE values; they come from already-escaped copies, so every quote is doubled. A lone quote would make the
// statement fail and the original abort the parse. UPDATE values are times, constants and the Detail of an A row
// (empty or data runs), all ASCII, so the Unicode rules of sqliteText never change them.
func literal(v string) string {
	if strings.Count(strings.ReplaceAll(v, "''", ""), "'") != 0 {
		panic(fmt.Sprintf("%v: unescaped quote in UPDATE value %q", ErrOriginalCrash, v))
	}
	return sqlUnquote(v)
}

// UpdateEventTime is "update LogFile set EventTime='%s' where LSN=%s".
func (s *Store) UpdateEventTime(lsn, t string) {
	t, lsn = cstr(t), cstr(lsn)
	s.update(lsn, fmt.Sprintf("update LogFile set EventTime='%s' where LSN=%s", t, lsn), func(r *Row) {
		r.Cols[0] = literal(t)
	})
}

// UpdateTimeEventDetail is "update LogFile set EventTime='%s', Event='%s', Detail='%s' where LSN=%s".
func (s *Store) UpdateTimeEventDetail(lsn, t, event, detail string) {
	t, event, detail, lsn = cstr(t), cstr(event), cstr(detail), cstr(lsn)
	s.update(lsn, fmt.Sprintf("update LogFile set EventTime='%s', Event='%s', Detail='%s' where LSN=%s", t, event, detail, lsn),
		func(r *Row) {
			r.Cols[0], r.Cols[1], r.Cols[2] = literal(t), literal(event), literal(detail)
		})
}

// UpdateEvent is "update LogFile set Event='%s' where LSN=%s".
func (s *Store) UpdateEvent(lsn, event string) {
	event, lsn = cstr(event), cstr(lsn)
	s.update(lsn, fmt.Sprintf("update LogFile set Event='%s' where LSN=%s", event, lsn), func(r *Row) {
		r.Cols[1] = literal(event)
	})
}

// DeleteTempEvents is "delete from LogFile where Event='Temp Event'".
func (s *Store) DeleteTempEvents() {
	s.emit("delete from LogFile where Event='Temp Event'")
	for k, r := range s.rows {
		if r.Cols[1] == "Temp Event" {
			delete(s.rows, k)
		}
	}
}

// SetTimeZone is "insert into TimeZone (UTC, DST) values(%d, %d)".
func (s *Store) SetTimeZone(utc, dst int) {
	s.emit(fmt.Sprintf("insert into TimeZone (UTC, DST) values(%d, %d)", utc, dst))
	s.TZ.UTC, s.TZ.DST = utc, dst
}

// Rows returns the table ordered by LSN (the CSV export order) and by rowid.
func (s *Store) Rows() (byLSN, byRowID []*Row) {
	byLSN = make([]*Row, 0, len(s.rows))
	for _, r := range s.rows {
		byLSN = append(byLSN, r)
	}
	byRowID = append([]*Row(nil), byLSN...)
	slices.SortFunc(byLSN, func(a, b *Row) int { return a.key.compare(b.key) })
	slices.SortFunc(byRowID, func(a, b *Row) int { return cmp.Compare(a.RowID, b.RowID) })
	return byLSN, byRowID
}

// jsonQuote quotes a WTF-8 string as JSON, escaping lone surrogates as \uXXXX.
func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	u := toUTF16(s)
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c < 0x20:
			fmt.Fprintf(&b, `\u%04x`, c)
		case c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000:
			b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
		case c >= 0xD800 && c < 0xE000:
			fmt.Fprintf(&b, `\u%04x`, c)
		default:
			b.WriteRune(rune(c))
		}
	}
	b.WriteByte('"')
	return b.String()
}
