package nlt

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// csvHeaderLabel is the EventTime column label chosen in 0x42d640 from the TimeZone row (UTC sign, DST == 1).
func csvHeaderLabel(utc, dst int) string {
	switch {
	case utc > 0 && dst == 1:
		return fmt.Sprintf("EventTime(UTC+%d DST)", utc)
	case utc > 0:
		return fmt.Sprintf("EventTime(UTC+%d)", utc)
	case utc < 0 && dst == 1:
		return fmt.Sprintf("EventTime(UTC%d,DST)", utc)
	case utc < 0:
		return fmt.Sprintf("EventTime(UTC%d)", utc)
	case dst == 1:
		return fmt.Sprintf("EventTime(UTC %d,DST)", utc)
	default:
		return fmt.Sprintf("EventTime(UTC %d)", utc)
	}
}

const csvHeaderFmt = "\"LSN\",\"%s\",\"Event\",\"Detail\",\"File/Directory Name\",\"Full Path\",\"Create Time\",\"Modified Time\",\"MFT_Modified Time\",\"Access Time\",\"Redo\",\"Target VCN\",\"Cluster Index\"\r\n"

// WriteCSV writes NLT_LogFile_*.csv content as 0x42d640 does: header, then every row of
// "select ... from LogFile ORDER BY LSN" as 13 quoted fields with no escaping, CRLF, converted from UTF-16 to the
// thread ANSI code page (best-fit, '?' for unmappable characters). No BOM.
//
// Each value is read back with sqlite3_get_table (UTF-8), MultiByteToWideChar(CP_UTF8) into the 0x1000-unit buffer
// of fieldValue (0x4042b0), wcslen and SetString (0x403100 at 0x42e461): the stored units, unchanged.
//
// Known nondeterministic area (SPEC 8.5, U10; spec 06 edge case 10): fieldValue returns its own, already released
// stack buffer (buf[k] at S-0x200c+2k, S = esp at 0x42e435). SetString's frame and its heap allocation reuse that
// stack before memcpy_s (0x403187) copies the value, so every unit from (0x200c-D)/2 on is whatever that call chain
// left there, D being its stack depth: always from about 0xfd6 on (SetString's own frame), and from unit 0xe8c or
// 0xdaa in the recorded runs, depending on the heap's path (the two runs of the original differ there on vhd-018,
// vhd-041, vhd2-018, vhd2-041 and audit-driver-csv-001). A value of 0x1000 units or more fills the buffer without
// a terminator, so wcslen runs on into the dead frame. None of that is reproducible: such a field is written
// intact, which is what the original writes whenever the garbage does not reach it (every field shorter than 0xdaa
// units in every recorded run).
func WriteCSV(w io.Writer, s *Store) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	if _, err := bw.Write(toACP(fmt.Sprintf(csvHeaderFmt, csvHeaderLabel(s.TZ.UTC, s.TZ.DST)))); err != nil {
		return err
	}
	rows, _ := s.Rows()
	var line strings.Builder
	for _, r := range rows {
		line.Reset()
		line.WriteString(`"`)
		line.WriteString(r.key.text())
		for _, v := range r.Cols {
			line.WriteString(`","`)
			line.WriteString(v)
		}
		line.WriteString("\"\r\n")
		if _, err := bw.Write(toACP(line.String())); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// toACP converts a WTF-8 string the way WideCharToMultiByte(CP_THREAD_ACP, 0, ...) does.
func toACP(s string) []byte {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return []byte(s)
	}
	return wideToACP(toUTF16(s))
}
