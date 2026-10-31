package nlt

import (
	"encoding/binary"
	"fmt"
	"time"
)

// SystemTime mirrors the Win32 SYSTEMTIME fields used by the original.
type SystemTime struct {
	Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds int
}

const ticksPerSecond = 10_000_000

// unixEpochIn1601 is the number of seconds from 1601-01-01 to 1970-01-01.
const unixEpochIn1601 = 11644473600

// fileTimeToSystemTime follows kernel32 FileTimeToSystemTime: it fails for values with the high bit set.
func fileTimeToSystemTime(ft uint64) (SystemTime, bool) {
	if ft > 0x7FFFFFFFFFFFFFFF {
		return SystemTime{}, false
	}
	secs := int64(ft / ticksPerSecond)
	ms := int((ft % ticksPerSecond) / 10_000)
	t := time.Unix(secs-unixEpochIn1601, 0).UTC()
	return SystemTime{t.Year(), int(t.Month()), int(t.Weekday()), t.Day(), t.Hour(), t.Minute(), t.Second(), ms}, true
}

// systemTimeToFileTime follows kernel32 SystemTimeToFileTime validation (wDayOfWeek is ignored).
func systemTimeToFileTime(st SystemTime) (uint64, bool) {
	if st.Year < 1601 || st.Year > 30827 || st.Month < 1 || st.Month > 12 || st.Day < 1 ||
		st.Hour < 0 || st.Hour > 23 || st.Minute < 0 || st.Minute > 59 || st.Second < 0 || st.Second > 59 ||
		st.Milliseconds < 0 || st.Milliseconds > 999 {
		return 0, false
	}
	if st.Day > time.Date(st.Year, time.Month(st.Month)+1, 0, 0, 0, 0, 0, time.UTC).Day() {
		return 0, false
	}
	secs := uint64(time.Date(st.Year, time.Month(st.Month), st.Day, st.Hour, st.Minute, st.Second, 0, time.UTC).Unix() + unixEpochIn1601)
	return secs*ticksPerSecond + uint64(st.Milliseconds)*10_000, true
}

// formatSystemTime is Format("%0.4d-%0.2d-%0.2d %0.2d:%0.2d:%0.2d", ...).
func formatSystemTime(st SystemTime) string {
	return fmt.Sprintf("%s-%s-%s %s:%s:%s", prec(st.Year, 4), prec(st.Month, 2), prec(st.Day, 2),
		prec(st.Hour, 2), prec(st.Minute, 2), prec(st.Second, 2))
}

// prec is printf "%0.Nd": precision N (minimum digits), the sign is not counted.
func prec(v, n int) string {
	if v < 0 {
		return "-" + fmt.Sprintf("%0*d", n, -v)
	}
	return fmt.Sprintf("%0*d", n, v)
}

// mid is CStringW::Mid(first, count) on code units.
func mid(u []uint16, first, count int) []uint16 {
	if first < 0 {
		first = 0
	}
	if count < 0 {
		count = 0
	}
	if first > len(u) {
		first = len(u)
	}
	if first+count > len(u) {
		count = len(u) - first
	}
	return u[first : first+count]
}

// wtoi is the MSVC _wtoi: leading white space, optional sign, decimal digits, saturating at the int32 range.
func wtoi(u []uint16) int {
	i := 0
	for i < len(u) && (u[i] == ' ' || (u[i] >= 9 && u[i] <= 13)) {
		i++
	}
	neg := false
	if i < len(u) && (u[i] == '+' || u[i] == '-') {
		neg = u[i] == '-'
		i++
	}
	var v int64
	over := false
	for ; i < len(u) && u[i] >= '0' && u[i] <= '9'; i++ {
		v = v*10 + int64(u[i]-'0')
		if v > 1<<31 {
			over = true
		}
	}
	switch {
	case over && neg:
		return -1 << 31
	case over:
		return 1<<31 - 1
	case neg:
		v = -v
	}
	if v > 1<<31-1 {
		return 1<<31 - 1
	}
	return int(v)
}

// adjustTimeString is 0x41b1a0: parse "YYYY-MM-DD hh:mm:ss", shift by whole hours, format again.
//
// The parsed fields and the converted result share one SYSTEMTIME, so when FileTimeToSystemTime fails (shifted
// value below 1601 or above 30827) the original prints the parsed input fields (WORD-truncated); that is exact.
// When SystemTimeToFileTime fails (e.g. a 5-digit year) the original adds the shift to an uninitialised FILETIME
// whose value differs from run to run (ASLR stack addresses), so no output is reproducible; the input string is
// then returned unchanged and ok is false.
func adjustTimeString(t string, hours int) (string, bool) {
	u := toUTF16(t)
	st := SystemTime{
		Year: wtoi(mid(u, 0, 4)) & 0xFFFF, Month: wtoi(mid(u, 5, 2)) & 0xFFFF, Day: wtoi(mid(u, 8, 2)) & 0xFFFF,
		Hour: wtoi(mid(u, 11, 2)) & 0xFFFF, Minute: wtoi(mid(u, 14, 2)) & 0xFFFF, Second: wtoi(mid(u, 17, 2)) & 0xFFFF,
	}
	ft, ok := systemTimeToFileTime(st)
	if !ok {
		return t, false
	}
	ft += uint64(int64(hours) * 36_000_000_000)
	if st2, ok := fileTimeToSystemTime(ft); ok {
		st = st2
	}
	return formatSystemTime(st), true
}

// fileTimeToSlot is the conversion inlined at every call site: FileTimeToSystemTime(&ft, slot) (IAT 0x56d428) and
// Format(0x5997a0) of the slot's words (movzx, so 0..65535). slot is the caller's model of the 16 stack bytes of that
// SYSTEMTIME local (wYear +0, wMonth +2, wDayOfWeek +4, wDay +6, wHour +8, wMinute +0xa, wSecond +0xc,
// wMilliseconds +0xe). No caller checks the BOOL: for a FILETIME >= 2^63 the call fails without writing (verified on
// Windows 10 19045), so the string shows whatever those bytes held, i.e. the last write to that stack slot.
func fileTimeToSlot(slot []byte, ft uint64) string {
	if st, ok := fileTimeToSystemTime(ft); ok {
		for i, w := range [8]int{st.Year, st.Month, st.DayOfWeek, st.Day, st.Hour, st.Minute, st.Second, st.Milliseconds} {
			binary.LittleEndian.PutUint16(slot[2*i:], uint16(w))
		}
	}
	w := func(o int) int { return int(binary.LittleEndian.Uint16(slot[o:])) }
	return formatSystemTime(SystemTime{Year: w(0), Month: w(2), DayOfWeek: w(4), Day: w(6), Hour: w(8), Minute: w(0xa),
		Second: w(0xc), Milliseconds: w(0xe)})
}
