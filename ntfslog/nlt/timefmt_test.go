package nlt

import "testing"

func TestTimeRoundTrip(t *testing.T) {
	cases := []struct {
		ft   uint64
		want string
	}{
		{0, "1601-01-01 00:00:00"},
		{0x01DD48A7C9F1A000, ""},
		{0x7FFF35F4F06C7FFF, "30827-12-31 23:59:59"},
	}
	for _, c := range cases {
		st, ok := fileTimeToSystemTime(c.ft)
		if s := formatSystemTime(st); !ok || (c.want != "" && s != c.want) {
			t.Errorf("fileTimeToSystemTime(%#x) = %q, %v; want %q", c.ft, s, ok, c.want)
		}
		if ft, ok := systemTimeToFileTime(st); c.ft != 0x7FFF35F4F06C7FFF && (!ok || ft/ticksPerSecond != c.ft/ticksPerSecond) {
			t.Errorf("round trip %#x -> %#x %v", c.ft, ft, ok)
		}
	}
	if s, ok := adjustTimeString("2026-10-30 14:21:08", 10); s != "2026-10-31 00:21:08" || !ok {
		t.Errorf("adjust +10 = %q %v", s, ok)
	}
	if s, ok := adjustTimeString("2026-10-30 14:21:08", -3); s != "2026-10-30 11:21:08" || !ok {
		t.Errorf("adjust -3 = %q %v", s, ok)
	}
}

func TestAdjustFailurePaths(t *testing.T) {
	// FileTimeToSystemTime fails on the negative result: the parsed input is printed (observed in the oracle).
	for _, in := range []string{"1601-01-01 00:00:00", "1601-01-01 02:00:00"} {
		if s, ok := adjustTimeString(in, -3); s != in || !ok {
			t.Errorf("adjust(%q, -3) = %q %v", in, s, ok)
		}
	}
	if s, ok := adjustTimeString("30827-12-31 23:59:59", -3); ok || s != "30827-12-31 23:59:59" {
		t.Errorf("5-digit year: %q %v", s, ok)
	}
}

// A failed conversion (FILETIME >= 2^63) keeps the slot's bytes: the previous conversion, or zero before the first.
func TestFileTimeToSlotStale(t *testing.T) {
	var slot [0x10]byte
	if s := fileTimeToSlot(slot[:], 1<<63); s != "0000-00-00 00:00:00" {
		t.Errorf("never written: %q", s)
	}
	if s := fileTimeToSlot(slot[:], 0); s != "1601-01-01 00:00:00" {
		t.Errorf("FILETIME 0: %q", s)
	}
	for _, ft := range []uint64{1 << 63, ^uint64(0)} {
		if s := fileTimeToSlot(slot[:], ft); s != "1601-01-01 00:00:00" {
			t.Errorf("stale after %#x: %q", ft, s)
		}
	}
}

// The UPDATE query objects of E2 and H overlay st1460 / st1448: wYear, wMonth, wHour, wMinute become 0, the low
// bytes of wDayOfWeek and wSecond 1; wDay and the high bytes keep the previous conversion.
func TestUpdateQueryOverlay(t *testing.T) {
	for _, c := range []struct{ q, slot int }{{q1468, st1460}, {q1450, st1448}} {
		var p parser
		fileTimeToSlot(p.st412[c.slot:c.slot+0x10], 0x01DD48A7C9F1A000) // 2026-09-20 02:28:57
		p.updateQuery(c.q)
		if s := fileTimeToSlot(p.st412[c.slot:c.slot+0x10], 1<<63); s != "0000-00-20 00:00:01" {
			t.Errorf("slot %#x after query %#x: %q", c.slot, c.q, s)
		}
	}
}
