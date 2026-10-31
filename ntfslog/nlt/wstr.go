package nlt

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Text values are kept as Go strings in WTF-8: valid UTF-16 becomes UTF-8 and a lone surrogate is kept as its
// 3-byte generalized UTF-8 form, so names read from disk round-trip to UTF-16 unchanged.

// fromUTF16 decodes UTF-16 code units, keeping lone surrogates.
func fromUTF16(u []uint16) string {
	var b strings.Builder
	b.Grow(len(u))
	for i := 0; i < len(u); i++ {
		c := u[i]
		switch {
		case c < 0x80:
			b.WriteByte(byte(c))
		case c >= 0xD800 && c < 0xDC00 && i+1 < len(u) && u[i+1] >= 0xDC00 && u[i+1] < 0xE000:
			b.WriteRune(utf16.DecodeRune(rune(c), rune(u[i+1])))
			i++
		case c >= 0xD800 && c < 0xE000:
			b.WriteByte(0xE0 | byte(c>>12))
			b.WriteByte(0x80 | byte(c>>6)&0x3F)
			b.WriteByte(0x80 | byte(c)&0x3F)
		default:
			b.WriteRune(rune(c))
		}
	}
	return b.String()
}

// toUTF16 is the inverse of fromUTF16.
func toUTF16(s string) []uint16 {
	out := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
			out = append(out, uint16(0xD000|uint16(s[i+1]&0x3F)<<6|uint16(s[i+2]&0x3F)))
			i += 3
			continue
		}
		r, n := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			a, b := utf16.EncodeRune(r)
			out = append(out, uint16(a), uint16(b))
		} else {
			out = append(out, uint16(r))
		}
		i += n
	}
	return out
}

// utf16Str decodes a little-endian UTF-16 byte slice of n code units.
func utf16Str(b []byte, n int) string {
	if n*2 > len(b) {
		n = len(b) / 2
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return fromUTF16(u)
}

// cstr truncates at the first NUL, as CString Format("%s") and SetString(LPCWSTR) do.
func cstr(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}
