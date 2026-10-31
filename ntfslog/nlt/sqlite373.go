package nlt

import (
	"cmp"
	"math"
	"strconv"
)

// SQLite 3.7.3 (the original's sqlite3.dll) behaviour that decides what the LogFile table stores and what the CSV
// export reads back. The port reproduces it whatever SQLite version it links. Specification: re/spec/SPEC.md 7.5
// (LSN >= 2^63) and 7.7 (Unicode).

// sqliteText is the TEXT that SQLite 3.7.3 stores for the literal '<v>' of a statement prepared with
// sqlite3_prepare16 into the UTF-16le database. v is the escaped value exactly as formatted between the quotes
// (every quote doubled, cut at the first NUL); the closing quote follows it.
//
// prepare16 converts the whole statement to UTF-8 with READ_UTF16LE (sqlite3VdbeMemTranslate 0x60906951..
// 0x6090698a): a unit in 0xD800..0xDFFF, paired or not, consumes the next unit c2, whatever it is, and becomes the
// code point 0x10000 + (c&0x3FF)<<10 + (c2&0x3FF). Every surrogate of the statement lies inside a quoted value, and
// the unit before a value's opening quote is never a surrogate, so the statement translates value by value.
//
//   - A consumed quote (the closing one, or the first of a doubled pair) ends the literal somewhere else. From there
//     on, the separators become literals and the values become SQL text: a path starts with '\' (illegal token),
//     a time is "N-N-N N:N:N" (two numbers in a row), TargetVCN is "0x.." (illegal token in 3.7.3), and any other
//     word is a column name that VALUES cannot resolve. prepare16 fails and 0x41a7d0's catch(...) (FuncInfo
//     0x5b7f5c) swallows it: no row, no rowid (oracle sem-009, sem-010, mft-013, vhd-038). ok is false then.
//     Limitation: a second consumed quote can re-pair the quotes; only names that themselves hold SQL syntax could
//     then form 13 resolvable values, which 3.7.3 would insert. That is not modelled: such a statement also counts
//     as failing.
//   - Otherwise the quotes are intact and only the literal contents change. The literal is stored through
//     READ_UTF8 (0x609067c4..0x60906817), which turns U+FFFE and U+FFFF into U+FFFD, and WRITE_UTF16LE: each
//     merged code point becomes the pair 0xD800|c&0x3FF, 0xDC00|c2&0x3FF (oracle sem-008: "ab" D800 "c" is stored
//     as D800 DC63).
//
// The result is always well-formed UTF-16, so it is a valid UTF-8 Go string: the DB writer stores exactly these
// units, and the CSV export reads them back unchanged (get_table's UTF-8 and MultiByteToWideChar are lossless on
// well-formed text).
func sqliteText(v string) (stored string, ok bool) {
	u := toUTF16(v)
	out := make([]rune, 0, len(u))
	for i := 0; i < len(u); i++ {
		c := rune(u[i])
		switch {
		case c >= 0xD800 && c < 0xE000:
			c2 := rune('\'') // the closing quote
			if i+1 < len(u) {
				c2 = rune(u[i+1])
			}
			if c2 == '\'' {
				return "", false
			}
			i++
			out = append(out, 0x10000+(c&0x3FF)<<10+(c2&0x3FF))
		case c == '\'':
			out = append(out, c) // the first of a doubled quote: the literal holds one
			i++
		case c == 0xFFFE || c == 0xFFFF:
			out = append(out, 0xFFFD)
		default:
			out = append(out, c)
		}
	}
	return string(out), true
}

// lsnKey is the value SQLite 3.7.3 stores in the LSN column for the unquoted "%I64u" literal of the INSERT
// (0x59abd0 at 0x41a86b), and the value "where LSN=%s" matches.
//
// Up to 2^63-1 the literal is an INTEGER. Above, sqlite3FitsIn64Bits fails and codeInteger (0x6092caa0) codes it as
// a REAL (codeReal 0x6092cb3e): sqlite3AtoF (0x60906f10) accumulates the significand only while it is below
// (2^63-1-9)/10, so the last digit is dropped (the exponent becomes 1), and the x87 computes significand * 10.0 at
// 53-bit precision, one rounding of n - n%10. INTEGER affinity (0x6091c540) cannot turn a REAL >= 2^63 back into
// an INTEGER. REALs that round to the same double collide on the PRIMARY KEY, so the first row wins and later
// UPDATEs of any of those LSNs hit it. INTEGER and REAL compare exactly (oracle lfs-070 keeps INTEGER 2^63-175, a
// double 2^63, next to REAL 2^63), so every INTEGER sorts before every REAL (oracle lfs-069, lfs-070).
type lsnKey struct {
	real bool
	i    uint64
	f    float64
}

func lsnKeyOf(n uint64) lsnKey {
	if n <= math.MaxInt64 {
		return lsnKey{i: n}
	}
	return lsnKey{real: true, f: float64(n - n%10)}
}

// compare is the order of "ORDER BY LSN" (the unique index).
func (k lsnKey) compare(o lsnKey) int {
	switch {
	case k.real != o.real:
		if k.real {
			return 1
		}
		return -1
	case k.real:
		return cmp.Compare(k.f, o.f)
	}
	return cmp.Compare(k.i, o.i)
}

// text is the LSN as sqlite3_get_table returns it to the CSV export: "%lld" for an INTEGER, "%!.15g" for a REAL
// (sqlite3VdbeMemStringify 0x6091c266 / 0x6091c2cb).
func (k lsnKey) text() string {
	if k.real {
		return sqliteRealText(k.f)
	}
	return strconv.FormatUint(k.i, 10)
}

// value is the LSN bound so that the DB stores the same type: int64 for an INTEGER, float64 for a REAL.
func (k lsnKey) value() any {
	if k.real {
		return k.f
	}
	return int64(k.i)
}

// sqliteRealText is "%!.15g" as SQLite 3.7.3's own vxprintf prints a REAL r > 0: the etGENERIC path with its
// rounder (0.5 * 0.1^14), the normalisation by 1e32, 1e8 and 10, and et_getdigit (at most 16 significant digits).
// Its LONGDOUBLE arithmetic runs on the x87 at the 53-bit precision set by the MSVC CRT, i.e. float64 arithmetic
// rounded after every operation (the float64() conversions keep Go from fusing operations). This is not the
// correctly rounded %.15g: it reproduces every REAL LSN text of oracle lfs-069 and lfs-070, where %.15g gets some
// last digits wrong.
func sqliteRealText(r float64) string {
	prec := 15 - 1 // etGENERIC counts the leading digit
	rounder := 0.5
	for i := prec; i > 0; i-- {
		rounder = float64(rounder * 0.1)
	}
	exp := 0
	for r >= 1e32 && exp <= 350 {
		r, exp = float64(r*1e-32), exp+32
	}
	for r >= 1e8 && exp <= 350 {
		r, exp = float64(r*1e-8), exp+8
	}
	for r >= 10 && exp <= 350 {
		r, exp = float64(r*0.1), exp+1
	}
	for r < 1e-8 {
		r, exp = float64(r*1e8), exp-8
	}
	for r < 1 {
		r, exp = float64(r*10), exp-1
	}
	r = float64(r + rounder)
	if r >= 10 {
		r, exp = float64(r*0.1), exp+1
	}
	useExp := exp < -4 || exp > prec
	e2 := 0
	if !useExp {
		prec -= exp
		e2 = exp
	}
	nsd := 0
	digit := func() byte {
		if nsd++; nsd > 16 {
			return '0'
		}
		d := int(r)
		r = float64(float64(r-float64(d)) * 10)
		return byte('0' + d)
	}
	var b []byte
	if e2 < 0 {
		b = append(b, '0')
	} else {
		for ; e2 >= 0; e2-- {
			b = append(b, digit())
		}
	}
	b = append(b, '.') // the '!' flag always prints the point
	for e2++; e2 < 0; prec, e2 = prec-1, e2+1 {
		b = append(b, '0')
	}
	for ; prec > 0; prec-- {
		b = append(b, digit())
	}
	for b[len(b)-1] == '0' { // %g drops trailing zeros; '!' keeps one digit after the point
		b = b[:len(b)-1]
	}
	if b[len(b)-1] == '.' {
		b = append(b, '0')
	}
	if useExp {
		b = append(b, 'e', '+')
		if exp < 0 {
			b[len(b)-1], exp = '-', -exp
		}
		if exp >= 100 {
			b, exp = append(b, byte('0'+exp/100)), exp%100
		}
		b = append(b, byte('0'+exp/10), byte('0'+exp%10))
	}
	return string(b)
}
