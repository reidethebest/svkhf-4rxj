package nlt

import (
	"errors"
	"fmt"
	"io"
)

// Options select what the original's "Parse Setting" dialog selects for a $LogFile-only parse.
type Options struct {
	UTC   int  // time-zone combo, -12..14
	DST   bool // DST check box (+1 hour)
	Trace io.Writer
	// MFT is the optional $MFT file content (nil when no $MFT is given).
	MFT []byte
}

// Parse runs the $LogFile stage of NTFS Log Tracker v1.71 on the raw $LogFile bytes and returns the final
// LogFile/TimeZone table state.
//
// An unsupported $LogFile (no RSTR pages, or an LFS version other than 1.1/2.0) is not fatal in the original: the
// worker still deletes Temp Events and inserts the TimeZone row, leaving an empty LogFile table. Parse then returns
// that store together with an error wrapping ErrNotSupported.
func Parse(logFile []byte, opt Options) (st *Store, err error) {
	dst := 0
	if opt.DST {
		dst = 1
	}
	st = NewStore(opt.Trace)
	store := st // st is nil on error returns
	p := &parser{data: logFile, tz: opt.UTC + dst, store: st}
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v (%w)", r, ErrOriginalCrash)
		}
		if err != nil && !errors.Is(err, ErrNotSupported) {
			store.Flush() // the trace keeps every statement executed before the original would fail
		}
	}()
	if opt.MFT != nil {
		if err := p.parseMFT(opt.MFT); err != nil {
			return nil, err
		}
	}
	notice := p.run()
	if notice != nil && !errors.Is(notice, ErrNotSupported) {
		return nil, notice
	}
	st.DeleteTempEvents()
	st.SetTimeZone(opt.UTC, dst)
	if err := st.Flush(); err != nil {
		return nil, err
	}
	return st, notice
}
