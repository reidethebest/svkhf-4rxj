// Command ntfslog parses an NTFS $LogFile exactly like NTFS Log Tracker v1.71 and writes its SQLite DB and/or
// NLT_LogFile CSV.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"ntfslog/nlt"
)

func main() {
	logPath := flag.String("logfile", "", "$LogFile to parse (required)")
	mftPath := flag.String("mft", "", "optional $MFT for file names, paths and times")
	utc := flag.Int("utc", 0, "time zone offset in hours (-12..14)")
	dst := flag.Bool("dst", false, "add one hour (DST check box)")
	dbPath := flag.String("db", "", "output SQLite DB")
	csvPath := flag.String("csv", "", "output CSV file, or a directory for NLT_LogFile_<time>.csv")
	tracePath := flag.String("trace", "", "write every SQL statement the original would execute (JSONL)")
	flag.Parse()
	if *logPath == "" || (*dbPath == "" && *csvPath == "" && *tracePath == "") {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(*logPath, *mftPath, *utc, *dst, *dbPath, *csvPath, *tracePath); err != nil {
		fmt.Fprintln(os.Stderr, "ntfslog:", err)
		os.Exit(1)
	}
}

func run(logPath, mftPath string, utc int, dst bool, dbPath, csvPath, tracePath string) error {
	t0 := time.Now()
	data, err := os.ReadFile(logPath)
	if err != nil {
		return err
	}
	opt := nlt.Options{UTC: utc, DST: dst}
	if mftPath != "" {
		if opt.MFT, err = os.ReadFile(mftPath); err != nil {
			return err
		}
	}
	if tracePath != "" {
		f, err := os.Create(tracePath)
		if err != nil {
			return err
		}
		defer f.Close()
		opt.Trace = f
	}
	st, err := nlt.Parse(data, opt)
	if errors.Is(err, nlt.ErrNotSupported) && st != nil {
		fmt.Fprintln(os.Stderr, "ntfslog:", err, "(empty LogFile table, as the original)")
	} else if err != nil {
		return err
	}
	byLSN, _ := st.Rows()
	if dbPath != "" {
		if err := nlt.WriteDB(dbPath, st); err != nil {
			return err
		}
	}
	if csvPath != "" {
		if fi, err := os.Stat(csvPath); err == nil && fi.IsDir() {
			csvPath = filepath.Join(csvPath, "NLT_LogFile_"+time.Now().Format("2006-01-02 15-04-05")+".csv")
		}
		f, err := os.Create(csvPath)
		if err != nil {
			return err
		}
		if err := nlt.WriteCSV(f, st); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "%d rows (%d duplicate LSNs rejected) in %v\n", len(byLSN), st.Conflicts(), time.Since(t0).Round(time.Millisecond))
	return nil
}
