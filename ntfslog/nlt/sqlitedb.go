package nlt

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

// Schema of the original's DB (created through sqlite3_open16, hence UTF-16le, with 1024-byte pages).
var schema = []string{
	"PRAGMA page_size=1024",
	"PRAGMA encoding='UTF-16le'",
	"create table LogFile (LSN UNSIGNED BIG INT PRIMARY KEY, EventTime TEXT, Event TEXT, Detail TEXT, FileName TEXT, FullPath TEXT, CreateTime TEXT, ModifiedTIme TEXT, MFT_ModifiedTime TEXT, AccessTime TEXT, RedoInfo TEXT, TargetVCN TEXT, MFT_ClusterIndex TEXT)",
	"create table UsnJrnl (USN UNSIGNED BIG INT PRIMARY KEY, TimeStamp TEXT, FileName TEXT, FullPath TEXT, Event TEXT, SourceInfo TEXT, FileAttr TEXT, CarvingFlag TEXT, FileReferenceNumber TEXT, ParentFileReferenceNumber TEXT)",
	"create table TimeZone (UTC INT PRIMARY KEY, DST UNSIGNED BIG INT)",
}

// WriteDB writes the final table state to a new SQLite file (rows keep the original's rowids).
func WriteDB(path string, s *Store) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, q := range append([]string{"PRAGMA journal_mode=OFF", "PRAGMA synchronous=OFF"}, schema...) {
		if _, err := db.Exec(q); err != nil {
			return fmt.Errorf("%s: %w", q, err)
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare("insert into LogFile (rowid, LSN, EventTime, Event, Detail, FileName, FullPath, CreateTime, ModifiedTIme, MFT_ModifiedTime, AccessTime, RedoInfo, TargetVCN, MFT_ClusterIndex) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	_, rows := s.Rows()
	args := make([]any, 14)
	for _, r := range rows {
		args[0], args[1] = r.RowID, r.key.value()
		for i, v := range r.Cols {
			args[2+i] = v
		}
		if _, err := st.Exec(args...); err != nil {
			return err
		}
	}
	st.Close()
	if _, err := tx.Exec("insert into TimeZone (UTC, DST) values(?, ?)", s.TZ.UTC, s.TZ.DST); err != nil {
		return err
	}
	return tx.Commit()
}
