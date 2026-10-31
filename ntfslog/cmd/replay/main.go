// Command replay feeds the original's recorded SQL stream (oracle sql.jsonl) through nlt.Store and writes the DB
// and CSV with the Go writers. It validates the output layer independently of the $LogFile parser.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"ntfslog/nlt"
)

// literals splits "values(N, 'a', 'b”c', ...)" into its values, undoing the quote doubling.
func literals(s string) []string {
	var out []string
	i := strings.Index(s, "values(") + len("values(")
	j := strings.IndexByte(s[i:], ',')
	out = append(out, s[i:i+j])
	i += j
	for {
		k := strings.IndexByte(s[i:], '\'')
		if k < 0 {
			return out
		}
		i += k + 1
		var b strings.Builder
		for {
			if s[i] == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					b.WriteByte('\'')
					i += 2
					continue
				}
				i++
				break
			}
			b.WriteByte(s[i])
			i++
		}
		out = append(out, b.String())
	}
}

var (
	reUpd1 = regexp.MustCompile(`^update LogFile set EventTime='([^']*)' where LSN=(\d+)$`)
	reUpd3 = regexp.MustCompile(`^update LogFile set EventTime='([^']*)', Event='([^']*)', Detail='([^']*)' where LSN=(\d+)$`)
	reUpdE = regexp.MustCompile(`^update LogFile set Event='([^']*)' where LSN=(\d+)$`)
	reTZ   = regexp.MustCompile(`^insert into TimeZone \(UTC, DST\) values\((-?\d+), (-?\d+)\)$`)
)

func main() {
	in := flag.String("oracle", "", "oracle sql.jsonl")
	db := flag.String("db", "", "output DB")
	csv := flag.String("csv", "", "output CSV")
	trace := flag.String("trace", "", "output trace JSONL")
	flag.Parse()
	f, err := os.Open(*in)
	if err != nil {
		log.Fatal(err)
	}
	var tw *os.File
	if *trace != "" {
		if tw, err = os.Create(*trace); err != nil {
			log.Fatal(err)
		}
	}
	var s *nlt.Store
	if tw != nil {
		s = nlt.NewStore(tw)
	} else {
		s = nlt.NewStore(nil)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		var e struct{ Ev, SQL string }
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil || e.Ev != "prepare16" {
			continue
		}
		q := e.SQL
		switch {
		case strings.HasPrefix(q, "insert into LogFile"):
			v := literals(q)
			ci, _ := strconv.ParseUint(v[12], 10, 64)
			s.InsertLogFileRow(&nlt.Record{LSN: v[0], EventTime: v[1], Event: v[2], Detail: v[3], FileName: v[4],
				FullPath: v[5], CreateTime: v[6], ModifiedTime: v[7], MFTModifiedTime: v[8], AccessTime: v[9],
				RedoInfo: v[10], TargetVCN: v[11], ClusterBlockOffset: ci})
		case reUpd3.MatchString(q):
			m := reUpd3.FindStringSubmatch(q)
			s.UpdateTimeEventDetail(m[4], m[1], m[2], m[3])
		case reUpd1.MatchString(q):
			m := reUpd1.FindStringSubmatch(q)
			s.UpdateEventTime(m[2], m[1])
		case reUpdE.MatchString(q):
			m := reUpdE.FindStringSubmatch(q)
			s.UpdateEvent(m[2], m[1])
		case q == "delete from LogFile where Event='Temp Event'":
			s.DeleteTempEvents()
		case reTZ.MatchString(q):
			m := reTZ.FindStringSubmatch(q)
			u, _ := strconv.Atoi(m[1])
			d, _ := strconv.Atoi(m[2])
			s.SetTimeZone(u, d)
		case strings.HasPrefix(q, "create table"):
		default:
			log.Printf("unhandled: %.120s", q)
		}
	}
	if err := sc.Err(); err != nil {
		log.Fatal(err)
	}
	s.Flush()
	if *db != "" {
		if err := nlt.WriteDB(*db, s); err != nil {
			log.Fatal(err)
		}
	}
	if *csv != "" {
		out, err := os.Create(*csv)
		if err != nil {
			log.Fatal(err)
		}
		if err := nlt.WriteCSV(out, s); err != nil {
			log.Fatal(err)
		}
		out.Close()
	}
	fmt.Printf("conflicts=%d\n", s.Conflicts())
}
