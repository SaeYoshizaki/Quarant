// Command ouigen converts the IEEE MA-L registry CSV (tool/input/oui.csv,
// downloadable from https://standards-oui.ieee.org/oui/oui.csv) into the
// compact table embedded in the knowledge base (knowledge/oui_ma_l.tsv).
//
//	go run ./tool/ouigen -in tool/input/oui.csv -out knowledge/oui_ma_l.tsv -snapshot 2026-04-10
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	in := flag.String("in", "tool/input/oui.csv", "IEEE MA-L CSV")
	out := flag.String("out", "knowledge/oui_ma_l.tsv", "output TSV")
	snapshot := flag.String("snapshot", "", "date the CSV was downloaded (recorded as provenance)")
	flag.Parse()

	f, err := os.Open(*in)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	rows := map[string]string{}
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if len(rec) < 3 || rec[0] != "MA-L" || len(rec[1]) != 6 {
			continue
		}
		name := strings.Join(strings.Fields(strings.ReplaceAll(rec[2], "\t", " ")), " ")
		rows[strings.ToUpper(rec[1])] = name
	}
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	o, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriter(o)
	fmt.Fprintf(w, "# source: IEEE MA-L registry (oui.csv); snapshot: %s; entries: %d\n", *snapshot, len(keys))
	for _, k := range keys {
		fmt.Fprintf(w, "%s\t%s\n", k, rows[k])
	}
	if err := w.Flush(); err != nil {
		log.Fatal(err)
	}
	if err := o.Close(); err != nil {
		log.Fatal(err)
	}
}
