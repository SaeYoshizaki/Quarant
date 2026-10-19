package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"quarant/internal/zeekevidence"
)

// quarant zeek evidence: Zeek parses the capture, Quarant turns the parse
// into evidence events (internal/zeekevidence). The output directory gets
// events.jsonl in the same shape as `quarant analyze`, so the evidence-map
// scripts read either.
func runZeekEvidenceCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("zeek evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pcap := fs.String("pcap", "", "capture to parse with Zeek")
	logPath := fs.String("log", "", "existing quarant_evidence.log (instead of --pcap)")
	outDir := fs.String("out", "", "output directory (events.jsonl, quarant_evidence.log)")
	zeekBin := fs.String("zeek", "zeek", "Zeek binary")
	localNets := fs.String("local-net", "", "comma-separated CIDRs of the monitored network (default: RFC1918, link-local and ULA ranges)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse zeek evidence flags: %w", err)
	}
	if fs.NArg() != 0 || *outDir == "" || (*pcap == "") == (*logPath == "") {
		return fmt.Errorf("usage: quarant zeek evidence (--pcap FILE | --log quarant_evidence.log) --out DIR [--local-net CIDRS]")
	}
	local, err := parseLocalNetsFlag(*localNets)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return err
	}
	src := *logPath
	if *pcap != "" {
		// Zeek runs in a scratch directory; only the evidence log (names
		// and shapes, no values) is kept.
		work, err := os.MkdirTemp("", "quarant-zeek-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(work)
		src, err = zeekevidence.RunZeek(context.Background(), *zeekBin, *pcap, work)
		if err != nil {
			return err
		}
	}
	data, err := os.Open(src)
	if err != nil {
		return err
	}
	rows, err := zeekevidence.ReadRows(data)
	data.Close()
	if err != nil {
		return fmt.Errorf("read %s: %w", src, err)
	}
	if *pcap != "" {
		raw, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(*outDir, zeekevidence.LogName), raw, 0o644); err != nil {
			return err
		}
	}
	events := zeekevidence.Convert(rows, local)
	if err := writeJSONL(filepath.Join(*outDir, "events.jsonl"), events); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Type]++
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)
	fmt.Fprintf(out, "Zeek evidence: rows=%d events=%d out=%s\n", len(rows), len(events), *outDir)
	for _, t := range types {
		fmt.Fprintf(out, "  %-34s %d\n", t, counts[t])
	}
	return nil
}
