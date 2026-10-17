package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"quarant/internal/parserdiff"
)

// runParserDiff compares Quarant's TLS ClientHello parser with crypto/tls on
// every TLS client stream of a capture (offline; nothing is sent anywhere).
func runParserDiff(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("parser-diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pcapPath := fs.String("pcap", "", "capture to analyse")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse parser-diff flags: %w", err)
	}
	if strings.TrimSpace(*pcapPath) == "" {
		return fmt.Errorf("parser-diff requires --pcap")
	}
	rep, err := parserdiff.AnalyzePCAP(*pcapPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
