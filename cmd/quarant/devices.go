package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"quarant/internal/devicereport"
)

// runDevices prints the per-device report for an analysis output directory.
func runDevices(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir := fs.String("in", ".", "analysis output directory (events.jsonl, flows.jsonl, device_inventory.json)")
	format := fs.String("format", "markdown", "output format: markdown|json")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse devices flags: %w", err)
	}
	in, err := devicereport.LoadDir(*dir)
	if err != nil {
		return err
	}
	rep := devicereport.Build(in, time.Now())
	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "markdown", "md", "":
		devicereport.WriteMarkdown(out, rep)
		return nil
	default:
		return fmt.Errorf("unknown --format %q", *format)
	}
}
