package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"quarant/internal/findings"
)

// runFindings rebuilds findings.json for an existing analysis directory and
// prints the per-device conditions.
func runFindings(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("findings", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	in := fs.String("in", "", "analysis output directory (events.jsonl, device_inventory.json)")
	outPath := fs.String("out", "", "where to write findings.json (default: <in>/findings.json, - for none)")
	minSeverity := fs.String("min-severity", "WARNING", "lowest event severity to include (INFO|WARNING|HIGH|CRITICAL)")
	format := fs.String("format", "markdown", "printed summary: markdown|json|none")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse findings flags: %w", err)
	}
	if strings.TrimSpace(*in) == "" {
		return fmt.Errorf("findings requires --in <analysis dir>")
	}
	target := *outPath
	if target == "" {
		target = filepath.Join(*in, "findings.json")
	}
	rep, err := findings.FromRun(filepath.Join(*in, "events.jsonl"), filepath.Join(*in, "device_inventory.json"), *minSeverity)
	if err != nil {
		return err
	}
	if target != "-" {
		if err := findings.Write(rep, target); err != nil {
			return err
		}
	}
	switch strings.ToLower(*format) {
	case "none":
		return nil
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	fmt.Fprintf(out, "# Findings (%s and above)\n\n", rep.MinSeverity)
	fmt.Fprintf(out, "- Events: %d → findings (device × type): %d → conditions (device × condition): %d, devices: %d\n\n",
		rep.Counts.Events, rep.Counts.Findings, rep.Counts.Conditions, rep.Counts.Devices)
	fmt.Fprintln(out, "| Device | Condition | Severity | Basis | Event types | Events | Destinations | First seen | Last seen |")
	fmt.Fprintln(out, "|---|---|---|---|---|---|---|---|---|")
	for _, c := range rep.Conditions {
		dev := c.Device
		if c.MAC != "" {
			dev += " (" + c.MAC + ")"
		}
		cond := c.Condition
		if c.Derived {
			cond += " (derived)"
		}
		fmt.Fprintf(out, "| %s | %s | %s | %s | %s | %d | %d | %s | %s |\n", dev, cond, c.Severity, strings.Join(c.Basis, ", "),
			strings.Join(c.Types, ", "), c.Events, c.Destinations, c.FirstSeen.Format("2006-01-02 15:04:05"), c.LastSeen.Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(out, "\n%s\n", rep.Note)
	return nil
}
