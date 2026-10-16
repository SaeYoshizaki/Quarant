package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quarant/internal/synth"
)

// runSynth writes the synthetic home-network scenario as a PCAP plus a
// ground-truth label file. The traffic is generated in code, so the output
// contains no real network data and can be committed as a fixture.
func runSynth(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("synth", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pcapPath := fs.String("out", "synthetic-home.pcap", "path to write the synthetic PCAP")
	labelsPath := fs.String("labels-out", "", "path to write ground-truth labels JSON (default: <out without .pcap>.labels.json)")
	startFlag := fs.String("start", "2026-09-26T10:00:00Z", "scenario start time (RFC3339)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse synth flags: %w", err)
	}
	start, err := time.Parse(time.RFC3339, *startFlag)
	if err != nil {
		return fmt.Errorf("parse --start: %w", err)
	}
	if strings.TrimSpace(*labelsPath) == "" {
		*labelsPath = strings.TrimSuffix(*pcapPath, filepath.Ext(*pcapPath)) + ".labels.json"
	}

	scenario := synth.HomeScenario(start.UTC())
	if dir := filepath.Dir(*pcapPath); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(*pcapPath)
	if err != nil {
		return err
	}
	if err := scenario.Builder.WritePCAP(f); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(scenario, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*labelsPath, append(data, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "wrote %s (%d packets) and %s (%d labels)\n", *pcapPath, len(scenario.Builder.Packets()), *labelsPath, len(scenario.Labels))
	return nil
}
