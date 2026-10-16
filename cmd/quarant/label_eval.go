package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"quarant/internal/labeleval"
)

// runLabelEval compares events.jsonl with a ground-truth label file.
func runLabelEval(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("label-eval", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	eventsPath := fs.String("events", "events.jsonl", "events JSONL produced by quarant analyze")
	labelsPath := fs.String("labels", "", "ground-truth labels JSON (e.g. examples/pcap/synthetic-home.labels.json)")
	format := fs.String("format", "markdown", "output format: markdown|json")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse label-eval flags: %w", err)
	}
	if strings.TrimSpace(*labelsPath) == "" {
		return fmt.Errorf("label-eval requires --labels")
	}
	scenario, err := labeleval.LoadScenario(*labelsPath)
	if err != nil {
		return err
	}
	f, err := os.Open(*eventsPath)
	if err != nil {
		return err
	}
	defer f.Close()
	events, bad, err := labeleval.LoadEvents(f)
	if err != nil {
		return fmt.Errorf("read events: %w", err)
	}
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "label-eval: skipped %d malformed event lines\n", bad)
	}
	rep := labeleval.Evaluate(scenario, events)
	switch strings.ToLower(*format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "markdown", "md", "":
		labeleval.WriteMarkdown(out, rep)
		return nil
	default:
		return fmt.Errorf("unknown --format %q", *format)
	}
}
