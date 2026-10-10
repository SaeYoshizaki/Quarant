package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"quarant/internal/reportapi"
)

func runPrecision(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("precision", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	eventsPath := fs.String("events", "events.jsonl", "events JSONL path")
	securityEventsPath := fs.String("security-events", "", "security events JSONL path (default: sibling security_events.jsonl when present)")
	flowsPath := fs.String("flows", "", "flows JSONL path (default: sibling flows.jsonl)")
	observationsPath := fs.String("observations", "", "observations JSONL path (default: sibling observations.jsonl)")
	inventoryPath := fs.String("inventory", "", "device inventory JSON path (default: sibling device_inventory.json)")
	reportOut := fs.String("out", "precision_report.json", "precision report JSON output path")
	incidentsOut := fs.String("incidents-out", "incidents.jsonl", "incidents JSONL output path")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse precision flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("precision accepts flags only")
	}

	dir := filepath.Dir(*eventsPath)
	if dir == "." {
		dir = ""
	}
	report, err := reportapi.LoadDetectionPrecisionReportWithSecurityEvents(
		*eventsPath,
		defaultSibling(*securityEventsPath, dir, "security_events.jsonl"),
		defaultSibling(*flowsPath, dir, "flows.jsonl"),
		defaultSibling(*observationsPath, dir, "observations.jsonl"),
		defaultSibling(*inventoryPath, dir, "device_inventory.json"),
	)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reportOut) != "" && *reportOut != "-" {
		if err := writePrettyJSON(*reportOut, report); err != nil {
			return err
		}
	}
	if strings.TrimSpace(*incidentsOut) != "" && *incidentsOut != "-" {
		if err := writeIncidentsJSONL(*incidentsOut, report.Incidents); err != nil {
			return err
		}
	}
	if *reportOut == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(out, "Precision complete: incidents=%d suppressed=%d report=%s incidents_out=%s\n",
		report.Metrics.IncidentCount,
		report.Metrics.SuppressedSignalCount,
		*reportOut,
		*incidentsOut,
	)
	return nil
}

func writePrettyJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func writeIncidentsJSONL(path string, incidents []reportapi.PrecisionIncident) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, incident := range incidents {
		if err := enc.Encode(incident); err != nil {
			return err
		}
	}
	return nil
}
