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

func runEval(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("eval", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	incidentsPath := fs.String("incidents", "incidents.jsonl", "incidents JSONL path")
	labelsPath := fs.String("labels", "incident_labels.jsonl", "human labels JSONL path")
	reportOut := fs.String("out", "precision_eval_report.json", "evaluation report JSON output path")
	initLabels := fs.Bool("init-labels", false, "write a label template for unlabeled incidents")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse eval flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("eval accepts flags only")
	}

	if *initLabels {
		incidents, err := reportapi.LoadPrecisionIncidents(*incidentsPath)
		if err != nil {
			return err
		}
		if err := writeIncidentLabelTemplate(*labelsPath, incidents); err != nil {
			return err
		}
		fmt.Fprintf(out, "Label template written: %s incidents=%d\n", *labelsPath, len(incidents))
		return nil
	}

	report, err := reportapi.LoadPrecisionEvaluationReport(*incidentsPath, *labelsPath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reportOut) != "" && *reportOut != "-" {
		if err := writePrettyJSON(*reportOut, report); err != nil {
			return err
		}
	}
	if *reportOut == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(out, "Evaluation complete: labeled=%d unlabeled=%d precision=%.3f false_positive_rate=%.3f report=%s\n",
		report.Metrics.LabeledIncidentCount,
		report.Metrics.UnlabeledCount,
		report.Metrics.Precision,
		report.Metrics.FalsePositiveRate,
		*reportOut,
	)
	return nil
}

func writeIncidentLabelTemplate(path string, incidents []reportapi.PrecisionIncident) error {
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
		label := reportapi.IncidentLabel{
			IncidentID: incident.ID,
			Label:      "unlabeled",
			DeviceIP:   incident.DeviceIP,
			Note:       incident.Title,
		}
		if err := enc.Encode(label); err != nil {
			return err
		}
	}
	return nil
}
