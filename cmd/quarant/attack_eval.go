package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"quarant/internal/reportapi"
)

func runAttackEval(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("attack-eval", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	attackEvidencePath := fs.String("attack-evidence", "attack_evidence_report.json", "attack evidence report JSON path")
	labelsPath := fs.String("labels", "attack_evidence_labels.jsonl", "human-reviewed attack evidence labels JSONL path")
	reportOut := fs.String("out", "attack_evidence_eval_report.json", "attack evidence evaluation report JSON output path")
	initLabels := fs.Bool("init-labels", false, "write a label template for attack evidence findings")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse attack-eval flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("attack-eval accepts flags only")
	}

	if *initLabels {
		report, err := reportapi.LoadAttackEvidenceReportJSON(*attackEvidencePath)
		if err != nil {
			return err
		}
		if err := writeAttackEvidenceLabelTemplate(*labelsPath, report.Findings); err != nil {
			return err
		}
		fmt.Fprintf(out, "Attack evidence label template written: %s findings=%d\n", *labelsPath, len(report.Findings))
		return nil
	}

	report, err := reportapi.LoadAttackEvidenceEvaluationReport(*attackEvidencePath, *labelsPath)
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
	fmt.Fprintf(out, "Attack evidence evaluation complete: labeled=%d unlabeled=%d meaningful_evidence_rate=%.3f noise_or_benign_rate=%.3f label_coverage=%.3f report=%s\n",
		report.Metrics.LabeledFindingCount,
		report.Metrics.UnlabeledCount,
		report.Metrics.MeaningfulEvidenceRate,
		report.Metrics.NoiseOrBenignRate,
		report.Metrics.LabelCoverage,
		*reportOut,
	)
	return nil
}

func writeAttackEvidenceLabelTemplate(path string, findings []reportapi.AttackEvidenceFinding) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	for _, finding := range findings {
		label := reportapi.AttackEvidenceLabel{
			FindingID:      finding.ID,
			Label:          "unlabeled",
			Kind:           finding.Kind,
			SrcIP:          finding.SrcIP,
			TargetDeviceIP: finding.TargetDeviceIP,
			Note:           attackEvidenceLabelNote(finding),
		}
		if err := enc.Encode(label); err != nil {
			return err
		}
	}
	return nil
}

func attackEvidenceLabelNote(finding reportapi.AttackEvidenceFinding) string {
	parts := []string{}
	if finding.EventCount > 0 {
		parts = append(parts, fmt.Sprintf("events=%d", finding.EventCount))
	}
	if len(finding.Ports) > 0 {
		parts = append(parts, fmt.Sprintf("ports=%s", joinAttackEvidenceLabelPorts(finding.Ports)))
	}
	if len(finding.Targets) > 0 {
		parts = append(parts, fmt.Sprintf("targets=%s", strings.Join(finding.Targets, ",")))
	}
	if finding.FirstSeen != "" || finding.LastSeen != "" {
		parts = append(parts, fmt.Sprintf("window=%s..%s", finding.FirstSeen, finding.LastSeen))
	}
	return strings.Join(parts, " ")
}

func joinAttackEvidenceLabelPorts(ports []uint16) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		if port != 0 {
			values = append(values, strconv.Itoa(int(port)))
		}
	}
	return strings.Join(values, ",")
}
