package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunEvalWritesTemplateAndReport(t *testing.T) {
	dir := t.TempDir()
	incidentsPath := filepath.Join(dir, "incidents.jsonl")
	labelsPath := filepath.Join(dir, "labels.jsonl")
	reportPath := filepath.Join(dir, "eval.json")

	writeTestFile(t, incidentsPath, `{"id":"inc_1","state":"risky","severity":"HIGH","device_ip":"192.168.50.20","title":"Credential exposure","signals":[{"key":"event_i7_http_auth","layer":"observation"}]}`+"\n")

	var templateOut bytes.Buffer
	if err := runEval([]string{
		"--incidents", incidentsPath,
		"--labels", labelsPath,
		"--init-labels",
	}, &templateOut); err != nil {
		t.Fatalf("runEval init labels: %v", err)
	}
	templateData, err := os.ReadFile(labelsPath)
	if err != nil {
		t.Fatalf("read labels template: %v", err)
	}
	if !strings.Contains(string(templateData), `"label":"unlabeled"`) || !strings.Contains(templateOut.String(), "Label template written") {
		t.Fatalf("template=%s output=%s, want unlabeled template", templateData, templateOut.String())
	}

	writeTestFile(t, labelsPath, `{"incident_id":"inc_1","label":"true_positive","note":"confirmed"}`+"\n")
	var evalOut bytes.Buffer
	if err := runEval([]string{
		"--incidents", incidentsPath,
		"--labels", labelsPath,
		"--out", reportPath,
	}, &evalOut); err != nil {
		t.Fatalf("runEval report: %v", err)
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read eval report: %v", err)
	}
	if !strings.Contains(string(reportData), `"precision": 1`) || !strings.Contains(evalOut.String(), "Evaluation complete") {
		t.Fatalf("report=%s output=%s, want precision report", reportData, evalOut.String())
	}
}
