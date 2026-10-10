package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAttackEvalInitLabelsWritesTemplate(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "attack_evidence_report.json")
	labelsPath := filepath.Join(dir, "attack_evidence_labels.jsonl")
	writeTestFile(t, reportPath, `{
  "findings": [
    {
      "id": "atk_one",
      "kind": "port_scan",
      "src_ip": "203.0.113.9",
      "target_device_ip": "192.168.8.42",
      "ports": [23, 80, 8080],
      "event_count": 3,
      "first_seen": "2026-09-26T12:00:00Z",
      "last_seen": "2026-09-26T12:01:00Z"
    }
  ]
}`)

	var out bytes.Buffer
	if err := runAttackEval([]string{"--attack-evidence", reportPath, "--labels", labelsPath, "--init-labels"}, &out); err != nil {
		t.Fatalf("runAttackEval init labels: %v", err)
	}
	data, err := os.ReadFile(labelsPath)
	if err != nil {
		t.Fatalf("read labels: %v", err)
	}
	if !strings.Contains(string(data), `"finding_id":"atk_one"`) || !strings.Contains(string(data), `"label":"unlabeled"`) || !strings.Contains(string(data), `ports=23,80,8080`) {
		t.Fatalf("labels=%s, want label template context", data)
	}
	if !strings.Contains(out.String(), "Attack evidence label template written") {
		t.Fatalf("output=%q, want label template summary", out.String())
	}
}

func TestRunAttackEvalWritesEvaluationReport(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "attack_evidence_report.json")
	labelsPath := filepath.Join(dir, "attack_evidence_labels.jsonl")
	outPath := filepath.Join(dir, "attack_evidence_eval_report.json")
	writeTestFile(t, reportPath, `{
  "findings": [
    {"id": "atk_one", "kind": "port_scan", "severity": "WARNING", "confidence": "medium"},
    {"id": "atk_two", "kind": "sensitive_service_probe", "severity": "WARNING", "confidence": "medium"}
  ]
}`)
	writeTestFile(t, labelsPath, `{"finding_id":"atk_one","label":"true_attack"}`+"\n"+`{"finding_id":"atk_two","label":"benign_admin"}`+"\n")

	var out bytes.Buffer
	if err := runAttackEval([]string{"--attack-evidence", reportPath, "--labels", labelsPath, "--out", outPath}, &out); err != nil {
		t.Fatalf("runAttackEval: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), `"meaningful_evidence_count": 1`) || !strings.Contains(string(data), `"noise_or_benign_count": 1`) {
		t.Fatalf("report=%s, want separated evidence evaluation metrics", data)
	}
	if !strings.Contains(out.String(), "Attack evidence evaluation complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}
