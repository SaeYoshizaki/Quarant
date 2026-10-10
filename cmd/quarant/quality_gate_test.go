package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunQualityGateUsesExperimentDefaultsAndWritesGuardedResearch(t *testing.T) {
	dir := t.TempDir()
	mustMkdir(t, filepath.Join(dir, "before", "assembled"))
	writeTestFile(t, filepath.Join(dir, "precision_eval_report.json"), `{"metrics":{"incident_count":2,"labeled_incident_count":1,"label_coverage":0.5}}`)
	writeTestFile(t, filepath.Join(dir, "before", "assembled", "attack_evidence_eval_report.json"), `{"metrics":{"finding_count":1,"unlabeled_count":1,"label_coverage":0}}`)
	writeTestFile(t, filepath.Join(dir, "mitigation_eval_report.json"), `{"metrics":{"attack_evidence_reduction_rate":0.5,"before_normal_flow_count":10,"normal_flow_preservation_rate":0.4}}`)
	writeTestFile(t, filepath.Join(dir, "before", "assembled", "source_coverage_report.json"), `{"metrics":{"source_count":1,"multi_source_service_count":0}}`)
	writeTestFile(t, filepath.Join(dir, "research_report.json"), `{"generated_at":"2026-09-26T12:00:00Z","executive_summary":"summary.","supported_claims":["claim"]}`)

	var out bytes.Buffer
	err := runQualityGate([]string{
		"--experiment", dir,
		"--research-out", filepath.Join(dir, "guarded_research_report.json"),
	}, &out)
	if err != nil {
		t.Fatalf("runQualityGate: %v", err)
	}
	reportData, err := os.ReadFile(filepath.Join(dir, "quality_gate_report.json"))
	if err != nil {
		t.Fatalf("read quality gate report: %v", err)
	}
	if !strings.Contains(string(reportData), `"overall_status": "fail"`) ||
		!strings.Contains(string(reportData), `"claim": "safe mitigation"`) {
		t.Fatalf("quality gate report=%s, want fail and safe mitigation adjustment", reportData)
	}
	guarded, err := os.ReadFile(filepath.Join(dir, "guarded_research_report.json"))
	if err != nil {
		t.Fatalf("read guarded research: %v", err)
	}
	if !strings.Contains(string(guarded), "Quality gate status: fail") {
		t.Fatalf("guarded research=%s, want quality gate status", guarded)
	}
	if !strings.Contains(out.String(), "Quality gate complete") {
		t.Fatalf("output=%q, want completion", out.String())
	}
}
