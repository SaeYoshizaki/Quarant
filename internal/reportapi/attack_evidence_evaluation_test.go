package reportapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildAttackEvidenceEvaluationReportSeparatesMeaningfulAndNoiseLabels(t *testing.T) {
	attackEvidence := AttackEvidenceReport{
		Findings: []AttackEvidenceFinding{
			{ID: "atk_true", Kind: "port_scan", Severity: "WARNING", Confidence: "medium"},
			{ID: "atk_lab", Kind: "suspicious_tcp_flags", Severity: "WARNING", Confidence: "medium"},
			{ID: "atk_noise", Kind: "host_sweep", Severity: "INFO", Confidence: "low"},
			{ID: "atk_unlabeled", Kind: "sensitive_service_probe", Severity: "WARNING", Confidence: "medium"},
		},
	}
	labels := []AttackEvidenceLabel{
		{FindingID: "atk_true", Label: "true_attack"},
		{FindingID: "atk_lab", Label: "scanner_lab_generated"},
		{FindingID: "atk_noise", Label: "internet_background_noise"},
		{FindingID: "atk_unlabeled", Label: "unlabeled"},
	}

	report := BuildAttackEvidenceEvaluationReport(attackEvidence, labels)
	if report.Metrics.FindingCount != 4 || report.Metrics.LabeledFindingCount != 3 || report.Metrics.UnlabeledCount != 1 {
		t.Fatalf("metrics=%+v, want finding/labeled/unlabeled counts", report.Metrics)
	}
	if report.Metrics.MeaningfulEvidenceCount != 2 || report.Metrics.NoiseOrBenignCount != 1 {
		t.Fatalf("metrics=%+v, want separated meaningful and noise counts", report.Metrics)
	}
	if report.Metrics.MeaningfulEvidenceRate != ratio(2, 3) || report.Metrics.NoiseOrBenignRate != ratio(1, 3) || report.Metrics.LabelCoverage != ratio(3, 4) {
		t.Fatalf("metrics=%+v, want derived rates", report.Metrics)
	}
	if len(report.UnlabeledFindings) != 1 || report.UnlabeledFindings[0].ID != "atk_unlabeled" {
		t.Fatalf("unlabeled=%+v, want atk_unlabeled", report.UnlabeledFindings)
	}
	if !attackEvidenceBreakdownHas(report.ByKind, "port_scan", 1, 1, 0) {
		t.Fatalf("by_kind=%+v, want port_scan true attack breakdown", report.ByKind)
	}
	if !attackEvidenceBreakdownHas(report.ByKind, "host_sweep", 1, 0, 1) {
		t.Fatalf("by_kind=%+v, want host_sweep noise breakdown", report.ByKind)
	}
}

func TestLoadAttackEvidenceEvaluationReport(t *testing.T) {
	dir := t.TempDir()
	attackEvidencePath := filepath.Join(dir, "attack_evidence_report.json")
	labelsPath := filepath.Join(dir, "attack_evidence_labels.jsonl")

	writeTestData(t, attackEvidencePath, `{
  "findings": [
    {
      "id": "atk_one",
      "kind": "port_scan",
      "severity": "WARNING",
      "confidence": "medium"
    }
  ]
}`)
	writeTestData(t, labelsPath, `{"finding_id":"atk_one","label":"tp"}`+"\n")

	report, err := LoadAttackEvidenceEvaluationReport(attackEvidencePath, labelsPath)
	if err != nil {
		t.Fatalf("LoadAttackEvidenceEvaluationReport: %v", err)
	}
	if report.Metrics.TrueAttackCount != 1 || report.Source.AttackEvidenceReport != attackEvidencePath || report.Source.Labels != labelsPath {
		t.Fatalf("report=%+v, want loaded true attack with source paths", report)
	}
}

func attackEvidenceBreakdownHas(items []AttackEvidenceEvaluationBreakdown, key string, total, trueAttack, noise int) bool {
	for _, item := range items {
		if item.Key == key && item.Total == total && item.TrueAttackCount == trueAttack && item.InternetBackgroundNoiseCount == noise {
			return true
		}
	}
	return false
}

func writeTestData(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
