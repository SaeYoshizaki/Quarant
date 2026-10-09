package reportapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildPrecisionEvaluationReportComputesMetricsAndBreakdowns(t *testing.T) {
	incidents := []PrecisionIncident{
		{
			ID:       "inc_tp",
			State:    "risky",
			Severity: "HIGH",
			DeviceIP: "192.168.50.20",
			Signals: []PrecisionSignal{
				{Key: "event_i7_http_auth", Layer: "observation"},
				{Key: "correlation_direct_sensitive_exposure", Layer: "correlation"},
			},
		},
		{
			ID:       "inc_fp",
			State:    "suspicious",
			Severity: "WARNING",
			DeviceIP: "192.168.50.30",
			Signals: []PrecisionSignal{
				{Key: "unknown_udp", Layer: "context"},
			},
		},
		{
			ID:       "inc_unlabeled",
			State:    "observe",
			Severity: "INFO",
			DeviceIP: "192.168.50.40",
			Signals: []PrecisionSignal{
				{Key: "baseline_novelty", Layer: "context"},
			},
		},
	}
	labels := []IncidentLabel{
		{IncidentID: "inc_tp", Label: "true_positive"},
		{IncidentID: "inc_fp", Label: "false_positive"},
		{Label: "false_negative", DeviceIP: "192.168.50.99", Note: "missed scan"},
	}

	got := BuildPrecisionEvaluationReport(incidents, labels)
	if got.Metrics.TruePositiveCount != 1 || got.Metrics.FalsePositiveCount != 1 || got.Metrics.FalseNegativeCount != 1 {
		t.Fatalf("metrics=%+v, want tp/fp/fn counts", got.Metrics)
	}
	if got.Metrics.Precision != 0.5 {
		t.Fatalf("Precision=%v, want 0.5", got.Metrics.Precision)
	}
	if got.Metrics.Recall != 0.5 {
		t.Fatalf("Recall=%v, want 0.5", got.Metrics.Recall)
	}
	if got.Metrics.UnlabeledCount != 1 || len(got.UnlabeledIncidents) != 1 {
		t.Fatalf("unlabeled metrics=%+v incidents=%+v, want 1", got.Metrics, got.UnlabeledIncidents)
	}
	if !evaluationBreakdownExists(got.ByLayer, "observation") || !evaluationBreakdownExists(got.BySignal, "unknown_udp") {
		t.Fatalf("breakdowns layer=%+v signal=%+v, want observation and unknown_udp", got.ByLayer, got.BySignal)
	}
}

func TestLoadPrecisionEvaluationReportReadsFiles(t *testing.T) {
	dir := t.TempDir()
	incidentsPath := filepath.Join(dir, "incidents.jsonl")
	labelsPath := filepath.Join(dir, "labels.jsonl")

	if err := os.WriteFile(incidentsPath, []byte(`{"id":"inc_1","state":"risky","severity":"HIGH","device_ip":"192.168.50.20","signals":[{"key":"event_i7_http_auth","layer":"observation"}]}`+"\n"), 0644); err != nil {
		t.Fatalf("write incidents: %v", err)
	}
	if err := os.WriteFile(labelsPath, []byte(`{"incident_id":"inc_1","label":"tp","note":"confirmed"}`+"\n"), 0644); err != nil {
		t.Fatalf("write labels: %v", err)
	}

	got, err := LoadPrecisionEvaluationReport(incidentsPath, labelsPath)
	if err != nil {
		t.Fatalf("LoadPrecisionEvaluationReport: %v", err)
	}
	if got.Source.Incidents != incidentsPath || got.Metrics.TruePositiveCount != 1 || got.Metrics.Precision != 1 {
		t.Fatalf("got=%+v, want source and precision", got)
	}
}

func evaluationBreakdownExists(items []EvaluationBreakdown, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}
