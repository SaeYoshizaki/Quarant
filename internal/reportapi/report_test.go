package reportapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReportJSONWithEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	data := `{
  "generated_at": "2026-05-02T00:00:00Z",
  "source": "report.json",
  "total_events": 1,
  "severity": [{"key":"HIGH","count":1}],
  "rules": [{"key":"I3_API_OVER_PLAINTEXT","count":1}],
  "categories": [{"key":"I3","count":1}],
  "sources": [{"key":"192.168.1.50","count":1}],
  "events": [{
    "ts":"2026-05-02T00:00:10Z",
    "type":"I3_API_OVER_PLAINTEXT",
    "severity":"HIGH",
    "rule_id":"I3_API_OVER_PLAINTEXT",
    "category":"I3",
    "src_ip":"192.168.1.50",
    "message":"HTTP API-like communication was observed over plaintext transport."
  }]
}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write report json: %v", err)
	}

	got, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if got.TotalEvents != 1 {
		t.Fatalf("TotalEvents=%d, want 1", got.TotalEvents)
	}
	if len(got.Events) != 1 || got.Events[0].RuleID != "I3_API_OVER_PLAINTEXT" {
		t.Fatalf("unexpected events: %+v", got.Events)
	}
	if len(got.Sources) != 1 || got.Sources[0].Key != "192.168.1.50" {
		t.Fatalf("unexpected sources: %+v", got.Sources)
	}
}

func TestLoadReportJSONLegacySummary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	data := `{
  "window": {
    "start": "2026-03-04T07:06:48Z",
    "end": "2026-03-04T07:33:24Z"
  },
  "total_events": 27,
  "severity": [{"key":"INFO","count":15}],
  "rules": [{"key":"PAYLOAD_DEBUG","count":9}],
  "src_ip": [{"key":"10.0.1.2","count":27}],
  "flows": [{"key":"tcp|10.0.1.2:35636<->10.0.2.2:80","count":2}]
}`
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write legacy report json: %v", err)
	}

	got, err := LoadReport(path)
	if err != nil {
		t.Fatalf("LoadReport: %v", err)
	}
	if got.TotalEvents != 27 {
		t.Fatalf("TotalEvents=%d, want 27", got.TotalEvents)
	}
	if len(got.Sources) != 1 || got.Sources[0].Key != "10.0.1.2" {
		t.Fatalf("unexpected normalized sources: %+v", got.Sources)
	}
	if got.Source != path {
		t.Fatalf("Source=%q, want %q", got.Source, path)
	}
	if strings.TrimSpace(got.GeneratedAt) == "" {
		t.Fatal("GeneratedAt should be set")
	}
}
