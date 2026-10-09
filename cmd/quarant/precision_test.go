package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunPrecisionWritesReportAndIncidents(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")
	observationsPath := filepath.Join(dir, "observations.jsonl")
	inventoryPath := filepath.Join(dir, "device_inventory.json")
	reportPath := filepath.Join(dir, "precision_report.json")
	incidentsPath := filepath.Join(dir, "incidents.jsonl")

	writeTestFile(t, eventsPath, `{"ts":"2026-09-27T10:00:00Z","rule_id":"I7_HTTP_AUTH","type":"INSECURE_HTTP_AUTH","category":"I7","severity":"CRITICAL","confidence":"high","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80}`+"\n")
	writeTestFile(t, flowsPath, `{"ts":"2026-09-27T10:00:00Z","flow_key":"tcp|auth","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.example"}`+"\n")
	writeTestFile(t, observationsPath, "")
	writeTestFile(t, inventoryPath, `{"devices":[{"ip":"192.168.50.20","category_candidate":"Camera"}]}`)

	var out bytes.Buffer
	err := runPrecision([]string{
		"--events", eventsPath,
		"--flows", flowsPath,
		"--observations", observationsPath,
		"--inventory", inventoryPath,
		"--out", reportPath,
		"--incidents-out", incidentsPath,
	}, &out)
	if err != nil {
		t.Fatalf("runPrecision: %v", err)
	}
	if !strings.Contains(out.String(), "Precision complete") {
		t.Fatalf("output=%q, want completion", out.String())
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(reportData), `"risky_incident_count": 1`) {
		t.Fatalf("report=%s, want risky incident count", reportData)
	}
	incidentData, err := os.ReadFile(incidentsPath)
	if err != nil {
		t.Fatalf("read incidents: %v", err)
	}
	if !strings.Contains(string(incidentData), `"state":"risky"`) {
		t.Fatalf("incidents=%s, want risky incident", incidentData)
	}
}
