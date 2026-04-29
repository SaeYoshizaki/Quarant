package reportapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadActivitySummaryAggregatesTodayUsingFlowDeltas(t *testing.T) {
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	yesterday := dayStart.Add(-time.Hour)
	todayA := dayStart.Add(1 * time.Hour)
	todayB := dayStart.Add(2 * time.Hour)

	dir := t.TempDir()
	flowsPath := filepath.Join(dir, "flows.jsonl")
	eventsPath := filepath.Join(dir, "events.jsonl")

	flows := strings.Join([]string{
		`{"ts":"` + yesterday.Format(time.RFC3339) + `","flow_key":"tcp|a","src_ip":"192.168.1.10","dst_ip":"34.117.59.81","direction":"external","observed_destination":"api.example.com","bytes_out":40,"bytes_in":60}`,
		`{"ts":"` + todayA.Format(time.RFC3339) + `","flow_key":"tcp|a","src_ip":"192.168.1.10","dst_ip":"34.117.59.81","direction":"external","observed_destination":"api.example.com","device_label":"Living Room Camera","bytes_out":100,"bytes_in":200}`,
		`{"ts":"` + todayB.Format(time.RFC3339) + `","flow_key":"tcp|a","src_ip":"192.168.1.10","dst_ip":"34.117.59.81","direction":"external","observed_destination":"api.example.com","device_label":"Living Room Camera","bytes_out":150,"bytes_in":260}`,
		`{"ts":"` + todayB.Format(time.RFC3339) + `","flow_key":"tcp|b","src_ip":"192.168.1.20","dst_ip":"192.168.1.1","direction":"local","observed_destination":"192.168.1.1","bytes_out":20,"bytes_in":10}`,
	}, "\n") + "\n"
	if err := os.WriteFile(flowsPath, []byte(flows), 0644); err != nil {
		t.Fatalf("write flows: %v", err)
	}

	events := strings.Join([]string{
		`{"ts":"` + todayA.Format(time.RFC3339) + `","type":"I7_HTTP_PLAINTEXT","rule_id":"I7_HTTP_PLAINTEXT","category":"I7"}`,
		`{"ts":"` + todayB.Format(time.RFC3339) + `","type":"DEVICE_DEBUG","debug":true,"category":"I7"}`,
		`{"ts":"` + todayB.Format(time.RFC3339) + `","type":"I6_PII_TO_UNEXPECTED_DESTINATION","rule_id":"I6_PII_TO_UNEXPECTED_DESTINATION","category":"I6"}`,
	}, "\n") + "\n"
	if err := os.WriteFile(eventsPath, []byte(events), 0644); err != nil {
		t.Fatalf("write events: %v", err)
	}

	got, err := LoadActivitySummary(eventsPath, flowsPath)
	if err != nil {
		t.Fatalf("LoadActivitySummary: %v", err)
	}

	if got.Summary.DeviceCount != 2 {
		t.Fatalf("DeviceCount=%d, want 2", got.Summary.DeviceCount)
	}
	if got.Summary.ExternalFlowCount != 1 {
		t.Fatalf("ExternalFlowCount=%d, want 1", got.Summary.ExternalFlowCount)
	}
	if got.Summary.NewDestinationCount != 1 {
		t.Fatalf("NewDestinationCount=%d, want 1", got.Summary.NewDestinationCount)
	}
	if got.Summary.RiskEventCount != 2 {
		t.Fatalf("RiskEventCount=%d, want 2", got.Summary.RiskEventCount)
	}
	if got.Summary.TotalBytesOut != 130 || got.Summary.TotalBytesIn != 210 {
		t.Fatalf("unexpected byte totals: out=%d in=%d", got.Summary.TotalBytesOut, got.Summary.TotalBytesIn)
	}
	if len(got.TrafficByDevice) < 2 || got.TrafficByDevice[0].Device != "192.168.1.10" || got.TrafficByDevice[0].BytesTotal != 310 {
		t.Fatalf("unexpected traffic_by_device: %+v", got.TrafficByDevice)
	}
	if len(got.TopDestinations) != 1 || got.TopDestinations[0].Destination != "api.example.com" || got.TopDestinations[0].BytesTotal != 310 {
		t.Fatalf("unexpected top_destinations: %+v", got.TopDestinations)
	}
	if len(got.NewDestinations) != 1 {
		t.Fatalf("unexpected new_destinations: %+v", got.NewDestinations)
	}
	if len(got.RiskByCategory) != 2 || got.RiskByCategory[0].Category != "I6" && got.RiskByCategory[0].Category != "I7" {
		t.Fatalf("unexpected risk_by_category: %+v", got.RiskByCategory)
	}
	if len(got.TrafficByHour) != 24 || len(got.RiskByHour) != 24 {
		t.Fatalf("expected 24 hourly buckets")
	}
}

func TestLoadActivitySummaryHandlesMissingFiles(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadActivitySummary(filepath.Join(dir, "missing-events.jsonl"), filepath.Join(dir, "missing-flows.jsonl"))
	if err != nil {
		t.Fatalf("LoadActivitySummary missing files: %v", err)
	}
	if got.Summary.DeviceCount != 0 || got.Summary.RiskEventCount != 0 {
		t.Fatalf("expected empty summary, got %+v", got.Summary)
	}
	if len(got.TrafficByHour) != 24 || len(got.RiskByHour) != 24 {
		t.Fatalf("expected empty hourly buckets")
	}
}
