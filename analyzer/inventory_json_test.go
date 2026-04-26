package analyzer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quarant/analyzer/device"
)

func TestMarshalDeviceInventoryReportIncludesExpectedFields(t *testing.T) {
	now := time.Date(2026, 4, 26, 0, 10, 0, 0, time.UTC)
	devices := []device.InventorySnapshot{
		{
			IP:                 "10.0.1.2",
			FirstSeen:          "2026-04-26T00:00:00Z",
			LastSeen:           "2026-04-26T00:10:00Z",
			ObservedProtocols:  []string{"http"},
			ObservedPorts:      []uint16{80},
			ObservedHosts:      []string{"api.vendor-cloud.test"},
			ObservedSNI:        []string{},
			CategoryCandidate:  "GenericIoT",
			CategoryConfidence: "very_low",
			VendorCandidate:    "Philips",
			VendorConfidence:   "low",
			FamilyCandidate:    "philips_hue_hub",
			FamilyConfidence:   "low",
			RiskEventCount:     4,
			SeverityCounts: map[string]int{
				"WARNING": 2,
				"HIGH":    2,
			},
			OWASPTagCounts: map[string]int{
				"I3": 4,
				"I7": 4,
				"I9": 1,
			},
			LastRiskEventType: "I3_AUTH_TOKEN_IN_URL",
			LastRiskEventTS:   "2026-04-26T00:10:00Z",
		},
	}

	data, err := MarshalDeviceInventoryReport(now, devices)
	if err != nil {
		t.Fatalf("marshal inventory report: %v", err)
	}
	text := string(data)

	for _, want := range []string{
		`"generated_at": "2026-04-26T00:10:00Z"`,
		`"first_seen": "2026-04-26T00:00:00Z"`,
		`"last_seen": "2026-04-26T00:10:00Z"`,
		`"observed_hosts": [`,
		`"api.vendor-cloud.test"`,
		`"observed_ports": [`,
		`"observed_protocols": [`,
		`"risk_event_count": 4`,
		`"severity_counts": {`,
		`"owasp_tag_counts": {`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected inventory JSON to contain %q, got: %s", want, text)
		}
	}
}

func TestInventorySnapshotExcludesDebugEventsAndSecretValues(t *testing.T) {
	p := device.NewProfile("10.0.1.3")
	now := time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC)
	p.ObserveActivity(now)
	p.Hosts["device.local"] = true
	p.Protocols["http"] = true
	p.Ports[80] = true

	// Risk summary is only driven by explicit risk events, not debug output.
	p.RecordRiskEvent(now.Add(time.Minute), "I7_HTTP_AUTH", "HIGH", []string{"I1", "I3", "I7"})
	data, err := MarshalDeviceInventoryReport(now, []device.InventorySnapshot{p.Snapshot()})
	if err != nil {
		t.Fatalf("marshal inventory report: %v", err)
	}
	text := string(data)

	if strings.Contains(text, "super-secret-token-value") || strings.Contains(text, "hunter2") {
		t.Fatalf("inventory should not contain secret values, got: %s", text)
	}
	if strings.Contains(text, "PAYLOAD_DEBUG") || strings.Contains(text, "DEVICE_DEBUG") {
		t.Fatalf("inventory should not contain debug events, got: %s", text)
	}
	if !strings.Contains(text, `"risk_event_count": 1`) {
		t.Fatalf("expected only one risk event in inventory, got: %s", text)
	}
}

func TestWriteDeviceInventoryJSONWritesPrettyPrintedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device_inventory.json")
	now := time.Date(2026, 4, 26, 0, 10, 0, 0, time.UTC)

	err := WriteDeviceInventoryJSON(path, now, []device.InventorySnapshot{
		{
			IP:                 "10.0.1.2",
			FirstSeen:          "2026-04-26T00:00:00Z",
			LastSeen:           "2026-04-26T00:10:00Z",
			ObservedProtocols:  []string{"http"},
			ObservedPorts:      []uint16{80},
			ObservedHosts:      []string{"api.vendor-cloud.test"},
			CategoryCandidate:  "GenericIoT",
			CategoryConfidence: "very_low",
			RiskEventCount:     1,
		},
	})
	if err != nil {
		t.Fatalf("write inventory json: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read inventory json: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "\n  \"devices\": [\n") {
		t.Fatalf("expected pretty printed JSON, got: %s", text)
	}
}
