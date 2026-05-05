package reportapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInventoryMissingFileReturnsEmptyDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")

	got, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(got.Devices) != 0 {
		t.Fatalf("Devices=%d, want 0", len(got.Devices))
	}
}

func TestLoadInventoryInvalidJSONReturnsEmptyDevices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device_inventory.json")
	if err := os.WriteFile(path, []byte("{"), 0644); err != nil {
		t.Fatalf("write inventory json: %v", err)
	}

	got, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(got.Devices) != 0 {
		t.Fatalf("Devices=%d, want 0", len(got.Devices))
	}
}

func TestLoadInventoryWithFallbackBuildsDevicesFromEventsAndFlows(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")

	events := []byte(
		"{\"ts\":\"2026-05-05T10:00:00Z\",\"rule_id\":\"I7_HTTP_PLAINTEXT\",\"severity\":\"WARNING\",\"device_key\":\"192.168.2.4\",\"src_ip\":\"192.168.2.4\",\"dst_ip\":\"198.51.100.10\",\"dst_port\":80}\n" +
			"{\"ts\":\"2026-05-05T10:01:00Z\",\"rule_id\":\"I7_HTTP_AUTH\",\"severity\":\"HIGH\",\"src_ip\":\"198.51.100.10\",\"dst_ip\":\"192.168.2.4\",\"dst_port\":80}\n",
	)
	flows := []byte(
		"{\"ts\":\"2026-05-05T10:00:00Z\",\"flow_key\":\"192.168.2.4:1234-198.51.100.10:80-tcp\",\"src_ip\":\"192.168.2.4\",\"dst_ip\":\"198.51.100.10\",\"src_port\":1234,\"dst_port\":80,\"protocol\":\"tcp\",\"app_protocol\":\"http\"}\n",
	)
	if err := os.WriteFile(eventsPath, events, 0644); err != nil {
		t.Fatalf("write events: %v", err)
	}
	if err := os.WriteFile(flowsPath, flows, 0644); err != nil {
		t.Fatalf("write flows: %v", err)
	}

	got, err := LoadInventoryWithFallback(filepath.Join(dir, "missing-device_inventory.json"), eventsPath, flowsPath)
	if err != nil {
		t.Fatalf("LoadInventoryWithFallback: %v", err)
	}
	if len(got.Devices) == 0 {
		t.Fatal("expected derived devices")
	}

	var camera *InventoryDevice
	for i := range got.Devices {
		if got.Devices[i].IP == "192.168.2.4" {
			camera = &got.Devices[i]
			break
		}
	}
	if camera == nil {
		t.Fatalf("expected camera device in %+v", got.Devices)
	}
	if camera.EventCount != 2 {
		t.Fatalf("EventCount=%d, want 2", camera.EventCount)
	}
	if camera.FlowCount != 1 {
		t.Fatalf("FlowCount=%d, want 1", camera.FlowCount)
	}
	if camera.RiskEventCount != 2 {
		t.Fatalf("RiskEventCount=%d, want 2", camera.RiskEventCount)
	}
	if camera.RiskSummary == nil || camera.RiskSummary.HighestSeverity != "HIGH" {
		t.Fatalf("unexpected RiskSummary: %+v", camera.RiskSummary)
	}
}
