package analyzer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
	"quarant/internal/synth"
)

type scenarioRun struct {
	events    []Event
	flows     []FlowRecord
	inventory map[string]map[string]any
}

// runHomeScenario analyzes the synthetic home network end to end through the
// same Engine/FlowHandler path the CLI uses.
func runHomeScenario(t *testing.T) (*synth.Scenario, scenarioRun) {
	t.Helper()
	start := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	scenario := synth.HomeScenario(start)
	var pcap bytes.Buffer
	if err := scenario.Builder.WritePCAP(&pcap); err != nil {
		t.Fatal(err)
	}

	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatalf("load knowledge: %v", err)
	}
	dir := t.TempDir()
	open := func(name string) *JSONLSink {
		s, err := NewJSONSink(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	events, flows, observations := open("events.jsonl"), open("flows.jsonl"), open("observations.jsonl")
	handler := NewFlowHandlerWithObservations(events, flows, observations, false, db)
	if err := NewEngine(handler).RunPCAPStream(&pcap); err != nil {
		t.Fatal(err)
	}
	inv := handler.DeviceInventory()
	for _, s := range []*JSONLSink{events, flows, observations} {
		_ = s.Close()
	}

	var run scenarioRun
	readJSONL(t, filepath.Join(dir, "events.jsonl"), func(b []byte) {
		var e Event
		if err := json.Unmarshal(b, &e); err != nil {
			t.Fatal(err)
		}
		run.events = append(run.events, e)
	})
	readJSONL(t, filepath.Join(dir, "flows.jsonl"), func(b []byte) {
		var f FlowRecord
		if err := json.Unmarshal(b, &f); err != nil {
			t.Fatal(err)
		}
		run.flows = append(run.flows, f)
	})
	run.inventory = map[string]map[string]any{}
	raw, _ := json.Marshal(inv)
	var list []map[string]any
	_ = json.Unmarshal(raw, &list)
	for _, d := range list {
		run.inventory[d["ip"].(string)] = d
	}
	return scenario, run
}

func readJSONL(t *testing.T, path string, fn func([]byte)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		fn(sc.Bytes())
	}
}

func (r scenarioRun) has(deviceIP, eventType string) bool {
	for _, e := range r.events {
		if e.DeviceKey == deviceIP && e.Type == eventType {
			return true
		}
	}
	return false
}

func TestHomeScenarioUsesCaptureTime(t *testing.T) {
	scenario, run := runHomeScenario(t)
	if len(run.events) == 0 {
		t.Fatal("expected events")
	}
	for _, e := range run.events {
		if e.Timestamp.Before(scenario.Start) || e.Timestamp.After(scenario.End) {
			t.Fatalf("event %s at %s is outside the capture window %s..%s", e.Type, e.Timestamp, scenario.Start, scenario.End)
		}
	}
}

func TestHomeScenarioOnlyLocalHostsAreDevices(t *testing.T) {
	_, run := runHomeScenario(t)
	for ip := range run.inventory {
		if !DefaultLocalNetworks().Contains(ip) {
			t.Errorf("remote host %s was inventoried as a device", ip)
		}
	}
	for _, e := range run.events {
		if e.Type == "I8_NEW_DEVICE_OBSERVED" && !DefaultLocalNetworks().Contains(e.DeviceKey) {
			t.Errorf("new-device notification for remote host %s", e.DeviceKey)
		}
	}
}

func TestHomeScenarioIdentity(t *testing.T) {
	_, run := runHomeScenario(t)
	cam := run.inventory["192.168.50.20"]
	if cam["mac_address"] != "0c:75:d2:1a:2b:3c" || cam["hostname"] != "IPCAM-1A2B3C" {
		t.Fatalf("camera identity: mac=%v hostname=%v", cam["mac_address"], cam["hostname"])
	}
	if v, _ := cam["mac_vendor"].(string); v == "" {
		t.Fatal("expected OUI vendor for camera")
	}
	phone := run.inventory["192.168.50.30"]
	if phone["mac_locally_administered"] != true || phone["mac_vendor"] != nil {
		t.Fatalf("randomized phone MAC must have no vendor: %v", phone)
	}
	foundMDNS := false
	for _, e := range run.inventory["192.168.50.21"]["identity_evidence"].([]any) {
		ev := e.(map[string]any)
		if ev["source"] == "mdns" && ev["attribute"] == "mdns_service" {
			foundMDNS = true
		}
		if ev["attribute"] == "mac_vendor" && ev["basis"] != "reference_match" {
			t.Fatalf("OUI vendor must be marked reference_match: %v", ev)
		}
	}
	if !foundMDNS {
		t.Fatal("expected mDNS service evidence for the smart plug")
	}
}

func TestHomeScenarioAttribution(t *testing.T) {
	_, run := runHomeScenario(t)
	// Server-side exposure belongs to the camera, not the phone that connected.
	for _, typ := range []string{"I2_TELNET_SERVICE_OBSERVED", "I2_HTTP_ADMIN_INTERFACE_SUSPECTED"} {
		if !run.has("192.168.50.20", typ) {
			t.Errorf("expected %s on the camera", typ)
		}
		if run.has("192.168.50.30", typ) {
			t.Errorf("%s must not be attributed to the phone", typ)
		}
	}
	if !run.has("192.168.50.20", "INSECURE_HTTP_AUTH") || !run.has("192.168.50.20", "I7_TLS_WEAK_VERSION_OBSERVED") {
		t.Error("expected camera plaintext auth and weak TLS findings")
	}
	if !run.has("192.168.50.21", "INSECURE_MQTT_CREDENTIALS") {
		t.Error("expected plug MQTT credential finding")
	}
}

func TestHomeScenarioNoFalsePositivesOnControlsAndScans(t *testing.T) {
	_, run := runHomeScenario(t)
	for _, e := range run.events {
		if e.DeviceKey == "192.168.50.30" && (e.Type == "I7_TLS_WEAK_CIPHER_OFFERED" || e.Type == "I7_TLS_WEAK_VERSION_OBSERVED") {
			t.Errorf("negative control (modern TLS phone) flagged: %s", e.Type)
		}
		if e.DeviceKey == "192.168.50.22" && (e.Type == "I2_TELNET_SERVICE_OBSERVED" || e.Type == "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK") {
			t.Errorf("unanswered scan SYNs claimed a service: %s", e.Type)
		}
		if e.DeviceKey == "192.168.50.22" && e.Type == "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED" {
			t.Error("beacon to a vendor-looking host must not be called an admin interface")
		}
	}
}

func TestHomeScenarioFlushesFinalFlowRecords(t *testing.T) {
	_, run := runHomeScenario(t)
	last := map[string]FlowRecord{}
	for _, f := range run.flows {
		last[f.FlowKey] = f
	}
	// Camera -> cloud TLS flow: SYN, SYN/ACK, ACK, hello+ack, FIN/FIN/ACK = 8 packets.
	for key, f := range last {
		if f.SrcIP == "192.168.50.20" && f.DstPort == 443 {
			if f.PacketCount != 8 {
				t.Fatalf("flow %s final packet count = %d, want 8", key, f.PacketCount)
			}
			return
		}
	}
	t.Fatal("camera TLS flow not found")
}
