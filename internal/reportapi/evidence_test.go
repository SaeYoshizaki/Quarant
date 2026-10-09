package reportapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildDeviceEvidenceReportCombinesSignalsByDevice(t *testing.T) {
	ts := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	events := []Event{
		{
			Timestamp:      ts,
			Type:           "INSECURE_HTTP_AUTH",
			RuleID:         "I7_HTTP_AUTH",
			Category:       "I7",
			Severity:       "CRITICAL",
			Confidence:     "high",
			SrcIP:          "192.168.1.20",
			DstIP:          "198.51.100.10",
			DstPort:        80,
			ObservedFact:   "Authorization header was observed over plaintext HTTP.",
			Inference:      "Credentials or authentication tokens may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine password strength.",
			Recommendation: "Use HTTPS.",
			Evidence:       "Authorization: Basic ***",
		},
	}
	flows := []FlowRecord{
		{
			Timestamp:           ts.Add(time.Minute),
			FlowKey:             "tcp|camera-http",
			SrcIP:               "192.168.1.20",
			SrcPort:             50000,
			DstIP:               "198.51.100.10",
			DstPort:             80,
			Protocol:            "http",
			AppProtocol:         "http",
			Host:                "api.camera.example",
			HTTPMethod:          "POST",
			HTTPPath:            "/login",
			Direction:           "external",
			ObservedDestination: "api.camera.example",
		},
		{
			Timestamp:           ts.Add(2 * time.Minute),
			FlowKey:             "tcp|camera-tls",
			SrcIP:               "192.168.1.20",
			SrcPort:             50001,
			DstIP:               "203.0.113.20",
			DstPort:             443,
			Protocol:            "tls",
			AppProtocol:         "https",
			SNI:                 "device-ea01.example",
			Direction:           "external",
			ObservedDestination: "device-ea01.example",
		},
	}
	observations := []ObservationRecord{
		{
			Timestamp:           ts.Add(3 * time.Minute),
			Kind:                "dns_query",
			SrcIP:               "192.168.1.20",
			DstIP:               "8.8.8.8",
			DstPort:             53,
			Protocol:            "udp",
			AppProtocol:         "dns",
			Direction:           "external",
			DNSQuery:            "ep.tange365.com",
			ObservedDestination: "ep.tange365.com",
		},
		{
			Timestamp: ts.Add(4 * time.Minute),
			Kind:      "udp_packet",
			SrcIP:     "192.168.1.20",
			DstIP:     "198.51.100.99",
			DstPort:   9001,
			Protocol:  "udp",
			Direction: "external",
		},
	}
	devices := []InventoryDevice{
		{
			IP:                 "192.168.1.20",
			CategoryCandidate:  "Camera",
			CategoryConfidence: "medium",
			VendorCandidate:    "iCam365",
			VendorConfidence:   "low",
		},
	}

	got := BuildDeviceEvidenceReport(events, flows, observations, devices)
	if got.Metrics.DeviceCount != 1 {
		t.Fatalf("DeviceCount=%d, want 1", got.Metrics.DeviceCount)
	}
	if got.Metrics.DevicesWithRisk != 1 {
		t.Fatalf("DevicesWithRisk=%d, want 1", got.Metrics.DevicesWithRisk)
	}
	device := got.Devices[0]
	if device.IP != "192.168.1.20" {
		t.Fatalf("IP=%q, want camera IP", device.IP)
	}
	if device.Category != "Camera" {
		t.Fatalf("Category=%q, want Camera", device.Category)
	}
	if !stringSliceContains(device.ObservedEvidence.DNSQueries, "ep.tange365.com") {
		t.Fatalf("DNSQueries=%v, want ep.tange365.com", device.ObservedEvidence.DNSQueries)
	}
	if !stringSliceContains(device.ObservedEvidence.TLSSNI, "device-ea01.example") {
		t.Fatalf("TLSSNI=%v, want device-ea01.example", device.ObservedEvidence.TLSSNI)
	}
	if !portSliceContains(device.ObservedEvidence.UnknownUDPPorts, 9001) {
		t.Fatalf("UnknownUDPPorts=%v, want 9001", device.ObservedEvidence.UnknownUDPPorts)
	}
	if len(device.RiskSignals) != 1 || device.RiskSignals[0].RuleID != "I7_HTTP_AUTH" {
		t.Fatalf("RiskSignals=%+v, want I7_HTTP_AUTH", device.RiskSignals)
	}
	if !findingKeyExists(device.PassiveBlindSpots, "encrypted_payload_not_visible") {
		t.Fatalf("PassiveBlindSpots=%+v, want encrypted blind spot", device.PassiveBlindSpots)
	}
	if !findingKeyExists(device.PassiveBlindSpots, "unknown_udp_purpose") {
		t.Fatalf("PassiveBlindSpots=%+v, want unknown UDP blind spot", device.PassiveBlindSpots)
	}
	if !findingKeyExists(device.DefenseCandidates, "restrict_plaintext_http") {
		t.Fatalf("DefenseCandidates=%+v, want plaintext HTTP candidate", device.DefenseCandidates)
	}
	if device.Judgment.State != "risky" {
		t.Fatalf("Judgment.State=%q, want risky: %+v", device.Judgment.State, device.Judgment)
	}
	if device.Judgment.EvidenceReadiness != "enough" {
		t.Fatalf("Judgment.EvidenceReadiness=%q, want enough", device.Judgment.EvidenceReadiness)
	}
	if !judgmentFindingKeyExists(device.Judgment.Findings, "plaintext_secret_or_auth") {
		t.Fatalf("Judgment.Findings=%+v, want plaintext_secret_or_auth", device.Judgment.Findings)
	}
	if !controlKeyExists(device.Judgment.RecommendedControls, "restrict_plaintext_http") {
		t.Fatalf("Judgment.RecommendedControls=%+v, want restrict_plaintext_http", device.Judgment.RecommendedControls)
	}
	if !deferredDecisionKeyExists(device.Judgment.DeferredDecisions, "defer_unknown_udp_block") {
		t.Fatalf("Judgment.DeferredDecisions=%+v, want defer_unknown_udp_block", device.Judgment.DeferredDecisions)
	}
}

func TestLoadDeviceEvidenceReportReadsFiles(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")
	observationsPath := filepath.Join(dir, "observations.jsonl")
	inventoryPath := filepath.Join(dir, "device_inventory.json")

	if err := os.WriteFile(eventsPath, []byte(`{"ts":"2026-09-26T12:00:00Z","rule_id":"I7_HTTP_PLAINTEXT","type":"INSECURE_HTTP","category":"I7","severity":"WARNING","confidence":"high","src_ip":"192.168.1.30","dst_ip":"198.51.100.1","dst_port":80}`+"\n"), 0644); err != nil {
		t.Fatalf("write events: %v", err)
	}
	if err := os.WriteFile(flowsPath, []byte(`{"ts":"2026-09-26T12:00:01Z","flow_key":"tcp|camera","src_ip":"192.168.1.30","src_port":50000,"dst_ip":"198.51.100.1","dst_port":80,"protocol":"http","app_protocol":"http","host":"api.example","direction":"external","observed_destination":"api.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write flows: %v", err)
	}
	if err := os.WriteFile(observationsPath, []byte(`{"ts":"2026-09-26T12:00:02Z","kind":"http_host","src_ip":"192.168.1.30","dst_ip":"198.51.100.1","dst_port":80,"protocol":"http","app_protocol":"http","host":"api.example","direction":"external","observed_destination":"api.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write observations: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(`{"devices":[{"ip":"192.168.1.30","category_candidate":"Camera","category_confidence":"medium"}]}`), 0644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	got, err := LoadDeviceEvidenceReport(eventsPath, flowsPath, observationsPath, inventoryPath)
	if err != nil {
		t.Fatalf("LoadDeviceEvidenceReport: %v", err)
	}
	if got.Source.Events != eventsPath || got.Source.Observations != observationsPath {
		t.Fatalf("unexpected source paths: %+v", got.Source)
	}
	if len(got.Devices) != 1 {
		t.Fatalf("Devices=%d, want 1", len(got.Devices))
	}
	if !findingKeyExists(got.Devices[0].DefenseCandidates, "restrict_plaintext_http") {
		t.Fatalf("DefenseCandidates=%+v, want plaintext HTTP candidate", got.Devices[0].DefenseCandidates)
	}
}

func findingKeyExists(items []EvidenceFinding, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func stringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func portSliceContains(items []uint16, value uint16) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func judgmentFindingKeyExists(items []JudgmentFinding, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func controlKeyExists(items []ControlRecommendation, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func deferredDecisionKeyExists(items []DeferredDecision, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}
