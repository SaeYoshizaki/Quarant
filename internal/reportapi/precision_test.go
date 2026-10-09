package reportapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildDetectionPrecisionReportSuppressesDNSOnlyAndPromotesRisk(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{
			Timestamp:    ts.Add(4 * time.Minute),
			Type:         "INSECURE_HTTP_AUTH",
			RuleID:       "I7_HTTP_AUTH",
			Category:     "I7",
			Severity:     "CRITICAL",
			Confidence:   "high",
			SrcIP:        "192.168.50.20",
			DstIP:        "198.51.100.10",
			DstPort:      80,
			ObservedFact: "Authorization header was observed over plaintext HTTP.",
			Evidence:     "Authorization: Basic ***",
		},
	}
	flows := []FlowRecord{
		{
			Timestamp:           ts,
			FlowKey:             "tcp|learned",
			SrcIP:               "192.168.50.20",
			DstIP:               "198.51.100.10",
			DstPort:             443,
			Protocol:            "tcp",
			AppProtocol:         "tls",
			Direction:           "external",
			ObservedDestination: "api.camera.example",
		},
		{
			Timestamp:           ts.Add(6 * time.Minute),
			FlowKey:             "tcp|novel-http",
			SrcIP:               "192.168.50.20",
			DstIP:               "203.0.113.20",
			DstPort:             80,
			Protocol:            "tcp",
			AppProtocol:         "http",
			Direction:           "external",
			ObservedDestination: "new-upload.example",
		},
	}
	observations := []ObservationRecord{
		{
			Timestamp:           ts.Add(time.Minute),
			Kind:                "dns_query",
			SrcIP:               "192.168.50.30",
			DstPort:             53,
			Protocol:            "udp",
			AppProtocol:         "dns",
			Direction:           "external",
			DNSQuery:            "pool.ntp.org",
			ObservedDestination: "pool.ntp.org",
		},
	}
	devices := []InventoryDevice{
		{IP: "192.168.50.20", CategoryCandidate: "Camera", FamilyCandidate: "camera-01"},
		{IP: "192.168.50.30", CategoryCandidate: "Sensor", FamilyCandidate: "sensor-01"},
	}

	got := BuildDetectionPrecisionReport(events, flows, observations, devices)
	if got.Metrics.RiskyIncidentCount != 1 {
		t.Fatalf("RiskyIncidentCount=%d, want 1: %+v", got.Metrics.RiskyIncidentCount, got.Incidents)
	}
	if got.Metrics.IncidentCount != 1 {
		t.Fatalf("IncidentCount=%d, want 1", got.Metrics.IncidentCount)
	}
	incident := got.Incidents[0]
	if incident.DeviceIP != "192.168.50.20" || incident.State != "risky" {
		t.Fatalf("incident=%+v, want risky camera incident", incident)
	}
	if incident.PrimaryTaxonomy != "credential_exposure" {
		t.Fatalf("PrimaryTaxonomy=%q, want credential_exposure", incident.PrimaryTaxonomy)
	}
	if incident.ScoreBand == "" {
		t.Fatalf("ScoreBand empty for incident=%+v", incident)
	}
	if incident.Decision.StateReason == "" || incident.Decision.ConfidenceReason == "" {
		t.Fatalf("Decision=%+v, want decision reasons", incident.Decision)
	}
	if !precisionSignalExists(incident.Signals, "event_i7_http_auth") {
		t.Fatalf("signals=%+v, want event_i7_http_auth", incident.Signals)
	}
	if !precisionSignalTaxonomyExists(incident.Signals, "credential_exposure") {
		t.Fatalf("signals=%+v, want credential_exposure taxonomy", incident.Signals)
	}
	if !precisionSignalExists(incident.Signals, "correlation_observation_context") {
		t.Fatalf("signals=%+v, want correlation_observation_context", incident.Signals)
	}
	if len(got.DecisionPolicy.SignalTaxonomy) == 0 || len(got.DecisionPolicy.SuppressionPolicy) == 0 {
		t.Fatalf("DecisionPolicy=%+v, want taxonomy and suppression policy", got.DecisionPolicy)
	}
	if len(got.DecisionBreakdown.ByTaxonomy) == 0 || len(got.ScoreDistribution) == 0 {
		t.Fatalf("DecisionBreakdown=%+v ScoreDistribution=%+v, want research breakdowns", got.DecisionBreakdown, got.ScoreDistribution)
	}
	if got.EvaluationReadiness.RequiredLabelCount != len(got.Incidents) {
		t.Fatalf("EvaluationReadiness=%+v, want required labels for every incident", got.EvaluationReadiness)
	}
	if got.PaperSummary.IncidentCount != got.Metrics.IncidentCount || len(got.PaperSummary.ResearchClaimsSupported) == 0 {
		t.Fatalf("PaperSummary=%+v, want metrics and claims", got.PaperSummary)
	}
	if got.Layers.Observation.SignalCount == 0 || got.Layers.Correlation.SignalCount == 0 {
		t.Fatalf("Layers=%+v, want observation and correlation counts", got.Layers)
	}
	if !suppressedSignalExists(got.SuppressedSignals, "dns_only") {
		t.Fatalf("SuppressedSignals=%+v, want dns_only", got.SuppressedSignals)
	}
}

func TestBuildDetectionPrecisionReportCorrelatesUnknownUDPAndNovelty(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	flows := []FlowRecord{
		{
			Timestamp:           ts,
			FlowKey:             "udp|learned",
			SrcIP:               "192.168.50.40",
			DstIP:               "198.51.100.1",
			DstPort:             443,
			Protocol:            "udp",
			AppProtocol:         "tls",
			Direction:           "external",
			ObservedDestination: "known.example",
		},
		{
			Timestamp:           ts.Add(6 * time.Minute),
			FlowKey:             "udp|novel",
			SrcIP:               "192.168.50.40",
			DstIP:               "203.0.113.77",
			DstPort:             9001,
			Protocol:            "udp",
			Direction:           "external",
			ObservedDestination: "203.0.113.77",
		},
	}
	observations := []ObservationRecord{
		{
			Timestamp: ts.Add(6 * time.Minute),
			Kind:      "udp_packet",
			SrcIP:     "192.168.50.40",
			DstIP:     "203.0.113.77",
			DstPort:   9001,
			Protocol:  "udp",
			Direction: "external",
		},
	}
	devices := []InventoryDevice{{IP: "192.168.50.40", CategoryCandidate: "Sensor"}}

	got := BuildDetectionPrecisionReport(nil, flows, observations, devices)
	if got.Metrics.SuspiciousIncidentCount != 1 {
		t.Fatalf("SuspiciousIncidentCount=%d, want 1: %+v", got.Metrics.SuspiciousIncidentCount, got.Incidents)
	}
	incident := got.Incidents[0]
	if !precisionSignalExists(incident.Signals, "unknown_udp") {
		t.Fatalf("signals=%+v, want unknown_udp", incident.Signals)
	}
	if !precisionSignalExists(incident.Signals, "baseline_novelty") {
		t.Fatalf("signals=%+v, want baseline_novelty", incident.Signals)
	}
	if !precisionSignalExists(incident.Signals, "correlation_multi_context") {
		t.Fatalf("signals=%+v, want correlation_multi_context", incident.Signals)
	}
	if got.Layers.Context.SignalCount == 0 || got.Layers.Correlation.SignalCount == 0 {
		t.Fatalf("Layers=%+v, want context and correlation counts", got.Layers)
	}
}

func TestBuildDetectionPrecisionReportStabilizesIncidentIDAcrossEvidenceDetails(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	baseEvent := Event{
		Timestamp:  ts,
		Type:       "INSECURE_HTTP_TOKEN",
		RuleID:     "I7_HTTP_TOKEN",
		Category:   "I7",
		Severity:   "CRITICAL",
		Confidence: "high",
		SrcIP:      "192.168.50.20",
		DstIP:      "198.51.100.10",
		DstPort:    80,
		Evidence:   "token=redacted-a",
	}
	flows := []FlowRecord{
		{Timestamp: ts, FlowKey: "tcp|token", SrcIP: "192.168.50.20", DstIP: "198.51.100.10", DstPort: 80, Protocol: "tcp", AppProtocol: "http", Direction: "external", ObservedDestination: "api.example"},
	}
	devices := []InventoryDevice{{IP: "192.168.50.20", CategoryCandidate: "Camera"}}

	first := BuildDetectionPrecisionReport([]Event{baseEvent}, flows, nil, devices)
	baseEvent.Timestamp = ts.Add(5 * time.Minute)
	baseEvent.Evidence = "token=redacted-b"
	second := BuildDetectionPrecisionReport([]Event{baseEvent}, flows, nil, devices)

	if len(first.Incidents) != 1 || len(second.Incidents) != 1 {
		t.Fatalf("incident counts first=%d second=%d, want 1 each", len(first.Incidents), len(second.Incidents))
	}
	if first.Incidents[0].ID != second.Incidents[0].ID {
		t.Fatalf("IDs differ: %s != %s", first.Incidents[0].ID, second.Incidents[0].ID)
	}
}

func TestBuildDetectionPrecisionReportSuppressesSingleUnknownUDP(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	observations := []ObservationRecord{
		{
			Timestamp: ts,
			Kind:      "udp_packet",
			SrcIP:     "192.168.50.55",
			DstIP:     "203.0.113.55",
			DstPort:   9999,
			Protocol:  "udp",
			Direction: "external",
		},
	}
	devices := []InventoryDevice{{IP: "192.168.50.55", CategoryCandidate: "Sensor"}}

	got := BuildDetectionPrecisionReport(nil, nil, observations, devices)
	if got.Metrics.IncidentCount != 0 {
		t.Fatalf("IncidentCount=%d, want 0: %+v", got.Metrics.IncidentCount, got.Incidents)
	}
	if !suppressedSignalExists(got.SuppressedSignals, "single_unknown_udp") {
		t.Fatalf("SuppressedSignals=%+v, want single_unknown_udp", got.SuppressedSignals)
	}
}

func TestBuildDetectionPrecisionReportSuppressesWeakPlaintextOnlyIncident(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	events := []Event{
		{
			Timestamp:    ts,
			Type:         "I7_HTTP_PLAINTEXT",
			RuleID:       "I7_HTTP_PLAINTEXT",
			Category:     "I7",
			Severity:     "WARNING",
			Confidence:   "medium",
			SrcIP:        "192.168.50.60",
			DstIP:        "198.51.100.60",
			DstPort:      80,
			ObservedFact: "Plaintext HTTP traffic was observed.",
		},
	}
	devices := []InventoryDevice{{IP: "192.168.50.60", CategoryCandidate: "Camera"}}

	got := BuildDetectionPrecisionReport(events, nil, nil, devices)
	if got.Metrics.IncidentCount != 0 {
		t.Fatalf("IncidentCount=%d, want 0: %+v", got.Metrics.IncidentCount, got.Incidents)
	}
	if !suppressedSignalExists(got.SuppressedSignals, "weak_plaintext_only") {
		t.Fatalf("SuppressedSignals=%+v, want weak_plaintext_only", got.SuppressedSignals)
	}
	if got.SuppressionBreakdown.TotalSuppressed == 0 {
		t.Fatalf("SuppressionBreakdown=%+v, want suppressed total", got.SuppressionBreakdown)
	}
	if !suppressionBreakdownExists(got.SuppressionBreakdown.ByReason, "weak_plaintext_only", "observation") {
		t.Fatalf("SuppressionBreakdown=%+v, want weak_plaintext_only observation breakdown", got.SuppressionBreakdown)
	}
}

func TestBuildDetectionPrecisionReportScorePolicyPromotesCorrelationToSuspicious(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	flows := []FlowRecord{
		{
			Timestamp:           ts,
			FlowKey:             "tcp|learned",
			SrcIP:               "192.168.50.70",
			DstIP:               "198.51.100.70",
			DstPort:             443,
			Protocol:            "tcp",
			AppProtocol:         "tls",
			Direction:           "external",
			ObservedDestination: "known.example",
		},
		{
			Timestamp:           ts.Add(6 * time.Minute),
			FlowKey:             "udp|novel",
			SrcIP:               "192.168.50.70",
			DstIP:               "203.0.113.70",
			DstPort:             9001,
			Protocol:            "udp",
			Direction:           "external",
			ObservedDestination: "203.0.113.70",
		},
	}
	observations := []ObservationRecord{
		{Timestamp: ts.Add(6 * time.Minute), Kind: "udp_packet", SrcIP: "192.168.50.70", DstIP: "203.0.113.70", DstPort: 9001, Protocol: "udp", Direction: "external"},
	}
	devices := []InventoryDevice{{IP: "192.168.50.70", CategoryCandidate: "Sensor"}}

	got := BuildDetectionPrecisionReport(nil, flows, observations, devices)
	if got.Metrics.SuspiciousIncidentCount != 1 {
		t.Fatalf("SuspiciousIncidentCount=%d, want 1: %+v", got.Metrics.SuspiciousIncidentCount, got.Incidents)
	}
	incident := got.Incidents[0]
	if incident.State != "suspicious" || incident.Severity != "MEDIUM" || incident.Confidence != "high" {
		t.Fatalf("incident=%+v, want suspicious MEDIUM high", incident)
	}
	if !precisionTaxonomyExists(incident.Taxonomies, "correlation") {
		t.Fatalf("Taxonomies=%+v, want correlation", incident.Taxonomies)
	}
}

func TestLoadDetectionPrecisionReportReadsFiles(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")
	observationsPath := filepath.Join(dir, "observations.jsonl")
	inventoryPath := filepath.Join(dir, "device_inventory.json")

	if err := os.WriteFile(eventsPath, []byte(`{"ts":"2026-09-27T10:00:00Z","rule_id":"I7_HTTP_TOKEN","type":"INSECURE_HTTP_TOKEN","category":"I7","severity":"CRITICAL","confidence":"high","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80}`+"\n"), 0644); err != nil {
		t.Fatalf("write events: %v", err)
	}
	if err := os.WriteFile(flowsPath, []byte(`{"ts":"2026-09-27T10:00:00Z","flow_key":"tcp|token","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write flows: %v", err)
	}
	if err := os.WriteFile(observationsPath, []byte(`{"ts":"2026-09-27T10:00:00Z","kind":"http_request","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write observations: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(`{"devices":[{"ip":"192.168.50.20","category_candidate":"Camera"}]}`), 0644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	got, err := LoadDetectionPrecisionReport(eventsPath, flowsPath, observationsPath, inventoryPath)
	if err != nil {
		t.Fatalf("LoadDetectionPrecisionReport: %v", err)
	}
	if got.Source.Events != eventsPath || got.Metrics.RiskyIncidentCount != 1 {
		t.Fatalf("got=%+v, want source and risky incident", got)
	}
}

func precisionSignalExists(items []PrecisionSignal, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func precisionSignalTaxonomyExists(items []PrecisionSignal, taxonomy string) bool {
	for _, item := range items {
		if item.Taxonomy == taxonomy {
			return true
		}
	}
	return false
}

func suppressedSignalExists(items []SuppressedSignalSummary, key string) bool {
	for _, item := range items {
		if item.Key == key {
			return true
		}
	}
	return false
}

func precisionTaxonomyExists(items []string, key string) bool {
	for _, item := range items {
		if item == key {
			return true
		}
	}
	return false
}

func suppressionBreakdownExists(items []SuppressionBreakdown, key, layer string) bool {
	for _, item := range items {
		if item.Key == key && item.Layer == layer {
			return true
		}
	}
	return false
}
