package reportapi

import (
	"testing"
	"time"
)

func TestBuildTaxonomyCoverageReportGroupsBySourceEngineAndTaxonomy(t *testing.T) {
	ts := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	events := []SecurityEvent{
		{Timestamp: ts, Source: "openwrt_firewall", EventType: "firewall_dropped", Direction: "inbound", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 23, Protocol: "tcp", AttackTechnique: "tcp_syn_probe"},
		{Timestamp: ts, Source: "suricata", Engine: "suricata", EventType: "ids_alert", ClassType: "Attempted Administrator Privilege Gain", Signature: "ET EXPLOIT Web Probe", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 80, Protocol: "tcp"},
	}

	report := BuildTaxonomyCoverageReport(events, SecurityTaxonomyDecisionPolicy())
	if report.Metrics.SecurityEventCount != 2 || report.Metrics.ClassificationCoverage != 1 || report.Metrics.TaxonomyCount == 0 {
		t.Fatalf("metrics=%+v, want two classified events", report.Metrics)
	}
	if !taxonomyCoverageHasTerm(report, "sensitive_service_probe") || !taxonomyCoverageHasTerm(report, "exploit_attempt") {
		t.Fatalf("by_taxonomy=%+v, want sensitive_service_probe and exploit_attempt", report.ByTaxonomy)
	}
	if len(report.BySource) != 2 || len(report.ByEngine) != 2 {
		t.Fatalf("by_source=%+v by_engine=%+v, want source and engine breakdowns", report.BySource, report.ByEngine)
	}
}

func TestNormalizeSecurityEventWithCustomPolicy(t *testing.T) {
	policy := SecurityTaxonomyPolicy{
		Version: "test-policy",
		Taxonomies: []SecurityTaxonomyTerm{
			{Key: "vendor_camera_probe", MatchAny: []string{"vendor camera"}, NormalizedTechnique: "vendor_camera_probe"},
		},
	}
	event := NormalizeSecurityEventWithPolicy(SecurityEvent{
		Source:    "suricata",
		Engine:    "suricata",
		EventType: "ids_alert",
		Signature: "ET SCAN Vendor Camera Probe",
		SrcIP:     "203.0.113.9",
		DstIP:     "192.168.8.42",
		DeviceIP:  "192.168.8.42",
		DstPort:   80,
		Protocol:  "tcp",
	}, policy)
	if event.NormalizedTechnique != "vendor_camera_probe" || !securityEventHasTaxonomy(event, "vendor_camera_probe") {
		t.Fatalf("event=%+v, want custom taxonomy", event)
	}
}

func taxonomyCoverageHasTerm(report TaxonomyCoverageReport, taxonomy string) bool {
	for _, item := range report.ByTaxonomy {
		if item.Taxonomy == taxonomy {
			return true
		}
	}
	return false
}
