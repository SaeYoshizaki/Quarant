package reportapi

import (
	"strings"
	"testing"
	"time"
)

func TestBuildAttackEvidenceReportDetectsPortScan(t *testing.T) {
	ts := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	events := []SecurityEvent{
		{Timestamp: ts, Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 23, Protocol: "tcp"},
		{Timestamp: ts.Add(time.Second), Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 80, Protocol: "tcp"},
		{Timestamp: ts.Add(2 * time.Second), Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 8080, Protocol: "tcp"},
	}

	report := BuildAttackEvidenceReport(events)
	if report.Metrics.SecurityEventCount != 3 || report.Metrics.ObservedCount != 3 || report.Metrics.BlockedCount != 3 || report.Metrics.ScanCandidateCount != 1 || report.Metrics.SensitiveServiceProbeCount != 3 {
		t.Fatalf("metrics=%+v, want one scan candidate from three security events", report.Metrics)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "port_scan" {
		t.Fatalf("findings=%+v, want port_scan", report.Findings)
	}
}

func TestNormalizeSecurityEventMapsOpenWrtAndIDSTaxonomy(t *testing.T) {
	openwrt := NormalizeSecurityEvent(SecurityEvent{
		Source:          "openwrt_firewall",
		EventType:       "firewall_dropped",
		Verdict:         "dropped",
		Direction:       "inbound",
		SrcIP:           "203.0.113.9",
		DstIP:           "192.168.8.42",
		DeviceIP:        "192.168.8.42",
		DstPort:         23,
		Protocol:        "tcp",
		AttackTechnique: "tcp_fin_scan",
	})
	if openwrt.NormalizedTechnique != "suspicious_tcp_flags" || !securityEventHasTaxonomy(openwrt, "reconnaissance") || !securityEventHasTaxonomy(openwrt, "sensitive_service_probe") || !securityEventHasTaxonomy(openwrt, "suspicious_tcp_flags") {
		t.Fatalf("openwrt taxonomy=%+v normalized=%q, want reconnaissance/sensitive/suspicious", openwrt.Taxonomy, openwrt.NormalizedTechnique)
	}

	suricata := NormalizeSecurityEvent(SecurityEvent{
		Source:     "suricata",
		Engine:     "suricata",
		EventType:  "ids_alert",
		ClassType:  "Attempted Administrator Privilege Gain",
		Signature:  "ET EXPLOIT Example Web Command Injection",
		SrcIP:      "203.0.113.9",
		DstIP:      "192.168.8.42",
		DeviceIP:   "192.168.8.42",
		DstPort:    80,
		Protocol:   "tcp",
		Confidence: "medium",
	})
	if suricata.NormalizedTechnique != "exploit_attempt" || !securityEventHasTaxonomy(suricata, "ids_alert") || !securityEventHasTaxonomy(suricata, "exploit_attempt") {
		t.Fatalf("suricata taxonomy=%+v normalized=%q, want ids_alert/exploit_attempt", suricata.Taxonomy, suricata.NormalizedTechnique)
	}
}

func TestBuildAttackEvidenceReportIncludesTaxonomyCounts(t *testing.T) {
	ts := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	events := []SecurityEvent{
		{Timestamp: ts, Source: "suricata", Engine: "suricata", EventType: "ids_alert", ClassType: "A Network Trojan was detected", Signature: "ET TROJAN C2", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 4444, Protocol: "tcp"},
		{Timestamp: ts.Add(time.Second), Source: "suricata", Engine: "suricata", EventType: "ids_alert", ClassType: "A Network Trojan was detected", Signature: "ET TROJAN C2", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 4445, Protocol: "tcp"},
		{Timestamp: ts.Add(2 * time.Second), Source: "suricata", Engine: "suricata", EventType: "ids_alert", ClassType: "A Network Trojan was detected", Signature: "ET TROJAN C2", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 4446, Protocol: "tcp"},
	}

	report := BuildAttackEvidenceReport(events)
	if !securityEventKVContains(report.Metrics.TaxonomyCounts, "malware_or_c2") || len(report.Findings) != 1 || !securityEventStringSliceContains(report.Findings[0].Taxonomy, "malware_or_c2") {
		t.Fatalf("taxonomy_counts=%+v findings=%+v, want malware_or_c2 propagated", report.Metrics.TaxonomyCounts, report.Findings)
	}
	if report.TaxonomyPolicy.Version != "quarant-security-taxonomy-v1" {
		t.Fatalf("taxonomy policy version=%q", report.TaxonomyPolicy.Version)
	}
}

func securityEventHasTaxonomy(event SecurityEvent, taxonomy string) bool {
	return securityEventStringSliceContains(event.Taxonomy, taxonomy)
}

func securityEventStringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if strings.EqualFold(value, want) {
			return true
		}
	}
	return false
}

func securityEventKVContains(values []KV, want string) bool {
	for _, value := range values {
		if value.Key == want {
			return true
		}
	}
	return false
}

func TestPrecisionReportUsesSecurityEventsAsAttackEvidence(t *testing.T) {
	ts := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	securityEvents := []SecurityEvent{
		{Timestamp: ts, Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 23, Protocol: "tcp", AttackTechnique: "tcp_syn_probe"},
		{Timestamp: ts.Add(time.Second), Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 80, Protocol: "tcp", AttackTechnique: "tcp_syn_probe"},
		{Timestamp: ts.Add(2 * time.Second), Source: "openwrt_firewall", EventType: "firewall_dropped", Action: "DROP", Verdict: "dropped", SrcIP: "203.0.113.9", DstIP: "192.168.8.42", DeviceIP: "192.168.8.42", DstPort: 8080, Protocol: "tcp", AttackTechnique: "tcp_syn_probe"},
	}

	report := BuildDetectionPrecisionReportWithSecurityEvents(nil, securityEvents, nil, nil, nil)
	if report.Metrics.IncidentCount != 1 || report.Metrics.AttackLikeIncidentCount != 1 {
		t.Fatalf("metrics=%+v incidents=%+v, want attack-like incident", report.Metrics, report.Incidents)
	}
	if !hasPrecisionSignal(report.Incidents[0].Signals, "attack_evidence_port_scan") || !hasPrecisionSignal(report.Incidents[0].Signals, "attack_evidence_sensitive_service_probe") {
		t.Fatalf("signals=%+v, want port scan and sensitive service probe evidence", report.Incidents[0].Signals)
	}
}
