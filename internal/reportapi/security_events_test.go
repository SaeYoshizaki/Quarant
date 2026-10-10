package reportapi

import (
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
	if report.Metrics.SecurityEventCount != 3 || report.Metrics.ScanCandidateCount != 1 {
		t.Fatalf("metrics=%+v, want one scan candidate from three security events", report.Metrics)
	}
	if len(report.Findings) != 1 || report.Findings[0].Kind != "port_scan" {
		t.Fatalf("findings=%+v, want port_scan", report.Findings)
	}
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
	if !hasPrecisionSignal(report.Incidents[0].Signals, "attack_evidence_inbound_scan") {
		t.Fatalf("signals=%+v, want attack_evidence_inbound_scan", report.Incidents[0].Signals)
	}
}
