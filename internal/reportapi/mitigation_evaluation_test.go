package reportapi

import (
	"testing"
	"time"
)

func TestBuildMitigationEvaluationReportResolvesTargetedSignals(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	before := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:         "incident-before",
				State:      "risky",
				Score:      76,
				Confidence: "high",
				DeviceIP:   "192.168.50.92",
				Signals: []PrecisionSignal{
					{Key: "event_i2_telnet_service_observed", Taxonomy: "insecure_service", Weight: 35},
				},
			},
		},
	}
	after := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:         "incident-after-low",
				State:      "observe",
				Score:      14,
				Confidence: "low",
				DeviceIP:   "192.168.50.92",
				Signals: []PrecisionSignal{
					{Key: "baseline_novelty", Taxonomy: "baseline_novelty", Weight: 14},
				},
			},
		},
	}
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:         "action-telnet",
				IncidentID: "incident-before",
				DeviceIP:   "192.168.50.92",
				Kind:       "block_service",
				Status:     "review_required",
				RiskReductionTarget: MitigationRiskTarget{
					Taxonomy:   "insecure_service",
					SignalKeys: []string{"event_i2_telnet_service_observed"},
				},
				Impact: MitigationImpact{
					EstimatedBlockedFlows: 3,
					NormalTrafficRisk:     "possible",
				},
			},
		},
	}
	beforeFlows := []FlowRecord{
		{Timestamp: ts, SrcIP: "192.168.50.92", DstIP: "203.0.113.23", DstPort: 23, Protocol: "tcp", AppProtocol: "telnet", Direction: "external"},
		{Timestamp: ts, SrcIP: "192.168.50.92", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local"},
	}
	afterFlows := []FlowRecord{
		{Timestamp: ts.Add(time.Hour), SrcIP: "192.168.50.92", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local"},
	}

	report := BuildMitigationEvaluationReport(plan, before, after, beforeFlows, afterFlows)
	if report.OverallOutcome != "resolved" {
		t.Fatalf("OverallOutcome=%q, want resolved: %+v", report.OverallOutcome, report.Metrics)
	}
	if report.Metrics.ResolvedActionCount != 1 || report.Metrics.ImprovedActionCount != 1 {
		t.Fatalf("Metrics=%+v, want one resolved improved action", report.Metrics)
	}
	if report.Metrics.TargetedSignalReductionRate != 1 {
		t.Fatalf("TargetedSignalReductionRate=%f, want 1", report.Metrics.TargetedSignalReductionRate)
	}
	if report.Metrics.CriticalFlowContinuityRisk != "low" {
		t.Fatalf("CriticalFlowContinuityRisk=%q, want low", report.Metrics.CriticalFlowContinuityRisk)
	}
	if len(report.ActionOutcomes) != 1 || report.ActionOutcomes[0].Outcome != "resolved" {
		t.Fatalf("ActionOutcomes=%+v, want resolved action", report.ActionOutcomes)
	}
	if report.ActionOutcomes[0].TargetedSignalDelta != -1 {
		t.Fatalf("TargetedSignalDelta=%d, want -1", report.ActionOutcomes[0].TargetedSignalDelta)
	}
}

func TestBuildMitigationEvaluationReportFlagsContinuityRisk(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	before := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:       "incident-before",
				State:    "risky",
				Score:    70,
				DeviceIP: "192.168.50.93",
				Signals:  []PrecisionSignal{{Key: "event_i2_telnet_service_observed", Taxonomy: "insecure_service"}},
			},
		},
	}
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:       "action-telnet",
				DeviceIP: "192.168.50.93",
				Kind:     "block_service",
				RiskReductionTarget: MitigationRiskTarget{
					Taxonomy:   "insecure_service",
					SignalKeys: []string{"event_i2_telnet_service_observed"},
				},
			},
		},
	}
	beforeFlows := []FlowRecord{
		{Timestamp: ts, SrcIP: "192.168.50.93", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local"},
	}

	report := BuildMitigationEvaluationReport(plan, before, DetectionPrecisionReport{}, beforeFlows, nil)
	if report.OverallOutcome != "mixed_or_regressed" {
		t.Fatalf("OverallOutcome=%q, want continuity-risk mixed/regressed", report.OverallOutcome)
	}
	if report.Metrics.CriticalFlowContinuityRisk != "high" {
		t.Fatalf("CriticalFlowContinuityRisk=%q, want high", report.Metrics.CriticalFlowContinuityRisk)
	}
	if report.ActionOutcomes[0].Outcome != "resolved_with_continuity_risk" {
		t.Fatalf("ActionOutcomes=%+v, want resolved with continuity risk", report.ActionOutcomes)
	}
}

func TestBuildMitigationEvaluationReportConnectsApplyReportAndPaperMetrics(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	before := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:       "incident-before",
				State:    "risky",
				Severity: "HIGH",
				Score:    80,
				DeviceIP: "192.168.50.94",
				Signals:  []PrecisionSignal{{Key: "event_i2_telnet_service_observed", Taxonomy: "insecure_service"}},
			},
		},
	}
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:       "action-telnet",
				DeviceIP: "192.168.50.94",
				Kind:     "block_service",
				RiskReductionTarget: MitigationRiskTarget{
					Taxonomy:   "insecure_service",
					SignalKeys: []string{"event_i2_telnet_service_observed"},
				},
				FirewallRules: []MitigationRule{
					{ID: "rule-telnet", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.94", Protocol: "tcp", DstPort: 23, DstZone: "wan"},
				},
				Impact: MitigationImpact{EstimatedBlockedFlows: 1},
			},
		},
	}
	applyReport := MitigationApplyReport{
		Status:        "apply_script_generated",
		Mode:          "apply_script_generated",
		ExplicitApply: true,
		DryRun:        false,
		RollbackPath:  "openwrt_mitigation_rollback.sh",
		Metrics:       MitigationApplyMetrics{PartialApplyDetection: true},
		ManagedRules:  []MitigationManagedRule{{ID: "rule-telnet"}},
	}
	beforeFlows := []FlowRecord{
		{Timestamp: ts, SrcIP: "192.168.50.94", DstIP: "203.0.113.23", DstPort: 23, Protocol: "tcp", AppProtocol: "telnet", Direction: "external"},
		{Timestamp: ts, SrcIP: "192.168.50.94", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local"},
		{Timestamp: ts, SrcIP: "192.168.50.94", DstIP: "198.51.100.5", DstPort: 443, Protocol: "tcp", AppProtocol: "https", Direction: "external"},
	}

	report := BuildMitigationEvaluationReportWithApply(plan, &applyReport, before, DetectionPrecisionReport{}, beforeFlows, nil)
	if report.OverallOutcome != "rollback_recommended" {
		t.Fatalf("OverallOutcome=%q, want rollback_recommended", report.OverallOutcome)
	}
	if report.ApplySummary == nil || !report.ApplySummary.ExplicitApply || !report.ApplySummary.PartialApplyDetection {
		t.Fatalf("ApplySummary=%+v, want explicit apply summary", report.ApplySummary)
	}
	if report.Metrics.RollbackRequiredCount != 1 || report.Metrics.FalseMitigationCount != 1 {
		t.Fatalf("Metrics=%+v, want rollback and false mitigation counts", report.Metrics)
	}
	if report.PaperMetrics.IncidentReductionRate != 1 || report.PaperMetrics.HighRiskIncidentReductionRate != 1 {
		t.Fatalf("PaperMetrics=%+v, want incident reduction rates", report.PaperMetrics)
	}
	if report.PaperMetrics.NormalFlowPreservationRate != 0 || report.PaperMetrics.ApplyWasBlocked {
		t.Fatalf("PaperMetrics=%+v, want normal-flow loss and non-blocked apply", report.PaperMetrics)
	}
}

func TestMitigationEvaluationCountsIDSExposedOverlap(t *testing.T) {
	beforeSecurityEvents := []SecurityEvent{
		{Source: "openwrt_firewall", EventType: "firewall_accepted", Verdict: "accepted", Direction: "inbound", SrcIP: "203.0.113.9", DstIP: "192.168.50.20", DeviceIP: "192.168.50.20", DstPort: 80, Protocol: "tcp"},
		{Source: "suricata", Engine: "suricata", EventType: "ids_alert", Direction: "inbound", SrcIP: "203.0.113.9", DstIP: "192.168.50.20", DeviceIP: "192.168.50.20", DstPort: 80, Protocol: "tcp", Signature: "ET WEB Probe"},
	}
	afterSecurityEvents := []SecurityEvent{
		{Source: "openwrt_firewall", EventType: "firewall_dropped", Verdict: "dropped", Direction: "inbound", SrcIP: "203.0.113.9", DstIP: "192.168.50.20", DeviceIP: "192.168.50.20", DstPort: 80, Protocol: "tcp"},
		{Source: "suricata", Engine: "suricata", EventType: "ids_alert", Direction: "inbound", SrcIP: "203.0.113.9", DstIP: "192.168.50.20", DeviceIP: "192.168.50.20", DstPort: 80, Protocol: "tcp", Signature: "ET WEB Probe"},
	}
	report := BuildMitigationEvaluationReportWithApplyAndSecurityEvents(
		MitigationPlan{},
		nil,
		DetectionPrecisionReport{},
		DetectionPrecisionReport{},
		nil,
		nil,
		beforeSecurityEvents,
		afterSecurityEvents,
	)
	if report.Metrics.BeforeIDSAlertCount != 1 || report.Metrics.AfterIDSAlertCount != 1 {
		t.Fatalf("metrics=%+v, want IDS alert counts", report.Metrics)
	}
	if report.Metrics.BeforeIDSExposedOverlapCount != 1 || report.Metrics.AfterIDSExposedOverlapCount != 0 || report.Metrics.IDSExposedOverlapReductionRate != 1 {
		t.Fatalf("metrics=%+v, want IDS/exposed overlap reduction", report.Metrics)
	}
}
