package reportapi

import (
	"strings"
	"testing"
)

func TestBuildResearchReportSummarizesExperiment(t *testing.T) {
	precision := DetectionPrecisionReport{
		Metrics: PrecisionMetrics{
			IncidentCount:            2,
			RiskyIncidentCount:       1,
			SuspiciousIncidentCount:  1,
			SuppressedSignalCount:    3,
			BaselineReadyDeviceCount: 1,
		},
		PaperSummary: PrecisionPaperSummary{
			ResearchClaimsSupported: []string{"passive observations can be promoted into incidents"},
		},
	}
	precisionEval := &PrecisionEvaluationReport{
		Metrics: EvaluationMetrics{
			LabelCoverage:     1,
			Precision:         0.9,
			FalsePositiveRate: 0.1,
		},
	}
	mitigation := MitigationPlan{
		Metrics: MitigationMetrics{
			ActionCount:           1,
			ReviewRequiredCount:   1,
			EstimatedBlockedFlows: 3,
		},
		PaperSummary: MitigationPaperSummary{
			SupportedClaims:               []string{"historical flows estimate blocked communications"},
			NormalTrafficImpactMeasurable: true,
		},
		Actions: []MitigationAction{
			{
				ID:       "action-telnet",
				DeviceIP: "192.168.50.92",
				Kind:     "block_service",
				Status:   "review_required",
				RiskReductionTarget: MitigationRiskTarget{
					Exposure: "insecure remote management service",
				},
				Impact: MitigationImpact{
					EstimatedBlockedFlows: 3,
					NormalTrafficRisk:     "possible",
					BaselineImpact:        "blocks_non_baseline_observed_flows",
				},
			},
		},
	}
	mitigationEval := &MitigationEvaluationReport{
		OverallOutcome: "resolved",
		Metrics: MitigationEvaluationMetrics{
			EvaluableActionCount:        1,
			ImprovedActionCount:         1,
			ResolvedActionCount:         1,
			TargetedSignalReductionRate: 1,
			CriticalFlowContinuityRisk:  "low",
		},
		PaperSummary: MitigationEvalPaperSummary{
			SupportedClaims: []string{"before and after targeted signals can evaluate mitigation"},
		},
		PaperMetrics: MitigationEvaluationPaperMetrics{
			IncidentReductionRate:         0.5,
			HighRiskIncidentReductionRate: 1,
			NormalFlowPreservationRate:    1,
			CriticalFlowPreservationRate:  1,
			FalseMitigationRate:           0,
			ResidualRiskScore:             10,
		},
		ActionOutcomes: []MitigationActionEvaluation{
			{
				ActionID:              "action-telnet",
				DeviceIP:              "192.168.50.92",
				Kind:                  "block_service",
				BeforeTargetedSignals: 1,
				AfterTargetedSignals:  0,
				TargetedSignalDelta:   -1,
				Outcome:               "resolved",
			},
		},
		DeviceOutcomes: []MitigationDeviceEvaluation{
			{
				DeviceIP:             "192.168.50.92",
				BeforeCriticalFlows:  1,
				AfterCriticalFlows:   1,
				ContinuityAssessment: "maintained",
			},
		},
	}

	report := BuildResearchReport(precision, precisionEval, mitigation, mitigationEval)
	if report.Metrics.IncidentCount != 2 || report.Metrics.MitigationActionCount != 1 {
		t.Fatalf("Metrics=%+v, want precision and mitigation metrics", report.Metrics)
	}
	if report.Metrics.TargetedSignalReductionRate != 1 || report.Metrics.OverallOutcome != "resolved" {
		t.Fatalf("Metrics=%+v, want mitigation eval metrics", report.Metrics)
	}
	if report.Metrics.NormalFlowPreservationRate != 1 || report.Metrics.IncidentReductionRate != 0.5 {
		t.Fatalf("Metrics=%+v, want paper mitigation metrics", report.Metrics)
	}
	if len(report.Tables.MitigationSummary) != 1 || len(report.Tables.MitigationOutcomes) != 1 {
		t.Fatalf("Tables=%+v, want mitigation rows", report.Tables)
	}
	if !researchStringSliceContains(report.SupportedClaims, "before and after targeted signals can evaluate mitigation") {
		t.Fatalf("SupportedClaims=%+v, want mitigation eval claim", report.SupportedClaims)
	}
	if len(report.MissingEvidence) != 0 {
		t.Fatalf("MissingEvidence=%+v, want complete evidence", report.MissingEvidence)
	}
}

func TestResearchReportMarkdownIncludesTables(t *testing.T) {
	report := ResearchReport{
		ExecutiveSummary: "summary.",
		ResearchQuestion: "question?",
		Metrics: ResearchMetrics{
			IncidentCount:               1,
			MitigationActionCount:       1,
			EstimatedBlockedFlows:       2,
			TargetedSignalReductionRate: 1,
			NormalFlowPreservationRate:  1,
			CriticalFlowContinuityRisk:  "low",
			OverallOutcome:              "resolved",
		},
		ExperimentStages: []ResearchStage{{Name: "incident_generation", Status: "ready"}},
		Tables: ResearchTables{
			IncidentSummary:   []ResearchTableRow{{"metric": "incidents", "value": "1"}},
			MitigationSummary: []ResearchTableRow{{"action_id": "a1", "kind": "block_service"}},
		},
		SupportedClaims:   []string{"claim"},
		MissingEvidence:   []string{"gap"},
		ThreatsToValidity: []string{"threat"},
		NextSteps:         []string{"next"},
	}

	markdown := ResearchReportMarkdown(report)
	for _, want := range []string{
		"# Quarant Research Report",
		"## Key Metrics",
		"## Mitigation Summary",
		"block_service",
		"## Supported Claims",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown=%s, want %q", markdown, want)
		}
	}
}

func TestResearchReportCSVsIncludesPaperTables(t *testing.T) {
	report := ResearchReport{
		Metrics: ResearchMetrics{
			IncidentCount:               1,
			MitigationActionCount:       1,
			EstimatedBlockedFlows:       2,
			TargetedSignalReductionRate: 1,
			NormalFlowPreservationRate:  1,
			CriticalFlowContinuityRisk:  "low",
			OverallOutcome:              "resolved",
		},
		ExperimentStages: []ResearchStage{{Name: "incident_generation", Status: "ready", Evidence: []string{"1 incident"}}},
		Tables: ResearchTables{
			IncidentSummary:         []ResearchTableRow{{"metric": "incidents", "value": "1"}},
			MitigationSummary:       []ResearchTableRow{{"action_id": "a1", "kind": "block_service"}},
			MitigationOutcomes:      []ResearchTableRow{{"action_id": "a1", "outcome": "resolved"}},
			NormalTrafficContinuity: []ResearchTableRow{{"device_ip": "192.168.50.92", "continuity_assessment": "maintained"}},
		},
	}

	files := ResearchReportCSVs(report)
	for _, name := range []string{
		"metrics.csv",
		"incident_summary.csv",
		"mitigation_summary.csv",
		"mitigation_outcomes.csv",
		"normal_traffic_continuity.csv",
		"experiment_stages.csv",
	} {
		if strings.TrimSpace(files[name]) == "" {
			t.Fatalf("files=%+v, want %s", files, name)
		}
	}
	if !strings.Contains(files["metrics.csv"], "estimated_blocked_flows") {
		t.Fatalf("metrics.csv=%s, want estimated_blocked_flows", files["metrics.csv"])
	}
	if !strings.Contains(files["metrics.csv"], "normal_flow_preservation_rate") {
		t.Fatalf("metrics.csv=%s, want normal_flow_preservation_rate", files["metrics.csv"])
	}
	if !strings.Contains(files["mitigation_summary.csv"], "block_service") {
		t.Fatalf("mitigation_summary.csv=%s, want block_service", files["mitigation_summary.csv"])
	}
}

func researchStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
