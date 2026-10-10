package reportapi

import (
	"strings"
	"testing"
)

func TestBuildQualityGateReportWarnsOnWeakClaims(t *testing.T) {
	gate := BuildQualityGateReport(QualityGateInputs{
		PrecisionEval:      &PrecisionEvaluationReport{Metrics: EvaluationMetrics{LabelCoverage: 0.5}},
		AttackEvidenceEval: &AttackEvidenceEvaluationReport{Metrics: AttackEvidenceEvaluationMetrics{LabelCoverage: 0}},
		MitigationEval: &MitigationEvaluationReport{Metrics: MitigationEvaluationMetrics{
			AttackEvidenceReductionRate:         0.5,
			AcceptedAttackEvidenceReductionRate: 0,
			ExposedServiceAttemptReductionRate:  0,
			IDSExposedOverlapReductionRate:      0,
			BeforeNormalFlowCount:               10,
			NormalFlowPreservationRate:          0.4,
		}},
		SourceCoverage: &SourceCoverageReport{Metrics: SourceCoverageMetrics{SourceCount: 1}},
	})
	if gate.OverallStatus != "fail" {
		t.Fatalf("OverallStatus=%q, want fail", gate.OverallStatus)
	}
	if !qualityGateHasCheck(gate.Checks, "normal_traffic_safety", "fail") {
		t.Fatalf("checks=%+v, want normal traffic safety fail", gate.Checks)
	}
	if !qualityGateHasAdjustment(gate.ClaimAdjustments, "mitigation reduced risk") {
		t.Fatalf("adjustments=%+v, want mitigation risk claim adjustment", gate.ClaimAdjustments)
	}
}

func TestApplyQualityGateToResearchReportAddsGuardrails(t *testing.T) {
	research := ResearchReport{ExecutiveSummary: "summary.", SupportedClaims: []string{"claim"}}
	gate := QualityGateReport{
		OverallStatus: "warn",
		Checks: []QualityGateCheck{
			{Key: "precision_label_coverage", Status: "warn", Summary: "low labels", Guardrail: "weaken precision claims"},
		},
		ClaimAdjustments: []QualityClaimAdjustment{
			{Claim: "incident precision", Disposition: "weaken", Reason: "low labels"},
		},
		RecommendedNextSteps: []string{"label more incidents"},
	}
	got := ApplyQualityGateToResearchReport(research, gate)
	if !qualityStringSliceContains(got.ThreatsToValidity, "weaken precision claims") {
		t.Fatalf("ThreatsToValidity=%+v, want guardrail", got.ThreatsToValidity)
	}
	if !strings.Contains(got.ExecutiveSummary, "Quality gate status: warn") {
		t.Fatalf("ExecutiveSummary=%q, want quality gate status", got.ExecutiveSummary)
	}
	if !qualityStringSliceContains(got.NextSteps, "label more incidents") {
		t.Fatalf("NextSteps=%+v, want gate next step", got.NextSteps)
	}
}

func qualityGateHasCheck(checks []QualityGateCheck, key, status string) bool {
	for _, check := range checks {
		if check.Key == key && check.Status == status {
			return true
		}
	}
	return false
}

func qualityGateHasAdjustment(items []QualityClaimAdjustment, claim string) bool {
	for _, item := range items {
		if item.Claim == claim {
			return true
		}
	}
	return false
}

func qualityStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
