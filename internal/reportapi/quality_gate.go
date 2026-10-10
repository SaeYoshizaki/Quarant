package reportapi

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type QualityGateReport struct {
	GeneratedAt          string                   `json:"generated_at"`
	Version              string                   `json:"version"`
	OverallStatus        string                   `json:"overall_status"`
	Source               QualityGateSources       `json:"source"`
	Metrics              QualityGateMetrics       `json:"metrics"`
	Checks               []QualityGateCheck       `json:"checks"`
	ClaimAdjustments     []QualityClaimAdjustment `json:"claim_adjustments"`
	RecommendedNextSteps []string                 `json:"recommended_next_steps"`
}

type QualityGateSources struct {
	PrecisionEvalReport      string `json:"precision_eval_report,omitempty"`
	AttackEvidenceEvalReport string `json:"attack_evidence_eval_report,omitempty"`
	MitigationEvalReport     string `json:"mitigation_eval_report,omitempty"`
	SourceCoverageReport     string `json:"source_coverage_report,omitempty"`
	ResearchReport           string `json:"research_report,omitempty"`
}

type QualityGateMetrics struct {
	PrecisionLabelCoverage         float64 `json:"precision_label_coverage,omitempty"`
	AttackEvidenceLabelCoverage    float64 `json:"attack_evidence_label_coverage,omitempty"`
	AcceptedEvidenceReductionRate  float64 `json:"accepted_attack_evidence_reduction_rate,omitempty"`
	ExposedServiceReductionRate    float64 `json:"exposed_service_attempt_reduction_rate,omitempty"`
	IDSExposedOverlapReductionRate float64 `json:"ids_exposed_overlap_reduction_rate,omitempty"`
	NormalFlowPreservationRate     float64 `json:"normal_flow_preservation_rate,omitempty"`
	SourceCount                    int     `json:"source_count,omitempty"`
	MultiSourceServiceCount        int     `json:"multi_source_service_count,omitempty"`
}

type QualityGateCheck struct {
	Key       string `json:"key"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Summary   string `json:"summary"`
	Guardrail string `json:"guardrail,omitempty"`
}

type QualityClaimAdjustment struct {
	Claim       string `json:"claim"`
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
}

type QualityGateInputs struct {
	PrecisionEval      *PrecisionEvaluationReport
	AttackEvidenceEval *AttackEvidenceEvaluationReport
	MitigationEval     *MitigationEvaluationReport
	SourceCoverage     *SourceCoverageReport
	ResearchReport     *ResearchReport
	Source             QualityGateSources
}

func LoadQualityGateReport(sources QualityGateSources) (QualityGateReport, error) {
	inputs := QualityGateInputs{Source: sources}
	if strings.TrimSpace(sources.PrecisionEvalReport) != "" {
		var report PrecisionEvaluationReport
		if ok, err := readOptionalJSONFile(sources.PrecisionEvalReport, &report); err != nil {
			return QualityGateReport{}, err
		} else if ok {
			inputs.PrecisionEval = &report
		}
	}
	if strings.TrimSpace(sources.AttackEvidenceEvalReport) != "" {
		var report AttackEvidenceEvaluationReport
		if ok, err := readOptionalJSONFile(sources.AttackEvidenceEvalReport, &report); err != nil {
			return QualityGateReport{}, err
		} else if ok {
			inputs.AttackEvidenceEval = &report
		}
	}
	if strings.TrimSpace(sources.MitigationEvalReport) != "" {
		var report MitigationEvaluationReport
		if ok, err := readOptionalJSONFile(sources.MitigationEvalReport, &report); err != nil {
			return QualityGateReport{}, err
		} else if ok {
			inputs.MitigationEval = &report
		}
	}
	if strings.TrimSpace(sources.SourceCoverageReport) != "" {
		var report SourceCoverageReport
		if ok, err := readOptionalJSONFile(sources.SourceCoverageReport, &report); err != nil {
			return QualityGateReport{}, err
		} else if ok {
			inputs.SourceCoverage = &report
		}
	}
	if strings.TrimSpace(sources.ResearchReport) != "" {
		var report ResearchReport
		if ok, err := readOptionalJSONFile(sources.ResearchReport, &report); err != nil {
			return QualityGateReport{}, err
		} else if ok {
			inputs.ResearchReport = &report
		}
	}
	return BuildQualityGateReport(inputs), nil
}

func BuildQualityGateReport(inputs QualityGateInputs) QualityGateReport {
	report := QualityGateReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "quality-gate-v1",
		Source:      inputs.Source,
	}
	if inputs.PrecisionEval != nil {
		report.Metrics.PrecisionLabelCoverage = inputs.PrecisionEval.Metrics.LabelCoverage
	}
	if inputs.AttackEvidenceEval != nil {
		report.Metrics.AttackEvidenceLabelCoverage = inputs.AttackEvidenceEval.Metrics.LabelCoverage
	}
	if inputs.MitigationEval != nil {
		report.Metrics.AcceptedEvidenceReductionRate = inputs.MitigationEval.Metrics.AcceptedAttackEvidenceReductionRate
		report.Metrics.ExposedServiceReductionRate = inputs.MitigationEval.Metrics.ExposedServiceAttemptReductionRate
		report.Metrics.IDSExposedOverlapReductionRate = inputs.MitigationEval.Metrics.IDSExposedOverlapReductionRate
		report.Metrics.NormalFlowPreservationRate = inputs.MitigationEval.Metrics.NormalFlowPreservationRate
	}
	if inputs.SourceCoverage != nil {
		report.Metrics.SourceCount = inputs.SourceCoverage.Metrics.SourceCount
		report.Metrics.MultiSourceServiceCount = inputs.SourceCoverage.Metrics.MultiSourceServiceCount
	}
	report.Checks = append(report.Checks, qualityPrecisionCoverageCheck(inputs.PrecisionEval))
	report.Checks = append(report.Checks, qualityAttackEvidenceCoverageCheck(inputs.AttackEvidenceEval))
	report.Checks = append(report.Checks, qualityMitigationEvidenceCheck(inputs.MitigationEval))
	report.Checks = append(report.Checks, qualityIDSGuardrailCheck(inputs.MitigationEval))
	report.Checks = append(report.Checks, qualityNormalTrafficCheck(inputs.MitigationEval))
	report.Checks = append(report.Checks, qualitySourceCoverageCheck(inputs.SourceCoverage))
	report.ClaimAdjustments = qualityClaimAdjustments(report.Checks)
	report.RecommendedNextSteps = qualityNextSteps(report.Checks)
	report.OverallStatus = qualityOverallStatus(report.Checks)
	return report
}

func ApplyQualityGateToResearchReport(research ResearchReport, gate QualityGateReport) ResearchReport {
	for _, check := range gate.Checks {
		if check.Status == "pass" {
			continue
		}
		if strings.TrimSpace(check.Guardrail) != "" {
			research.ThreatsToValidity = append(research.ThreatsToValidity, check.Guardrail)
		} else {
			research.ThreatsToValidity = append(research.ThreatsToValidity, check.Summary)
		}
	}
	for _, adjustment := range gate.ClaimAdjustments {
		research.NextSteps = append(research.NextSteps, fmt.Sprintf("%s: %s", adjustment.Disposition, adjustment.Reason))
	}
	research.ThreatsToValidity = uniqueSortedStrings(research.ThreatsToValidity)
	research.NextSteps = uniqueSortedStrings(append(research.NextSteps, gate.RecommendedNextSteps...))
	research.ExecutiveSummary = research.ExecutiveSummary + " Quality gate status: " + gate.OverallStatus + "."
	return research
}

func qualityPrecisionCoverageCheck(report *PrecisionEvaluationReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("precision_label_coverage", "warn", "medium", "precision evaluation labels were not provided", "Do not report measured precision or false-positive rate without human labels.")
	}
	coverage := report.Metrics.LabelCoverage
	switch {
	case coverage >= 0.8:
		return qualityCheck("precision_label_coverage", "pass", "low", fmt.Sprintf("precision label coverage is %.3f", coverage), "")
	case coverage > 0:
		return qualityCheck("precision_label_coverage", "warn", "medium", fmt.Sprintf("precision label coverage is %.3f", coverage), "Weaken precision claims until label coverage reaches at least 0.800.")
	default:
		return qualityCheck("precision_label_coverage", "warn", "medium", "precision label coverage is zero", "Treat incident precision as unevaluated.")
	}
}

func qualityAttackEvidenceCoverageCheck(report *AttackEvidenceEvaluationReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("attack_evidence_label_coverage", "warn", "medium", "attack evidence evaluation labels were not provided", "Do not claim detector evidence quality without labeled attack evidence findings.")
	}
	coverage := report.Metrics.LabelCoverage
	switch {
	case coverage >= 0.8:
		return qualityCheck("attack_evidence_label_coverage", "pass", "low", fmt.Sprintf("attack evidence label coverage is %.3f", coverage), "")
	case coverage > 0:
		return qualityCheck("attack_evidence_label_coverage", "warn", "medium", fmt.Sprintf("attack evidence label coverage is %.3f", coverage), "Separate unlabeled detector evidence from measured evidence quality.")
	default:
		return qualityCheck("attack_evidence_label_coverage", "warn", "medium", "attack evidence label coverage is zero", "Treat attack detector quality as unevaluated.")
	}
}

func qualityMitigationEvidenceCheck(report *MitigationEvaluationReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("mitigation_effectiveness", "warn", "high", "mitigation evaluation was not provided", "Do not claim before/after mitigation effectiveness without comparable windows.")
	}
	accepted := report.Metrics.AcceptedAttackEvidenceReductionRate
	exposed := report.Metrics.ExposedServiceAttemptReductionRate
	idsOverlap := report.Metrics.IDSExposedOverlapReductionRate
	if accepted > 0 || exposed > 0 || idsOverlap > 0 || report.Metrics.TargetedSignalReductionRate > 0 {
		return qualityCheck("mitigation_effectiveness", "pass", "low", "mitigation effectiveness has targeted or exposed-service evidence", "")
	}
	if report.Metrics.AttackEvidenceReductionRate > 0 {
		return qualityCheck("mitigation_effectiveness", "warn", "high", "only observed boundary attack evidence reduction is positive", "Do not treat lower observed internet scan volume as gateway-controlled risk reduction.")
	}
	return qualityCheck("mitigation_effectiveness", "warn", "medium", "accepted/exposed service attempt reduction was not observed", "Frame mitigation as posture confirmation or monitoring unless exposed-service or targeted signals decrease.")
}

func qualityIDSGuardrailCheck(report *MitigationEvaluationReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("ids_alert_guardrail", "warn", "medium", "IDS before/after evaluation was not provided", "Do not use IDS alert counts alone as mitigation effectiveness.")
	}
	if report.Metrics.IDSAlertDelta < 0 && report.Metrics.IDSExposedOverlapReductionRate <= 0 {
		return qualityCheck("ids_alert_guardrail", "warn", "medium", "IDS alert count decreased without exposed-service overlap reduction", "Report IDS alert deltas separately from gateway-controlled exposure reduction.")
	}
	return qualityCheck("ids_alert_guardrail", "pass", "low", "IDS alert metrics are separated from exposed-service overlap", "")
}

func qualityNormalTrafficCheck(report *MitigationEvaluationReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("normal_traffic_safety", "warn", "medium", "normal traffic preservation was not evaluated", "Do not claim mitigation safety without normal-flow continuity evidence.")
	}
	rate := report.Metrics.NormalFlowPreservationRate
	if report.Metrics.BeforeNormalFlowCount == 0 {
		return qualityCheck("normal_traffic_safety", "warn", "medium", "before window has no normal-flow baseline", "Treat normal traffic safety as unmeasured.")
	}
	switch {
	case rate >= 0.9:
		return qualityCheck("normal_traffic_safety", "pass", "low", fmt.Sprintf("normal flow preservation is %.3f", rate), "")
	case rate >= 0.5:
		return qualityCheck("normal_traffic_safety", "warn", "medium", fmt.Sprintf("normal flow preservation is %.3f", rate), "Qualify safety claims and inspect blocked normal dependencies.")
	default:
		return qualityCheck("normal_traffic_safety", "fail", "high", fmt.Sprintf("normal flow preservation is %.3f", rate), "Do not claim safe mitigation; rollback or rule refinement is required.")
	}
}

func qualitySourceCoverageCheck(report *SourceCoverageReport) QualityGateCheck {
	if report == nil {
		return qualityCheck("source_coverage", "warn", "medium", "source coverage report was not provided", "Treat evidence strength as single-pipeline unless source coverage is measured.")
	}
	if report.Metrics.SourceCount < 2 {
		return qualityCheck("source_coverage", "warn", "medium", "less than two evidence sources were assembled", "Weaken corroboration claims for single-source evidence.")
	}
	if report.Metrics.MultiSourceServiceCount == 0 {
		return qualityCheck("source_coverage", "warn", "medium", "no multi-source service overlap was observed", "Avoid claiming cross-sensor corroboration for this run.")
	}
	return qualityCheck("source_coverage", "pass", "low", fmt.Sprintf("%d multi-source service tuple(s) observed", report.Metrics.MultiSourceServiceCount), "")
}

func qualityCheck(key, status, severity, summary, guardrail string) QualityGateCheck {
	return QualityGateCheck{Key: key, Status: status, Severity: severity, Summary: summary, Guardrail: guardrail}
}

func qualityClaimAdjustments(checks []QualityGateCheck) []QualityClaimAdjustment {
	out := []QualityClaimAdjustment{}
	for _, check := range checks {
		if check.Status == "pass" {
			continue
		}
		switch check.Key {
		case "precision_label_coverage":
			out = append(out, QualityClaimAdjustment{Claim: "incident precision", Disposition: "weaken", Reason: check.Guardrail})
		case "attack_evidence_label_coverage":
			out = append(out, QualityClaimAdjustment{Claim: "attack evidence detector quality", Disposition: "weaken", Reason: check.Guardrail})
		case "mitigation_effectiveness":
			out = append(out, QualityClaimAdjustment{Claim: "mitigation reduced risk", Disposition: "weaken", Reason: check.Guardrail})
		case "ids_alert_guardrail":
			out = append(out, QualityClaimAdjustment{Claim: "IDS alert reduction", Disposition: "separate", Reason: check.Guardrail})
		case "normal_traffic_safety":
			out = append(out, QualityClaimAdjustment{Claim: "safe mitigation", Disposition: "weaken", Reason: check.Guardrail})
		case "source_coverage":
			out = append(out, QualityClaimAdjustment{Claim: "cross-sensor corroboration", Disposition: "weaken", Reason: check.Guardrail})
		}
	}
	return out
}

func qualityNextSteps(checks []QualityGateCheck) []string {
	steps := []string{}
	for _, check := range checks {
		if check.Status == "pass" {
			continue
		}
		switch check.Key {
		case "precision_label_coverage":
			steps = append(steps, "increase incident label coverage to at least 0.800")
		case "attack_evidence_label_coverage":
			steps = append(steps, "label attack evidence findings before reporting detector quality")
		case "mitigation_effectiveness":
			steps = append(steps, "evaluate accepted/exposed service attempts and targeted signals rather than observed scan volume alone")
		case "ids_alert_guardrail":
			steps = append(steps, "report IDS alert deltas separately from gateway-controlled exposure reduction")
		case "normal_traffic_safety":
			steps = append(steps, "inspect normal-flow continuity and refine mitigation rules")
		case "source_coverage":
			steps = append(steps, "assemble at least two independent evidence sources and inspect overlap")
		}
	}
	return uniqueSortedStrings(steps)
}

func qualityOverallStatus(checks []QualityGateCheck) string {
	hasWarn := false
	for _, check := range checks {
		if check.Status == "fail" {
			return "fail"
		}
		if check.Status == "warn" {
			hasWarn = true
		}
	}
	if hasWarn {
		return "warn"
	}
	return "pass"
}

func readOptionalJSONFile(path string, dst any) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return false, fmt.Errorf("decode %s: %w", path, err)
	}
	return true, nil
}

func SortedQualityGateChecks(checks []QualityGateCheck) []QualityGateCheck {
	out := append([]QualityGateCheck{}, checks...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Status == out[j].Status {
			return out[i].Key < out[j].Key
		}
		return qualityStatusRank(out[i].Status) > qualityStatusRank(out[j].Status)
	})
	return out
}

func qualityStatusRank(status string) int {
	switch status {
	case "fail":
		return 3
	case "warn":
		return 2
	case "pass":
		return 1
	default:
		return 0
	}
}
