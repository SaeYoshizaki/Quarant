package reportapi

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type ResearchReport struct {
	GeneratedAt       string                `json:"generated_at"`
	Source            ResearchReportSources `json:"source"`
	ExecutiveSummary  string                `json:"executive_summary"`
	ResearchQuestion  string                `json:"research_question"`
	Claim             string                `json:"claim"`
	Metrics           ResearchMetrics       `json:"metrics"`
	ExperimentStages  []ResearchStage       `json:"experiment_stages"`
	Tables            ResearchTables        `json:"tables"`
	SupportedClaims   []string              `json:"supported_claims"`
	MissingEvidence   []string              `json:"missing_evidence"`
	ThreatsToValidity []string              `json:"threats_to_validity"`
	NextSteps         []string              `json:"next_steps"`
}

type ResearchReportSources struct {
	PrecisionReport      string `json:"precision_report,omitempty"`
	PrecisionEvalReport  string `json:"precision_eval_report,omitempty"`
	MitigationPlan       string `json:"mitigation_plan,omitempty"`
	MitigationEvalReport string `json:"mitigation_eval_report,omitempty"`
}

type ResearchMetrics struct {
	IncidentCount                       int     `json:"incident_count"`
	RiskyIncidentCount                  int     `json:"risky_incident_count"`
	SuppressedSignalCount               int     `json:"suppressed_signal_count"`
	LabelCoverage                       float64 `json:"label_coverage,omitempty"`
	Precision                           float64 `json:"precision,omitempty"`
	FalsePositiveRate                   float64 `json:"false_positive_rate,omitempty"`
	MitigationActionCount               int     `json:"mitigation_action_count"`
	AutoEligibleActionCount             int     `json:"auto_eligible_action_count"`
	ReviewRequiredActionCount           int     `json:"review_required_action_count"`
	EstimatedBlockedFlows               int     `json:"estimated_blocked_flows"`
	NormalTrafficImpactMeasurable       bool    `json:"normal_traffic_impact_measurable"`
	TargetedSignalReductionRate         float64 `json:"targeted_signal_reduction_rate,omitempty"`
	AttackEvidenceReductionRate         float64 `json:"attack_evidence_reduction_rate,omitempty"`
	AcceptedAttackEvidenceReductionRate float64 `json:"accepted_attack_evidence_reduction_rate,omitempty"`
	ExposedServiceAttemptReductionRate  float64 `json:"exposed_service_attempt_reduction_rate,omitempty"`
	IDSExposedOverlapReductionRate      float64 `json:"ids_exposed_overlap_reduction_rate,omitempty"`
	ImprovedMitigationActionCount       int     `json:"improved_mitigation_action_count,omitempty"`
	ResidualMitigationActionCount       int     `json:"residual_mitigation_action_count,omitempty"`
	RegressedMitigationActionCount      int     `json:"regressed_mitigation_action_count,omitempty"`
	CriticalFlowContinuityRisk          string  `json:"critical_flow_continuity_risk,omitempty"`
	IncidentReductionRate               float64 `json:"incident_reduction_rate,omitempty"`
	HighRiskIncidentReductionRate       float64 `json:"high_risk_incident_reduction_rate,omitempty"`
	NormalFlowPreservationRate          float64 `json:"normal_flow_preservation_rate,omitempty"`
	CriticalFlowPreservationRate        float64 `json:"critical_flow_preservation_rate,omitempty"`
	FalseMitigationRate                 float64 `json:"false_mitigation_rate,omitempty"`
	RollbackRequiredCount               int     `json:"rollback_required_count,omitempty"`
	ResidualRiskScore                   int     `json:"residual_risk_score,omitempty"`
	OverallOutcome                      string  `json:"overall_outcome,omitempty"`
}

type ResearchStage struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
	Gaps     []string `json:"gaps,omitempty"`
}

type ResearchTables struct {
	IncidentSummary         []ResearchTableRow `json:"incident_summary,omitempty"`
	MitigationSummary       []ResearchTableRow `json:"mitigation_summary,omitempty"`
	MitigationOutcomes      []ResearchTableRow `json:"mitigation_outcomes,omitempty"`
	NormalTrafficContinuity []ResearchTableRow `json:"normal_traffic_continuity,omitempty"`
}

type ResearchTableRow map[string]string

func LoadResearchReport(precisionPath, precisionEvalPath, mitigationPlanPath, mitigationEvalPath string) (ResearchReport, error) {
	var precision DetectionPrecisionReport
	var precisionEval PrecisionEvaluationReport
	var mitigation MitigationPlan
	var mitigationEval MitigationEvaluationReport
	hasPrecisionEval := strings.TrimSpace(precisionEvalPath) != ""
	hasMitigationEval := strings.TrimSpace(mitigationEvalPath) != ""

	if err := readJSONFile(precisionPath, &precision); err != nil {
		return ResearchReport{}, err
	}
	if hasPrecisionEval {
		if err := readJSONFile(precisionEvalPath, &precisionEval); err != nil {
			return ResearchReport{}, err
		}
	}
	if err := readJSONFile(mitigationPlanPath, &mitigation); err != nil {
		return ResearchReport{}, err
	}
	if hasMitigationEval {
		if err := readJSONFile(mitigationEvalPath, &mitigationEval); err != nil {
			return ResearchReport{}, err
		}
	}
	report := BuildResearchReport(precision, optionalPrecisionEval(precisionEval, hasPrecisionEval), mitigation, optionalMitigationEval(mitigationEval, hasMitigationEval))
	report.Source = ResearchReportSources{
		PrecisionReport:      precisionPath,
		PrecisionEvalReport:  precisionEvalPath,
		MitigationPlan:       mitigationPlanPath,
		MitigationEvalReport: mitigationEvalPath,
	}
	return report, nil
}

func BuildResearchReport(precision DetectionPrecisionReport, precisionEval *PrecisionEvaluationReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) ResearchReport {
	report := ResearchReport{
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ResearchQuestion: "How much can passive IoT monitoring reduce observable risk through rule-based virtual patch planning while preserving normal traffic?",
		Claim:            "Quarant converts passive observations into explainable incidents, rule-based mitigation plans, and before/after mitigation evidence without actively touching IoT devices.",
		ThreatsToValidity: []string{
			"Passive monitoring cannot prove exploitability, compromise, or firmware-level remediation.",
			"Before/after windows must be comparable; device usage changes can bias mitigation effectiveness.",
			"Encrypted traffic and unseen local dependencies may hide residual risk or normal-traffic breakage.",
			"Rule-based decisions depend on the completeness of the signal taxonomy and suppression policy.",
			"Internet scan volume is not controlled by gateway mitigation; router-boundary evidence reduction must be interpreted separately from accepted or exposed-service attempts.",
		},
	}
	report.Metrics = buildResearchMetrics(precision, precisionEval, mitigation, mitigationEval)
	report.ExperimentStages = buildResearchStages(precision, precisionEval, mitigation, mitigationEval)
	report.Tables = buildResearchTables(precision, mitigation, mitigationEval)
	report.SupportedClaims = buildResearchSupportedClaims(precision, precisionEval, mitigation, mitigationEval)
	report.MissingEvidence = buildResearchMissingEvidence(precision, precisionEval, mitigation, mitigationEval)
	report.NextSteps = buildResearchNextSteps(report)
	report.ExecutiveSummary = researchExecutiveSummary(report.Metrics)
	return report
}

func readJSONFile(path string, dst any) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("JSON path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func optionalPrecisionEval(report PrecisionEvaluationReport, ok bool) *PrecisionEvaluationReport {
	if !ok {
		return nil
	}
	return &report
}

func optionalMitigationEval(report MitigationEvaluationReport, ok bool) *MitigationEvaluationReport {
	if !ok {
		return nil
	}
	return &report
}

func buildResearchMetrics(precision DetectionPrecisionReport, precisionEval *PrecisionEvaluationReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) ResearchMetrics {
	metrics := ResearchMetrics{
		IncidentCount:                 precision.Metrics.IncidentCount,
		RiskyIncidentCount:            precision.Metrics.RiskyIncidentCount,
		SuppressedSignalCount:         precision.Metrics.SuppressedSignalCount,
		MitigationActionCount:         mitigation.Metrics.ActionCount,
		AutoEligibleActionCount:       mitigation.Metrics.AutoEligibleCount,
		ReviewRequiredActionCount:     mitigation.Metrics.ReviewRequiredCount,
		EstimatedBlockedFlows:         mitigation.Metrics.EstimatedBlockedFlows,
		NormalTrafficImpactMeasurable: mitigation.PaperSummary.NormalTrafficImpactMeasurable,
	}
	if precisionEval != nil {
		metrics.LabelCoverage = precisionEval.Metrics.LabelCoverage
		metrics.Precision = precisionEval.Metrics.Precision
		metrics.FalsePositiveRate = precisionEval.Metrics.FalsePositiveRate
	}
	if mitigationEval != nil {
		metrics.TargetedSignalReductionRate = mitigationEval.Metrics.TargetedSignalReductionRate
		metrics.AttackEvidenceReductionRate = mitigationEval.Metrics.AttackEvidenceReductionRate
		metrics.AcceptedAttackEvidenceReductionRate = mitigationEval.Metrics.AcceptedAttackEvidenceReductionRate
		metrics.ExposedServiceAttemptReductionRate = mitigationEval.Metrics.ExposedServiceAttemptReductionRate
		metrics.IDSExposedOverlapReductionRate = mitigationEval.Metrics.IDSExposedOverlapReductionRate
		metrics.ImprovedMitigationActionCount = mitigationEval.Metrics.ImprovedActionCount
		metrics.ResidualMitigationActionCount = mitigationEval.Metrics.ResidualActionCount
		metrics.RegressedMitigationActionCount = mitigationEval.Metrics.RegressedActionCount
		metrics.CriticalFlowContinuityRisk = mitigationEval.Metrics.CriticalFlowContinuityRisk
		metrics.IncidentReductionRate = mitigationEval.PaperMetrics.IncidentReductionRate
		metrics.HighRiskIncidentReductionRate = mitigationEval.PaperMetrics.HighRiskIncidentReductionRate
		metrics.NormalFlowPreservationRate = mitigationEval.PaperMetrics.NormalFlowPreservationRate
		metrics.CriticalFlowPreservationRate = mitigationEval.PaperMetrics.CriticalFlowPreservationRate
		metrics.FalseMitigationRate = mitigationEval.PaperMetrics.FalseMitigationRate
		metrics.RollbackRequiredCount = mitigationEval.PaperMetrics.RollbackRequiredCount
		metrics.ResidualRiskScore = mitigationEval.PaperMetrics.ResidualRiskScore
		metrics.OverallOutcome = mitigationEval.OverallOutcome
	}
	return metrics
}

func buildResearchStages(precision DetectionPrecisionReport, precisionEval *PrecisionEvaluationReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) []ResearchStage {
	stages := []ResearchStage{
		{
			Name:   "incident_generation",
			Status: stageStatus(precision.Metrics.IncidentCount > 0, "ready", "needs_data"),
			Evidence: []string{
				fmt.Sprintf("%d incident(s) generated", precision.Metrics.IncidentCount),
				fmt.Sprintf("%d signal(s) suppressed before incident promotion", precision.Metrics.SuppressedSignalCount),
			},
			Gaps: precision.EvaluationReadiness.BlockingIssues,
		},
		{
			Name:   "mitigation_planning",
			Status: stageStatus(mitigation.Metrics.ActionCount > 0, "ready", "needs_rule_mapping"),
			Evidence: []string{
				fmt.Sprintf("%d mitigation action(s) generated", mitigation.Metrics.ActionCount),
				fmt.Sprintf("%d estimated historical flow(s) would be blocked", mitigation.Metrics.EstimatedBlockedFlows),
			},
			Gaps: mitigation.PaperSummary.MissingEvidence,
		},
	}
	if precisionEval != nil {
		stages = append(stages, ResearchStage{
			Name:   "precision_evaluation",
			Status: stageStatus(precisionEval.Metrics.LabelCoverage >= 0.8, "ready", "needs_more_labels"),
			Evidence: []string{
				fmt.Sprintf("label coverage %.3f", precisionEval.Metrics.LabelCoverage),
				fmt.Sprintf("precision %.3f", precisionEval.Metrics.Precision),
				fmt.Sprintf("false-positive rate %.3f", precisionEval.Metrics.FalsePositiveRate),
			},
			Gaps: precisionEval.Limitations,
		})
	} else {
		stages = append(stages, ResearchStage{
			Name:   "precision_evaluation",
			Status: "missing",
			Gaps:   []string{"precision_eval_report.json was not provided"},
		})
	}
	if mitigationEval != nil {
		stages = append(stages, ResearchStage{
			Name:   "post_mitigation_evaluation",
			Status: stageStatus(mitigationEval.Metrics.EvaluableActionCount > 0, "ready", "needs_comparable_windows"),
			Evidence: []string{
				fmt.Sprintf("overall outcome %s", mitigationEval.OverallOutcome),
				fmt.Sprintf("targeted signal reduction %.3f", mitigationEval.Metrics.TargetedSignalReductionRate),
				fmt.Sprintf("attack evidence reduction %.3f", mitigationEval.Metrics.AttackEvidenceReductionRate),
				fmt.Sprintf("accepted boundary evidence reduction %.3f", mitigationEval.Metrics.AcceptedAttackEvidenceReductionRate),
				fmt.Sprintf("exposed-service attempt reduction %.3f", mitigationEval.Metrics.ExposedServiceAttemptReductionRate),
				fmt.Sprintf("normal-flow preservation %.3f", mitigationEval.PaperMetrics.NormalFlowPreservationRate),
				fmt.Sprintf("false mitigation rate %.3f", mitigationEval.PaperMetrics.FalseMitigationRate),
				fmt.Sprintf("critical-flow continuity risk %s", mitigationEval.Metrics.CriticalFlowContinuityRisk),
			},
			Gaps: mitigationEval.PaperSummary.MissingEvidence,
		})
	} else {
		stages = append(stages, ResearchStage{
			Name:   "post_mitigation_evaluation",
			Status: "missing",
			Gaps:   []string{"mitigation_eval_report.json was not provided"},
		})
	}
	return stages
}

func buildResearchTables(precision DetectionPrecisionReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) ResearchTables {
	return ResearchTables{
		IncidentSummary:         researchIncidentRows(precision),
		MitigationSummary:       researchMitigationRows(mitigation),
		MitigationOutcomes:      researchMitigationOutcomeRows(mitigationEval),
		NormalTrafficContinuity: researchContinuityRows(mitigationEval),
	}
}

func researchIncidentRows(precision DetectionPrecisionReport) []ResearchTableRow {
	rows := []ResearchTableRow{
		{"metric": "incidents", "value": fmt.Sprintf("%d", precision.Metrics.IncidentCount)},
		{"metric": "risky_incidents", "value": fmt.Sprintf("%d", precision.Metrics.RiskyIncidentCount)},
		{"metric": "suspicious_incidents", "value": fmt.Sprintf("%d", precision.Metrics.SuspiciousIncidentCount)},
		{"metric": "observe_incidents", "value": fmt.Sprintf("%d", precision.Metrics.ObserveIncidentCount)},
		{"metric": "suppressed_signals", "value": fmt.Sprintf("%d", precision.Metrics.SuppressedSignalCount)},
		{"metric": "baseline_ready_devices", "value": fmt.Sprintf("%d", precision.Metrics.BaselineReadyDeviceCount)},
	}
	return rows
}

func researchMitigationRows(mitigation MitigationPlan) []ResearchTableRow {
	rows := []ResearchTableRow{}
	for _, action := range mitigation.Actions {
		rows = append(rows, ResearchTableRow{
			"action_id":               action.ID,
			"device_ip":               action.DeviceIP,
			"kind":                    action.Kind,
			"status":                  action.Status,
			"estimated_blocked_flows": fmt.Sprintf("%d", action.Impact.EstimatedBlockedFlows),
			"normal_traffic_risk":     action.Impact.NormalTrafficRisk,
			"baseline_impact":         action.Impact.BaselineImpact,
			"target":                  action.RiskReductionTarget.Exposure,
		})
	}
	return rows
}

func researchMitigationOutcomeRows(mitigationEval *MitigationEvaluationReport) []ResearchTableRow {
	if mitigationEval == nil {
		return nil
	}
	rows := []ResearchTableRow{}
	for _, outcome := range mitigationEval.ActionOutcomes {
		rows = append(rows, ResearchTableRow{
			"action_id":               outcome.ActionID,
			"device_ip":               outcome.DeviceIP,
			"kind":                    outcome.Kind,
			"before_targeted_signals": fmt.Sprintf("%d", outcome.BeforeTargetedSignals),
			"after_targeted_signals":  fmt.Sprintf("%d", outcome.AfterTargetedSignals),
			"targeted_signal_delta":   fmt.Sprintf("%d", outcome.TargetedSignalDelta),
			"device_risk_score_delta": fmt.Sprintf("%d", outcome.DeviceRiskScoreDelta),
			"critical_flow_delta":     fmt.Sprintf("%d", outcome.CriticalFlowDelta),
			"outcome":                 outcome.Outcome,
		})
	}
	return rows
}

func researchContinuityRows(mitigationEval *MitigationEvaluationReport) []ResearchTableRow {
	if mitigationEval == nil {
		return nil
	}
	rows := []ResearchTableRow{}
	for _, device := range mitigationEval.DeviceOutcomes {
		rows = append(rows, ResearchTableRow{
			"device_ip":             device.DeviceIP,
			"before_critical_flows": fmt.Sprintf("%d", device.BeforeCriticalFlows),
			"after_critical_flows":  fmt.Sprintf("%d", device.AfterCriticalFlows),
			"critical_flow_delta":   fmt.Sprintf("%d", device.CriticalFlowDelta),
			"continuity_assessment": device.ContinuityAssessment,
			"risk_score_delta":      fmt.Sprintf("%d", device.RiskScoreDelta),
			"incident_delta":        fmt.Sprintf("%d", device.IncidentDelta),
		})
	}
	return rows
}

func buildResearchSupportedClaims(precision DetectionPrecisionReport, precisionEval *PrecisionEvaluationReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) []string {
	claims := []string{}
	claims = append(claims, precision.PaperSummary.ResearchClaimsSupported...)
	claims = append(claims, mitigation.PaperSummary.SupportedClaims...)
	if precisionEval != nil && precisionEval.Metrics.LabelCoverage > 0 {
		claims = append(claims, "human labels can quantify precision and false-positive rate for generated incidents")
	}
	if mitigationEval != nil {
		claims = append(claims, mitigationEval.PaperSummary.SupportedClaims...)
	}
	return uniqueSortedStrings(claims)
}

func buildResearchMissingEvidence(precision DetectionPrecisionReport, precisionEval *PrecisionEvaluationReport, mitigation MitigationPlan, mitigationEval *MitigationEvaluationReport) []string {
	missing := []string{}
	missing = append(missing, precision.EvaluationReadiness.BlockingIssues...)
	missing = append(missing, mitigation.PaperSummary.MissingEvidence...)
	if precisionEval == nil {
		missing = append(missing, "precision_eval_report.json was not provided; measured precision and false-positive rate are unavailable")
	}
	if mitigationEval == nil {
		missing = append(missing, "mitigation_eval_report.json was not provided; before/after mitigation effectiveness is unavailable")
	} else {
		missing = append(missing, mitigationEval.PaperSummary.MissingEvidence...)
	}
	return uniqueSortedStrings(missing)
}

func buildResearchNextSteps(report ResearchReport) []string {
	steps := []string{}
	if report.Metrics.LabelCoverage < 0.8 {
		steps = append(steps, "increase human label coverage for incident precision evaluation")
	}
	if report.Metrics.MitigationActionCount == 0 {
		steps = append(steps, "add mitigation rule mappings for remaining incident taxonomies")
	}
	if report.Metrics.OverallOutcome == "" || report.Metrics.OverallOutcome == "not_evaluable" {
		steps = append(steps, "run comparable before/after observation windows and generate mitigation_eval_report.json")
	}
	if report.Metrics.CriticalFlowContinuityRisk == "high" || report.Metrics.CriticalFlowContinuityRisk == "possible" {
		steps = append(steps, "inspect normal-traffic continuity before claiming safe automated mitigation")
	}
	if len(steps) == 0 {
		steps = append(steps, "package the incident, mitigation, and before/after evaluation tables for the paper")
	}
	return uniqueSortedStrings(steps)
}

func researchExecutiveSummary(metrics ResearchMetrics) string {
	parts := []string{
		fmt.Sprintf("%d incident(s) were generated after precision filtering", metrics.IncidentCount),
		fmt.Sprintf("%d mitigation action(s) were planned", metrics.MitigationActionCount),
		fmt.Sprintf("%d historical flow(s) were estimated as blocked by planned mitigations", metrics.EstimatedBlockedFlows),
	}
	if metrics.OverallOutcome != "" {
		parts = append(parts, fmt.Sprintf("post-mitigation outcome was %s with targeted signal reduction %.3f", metrics.OverallOutcome, metrics.TargetedSignalReductionRate))
	}
	if metrics.AttackEvidenceReductionRate > 0 {
		parts = append(parts, fmt.Sprintf("attack evidence reduction was %.3f", metrics.AttackEvidenceReductionRate))
	}
	if metrics.AcceptedAttackEvidenceReductionRate > 0 || metrics.ExposedServiceAttemptReductionRate > 0 {
		parts = append(parts, fmt.Sprintf("accepted/exposed boundary evidence reduction was %.3f/%.3f", metrics.AcceptedAttackEvidenceReductionRate, metrics.ExposedServiceAttemptReductionRate))
	}
	if metrics.CriticalFlowContinuityRisk != "" {
		parts = append(parts, fmt.Sprintf("critical-flow continuity risk was %s", metrics.CriticalFlowContinuityRisk))
	}
	return strings.Join(parts, "; ") + "."
}

func stageStatus(ok bool, ready, missing string) string {
	if ok {
		return ready
	}
	return missing
}

func ResearchReportMarkdown(report ResearchReport) string {
	var b strings.Builder
	b.WriteString("# Quarant Research Report\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString(report.ExecutiveSummary)
	b.WriteString("\n\n")
	b.WriteString("## Research Question\n\n")
	b.WriteString(report.ResearchQuestion)
	b.WriteString("\n\n")
	b.WriteString("## Key Metrics\n\n")
	writeMarkdownKV(&b, []ResearchTableRow{
		{"metric": "incidents", "value": fmt.Sprintf("%d", report.Metrics.IncidentCount)},
		{"metric": "risky_incidents", "value": fmt.Sprintf("%d", report.Metrics.RiskyIncidentCount)},
		{"metric": "suppressed_signals", "value": fmt.Sprintf("%d", report.Metrics.SuppressedSignalCount)},
		{"metric": "mitigation_actions", "value": fmt.Sprintf("%d", report.Metrics.MitigationActionCount)},
		{"metric": "estimated_blocked_flows", "value": fmt.Sprintf("%d", report.Metrics.EstimatedBlockedFlows)},
		{"metric": "targeted_signal_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.TargetedSignalReductionRate)},
		{"metric": "attack_evidence_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.AttackEvidenceReductionRate)},
		{"metric": "accepted_attack_evidence_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.AcceptedAttackEvidenceReductionRate)},
		{"metric": "exposed_service_attempt_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.ExposedServiceAttemptReductionRate)},
		{"metric": "ids_exposed_overlap_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.IDSExposedOverlapReductionRate)},
		{"metric": "normal_flow_preservation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.NormalFlowPreservationRate)},
		{"metric": "false_mitigation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.FalseMitigationRate)},
		{"metric": "rollback_required_count", "value": fmt.Sprintf("%d", report.Metrics.RollbackRequiredCount)},
		{"metric": "critical_flow_continuity_risk", "value": report.Metrics.CriticalFlowContinuityRisk},
		{"metric": "overall_outcome", "value": report.Metrics.OverallOutcome},
	})
	b.WriteString("\n## Experiment Stages\n\n")
	for _, stage := range report.ExperimentStages {
		b.WriteString("- ")
		b.WriteString(stage.Name)
		b.WriteString(": ")
		b.WriteString(stage.Status)
		b.WriteString("\n")
	}
	writeMarkdownTable(&b, "Incident Summary", report.Tables.IncidentSummary)
	writeMarkdownTable(&b, "Mitigation Summary", report.Tables.MitigationSummary)
	writeMarkdownTable(&b, "Mitigation Outcomes", report.Tables.MitigationOutcomes)
	writeMarkdownTable(&b, "Normal Traffic Continuity", report.Tables.NormalTrafficContinuity)
	writeMarkdownList(&b, "Supported Claims", report.SupportedClaims)
	writeMarkdownList(&b, "Missing Evidence", report.MissingEvidence)
	writeMarkdownList(&b, "Threats To Validity", report.ThreatsToValidity)
	writeMarkdownList(&b, "Next Steps", report.NextSteps)
	return b.String()
}

func ResearchReportCSVs(report ResearchReport) map[string]string {
	out := map[string]string{}
	if csv := researchRowsCSV([]ResearchTableRow{
		{"metric": "incidents", "value": fmt.Sprintf("%d", report.Metrics.IncidentCount)},
		{"metric": "risky_incidents", "value": fmt.Sprintf("%d", report.Metrics.RiskyIncidentCount)},
		{"metric": "suppressed_signals", "value": fmt.Sprintf("%d", report.Metrics.SuppressedSignalCount)},
		{"metric": "label_coverage", "value": fmt.Sprintf("%.3f", report.Metrics.LabelCoverage)},
		{"metric": "precision", "value": fmt.Sprintf("%.3f", report.Metrics.Precision)},
		{"metric": "false_positive_rate", "value": fmt.Sprintf("%.3f", report.Metrics.FalsePositiveRate)},
		{"metric": "mitigation_actions", "value": fmt.Sprintf("%d", report.Metrics.MitigationActionCount)},
		{"metric": "auto_eligible_actions", "value": fmt.Sprintf("%d", report.Metrics.AutoEligibleActionCount)},
		{"metric": "review_required_actions", "value": fmt.Sprintf("%d", report.Metrics.ReviewRequiredActionCount)},
		{"metric": "estimated_blocked_flows", "value": fmt.Sprintf("%d", report.Metrics.EstimatedBlockedFlows)},
		{"metric": "incident_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.IncidentReductionRate)},
		{"metric": "high_risk_incident_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.HighRiskIncidentReductionRate)},
		{"metric": "targeted_signal_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.TargetedSignalReductionRate)},
		{"metric": "attack_evidence_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.AttackEvidenceReductionRate)},
		{"metric": "accepted_attack_evidence_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.AcceptedAttackEvidenceReductionRate)},
		{"metric": "exposed_service_attempt_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.ExposedServiceAttemptReductionRate)},
		{"metric": "ids_exposed_overlap_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.IDSExposedOverlapReductionRate)},
		{"metric": "normal_flow_preservation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.NormalFlowPreservationRate)},
		{"metric": "critical_flow_preservation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.CriticalFlowPreservationRate)},
		{"metric": "false_mitigation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.FalseMitigationRate)},
		{"metric": "rollback_required_count", "value": fmt.Sprintf("%d", report.Metrics.RollbackRequiredCount)},
		{"metric": "residual_risk_score", "value": fmt.Sprintf("%d", report.Metrics.ResidualRiskScore)},
		{"metric": "critical_flow_continuity_risk", "value": report.Metrics.CriticalFlowContinuityRisk},
		{"metric": "overall_outcome", "value": report.Metrics.OverallOutcome},
	}); csv != "" {
		out["metrics.csv"] = csv
	}
	if csv := researchRowsCSV(report.Tables.IncidentSummary); csv != "" {
		out["incident_summary.csv"] = csv
	}
	if csv := researchRowsCSV(report.Tables.MitigationSummary); csv != "" {
		out["mitigation_summary.csv"] = csv
	}
	if csv := researchRowsCSV(report.Tables.MitigationOutcomes); csv != "" {
		out["mitigation_outcomes.csv"] = csv
	}
	if csv := researchRowsCSV(report.Tables.NormalTrafficContinuity); csv != "" {
		out["normal_traffic_continuity.csv"] = csv
	}
	if csv := researchRowsCSV(researchStageRows(report.ExperimentStages)); csv != "" {
		out["experiment_stages.csv"] = csv
	}
	return out
}

func researchRowsCSV(rows []ResearchTableRow) string {
	if len(rows) == 0 {
		return ""
	}
	var b strings.Builder
	writer := csv.NewWriter(&b)
	columns := researchTableColumns(rows)
	if err := writer.Write(columns); err != nil {
		return ""
	}
	for _, row := range rows {
		record := make([]string, 0, len(columns))
		for _, col := range columns {
			record = append(record, row[col])
		}
		if err := writer.Write(record); err != nil {
			return ""
		}
	}
	writer.Flush()
	return b.String()
}

func researchStageRows(stages []ResearchStage) []ResearchTableRow {
	rows := make([]ResearchTableRow, 0, len(stages))
	for _, stage := range stages {
		rows = append(rows, ResearchTableRow{
			"name":     stage.Name,
			"status":   stage.Status,
			"evidence": strings.Join(stage.Evidence, "; "),
			"gaps":     strings.Join(stage.Gaps, "; "),
		})
	}
	return rows
}

func writeMarkdownKV(b *strings.Builder, rows []ResearchTableRow) {
	writeMarkdownTable(b, "", rows)
}

func writeMarkdownTable(b *strings.Builder, title string, rows []ResearchTableRow) {
	if len(rows) == 0 {
		return
	}
	if title != "" {
		b.WriteString("\n## ")
		b.WriteString(title)
		b.WriteString("\n\n")
	}
	columns := researchTableColumns(rows)
	for _, col := range columns {
		b.WriteString("| ")
		b.WriteString(col)
		b.WriteString(" ")
	}
	b.WriteString("|\n")
	for range columns {
		b.WriteString("|---")
	}
	b.WriteString("|\n")
	for _, row := range rows {
		for _, col := range columns {
			b.WriteString("| ")
			b.WriteString(markdownCell(row[col]))
			b.WriteString(" ")
		}
		b.WriteString("|\n")
	}
	b.WriteString("\n")
}

func writeMarkdownList(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("\n## ")
	b.WriteString(title)
	b.WriteString("\n\n")
	for _, item := range items {
		b.WriteString("- ")
		b.WriteString(item)
		b.WriteString("\n")
	}
}

func researchTableColumns(rows []ResearchTableRow) []string {
	set := map[string]bool{}
	for _, row := range rows {
		for key := range row {
			set[key] = true
		}
	}
	columns := make([]string, 0, len(set))
	for key := range set {
		columns = append(columns, key)
	}
	sort.Strings(columns)
	return columns
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, "|", "\\|")
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
