package reportapi

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type MitigationEvaluationReport struct {
	GeneratedAt     string                            `json:"generated_at"`
	Source          MitigationEvaluationSources       `json:"source"`
	Metrics         MitigationEvaluationMetrics       `json:"metrics"`
	PaperMetrics    MitigationEvaluationPaperMetrics  `json:"paper_metrics"`
	ApplySummary    *MitigationEvaluationApplySummary `json:"apply_summary,omitempty"`
	OverallOutcome  string                            `json:"overall_outcome"`
	ActionOutcomes  []MitigationActionEvaluation      `json:"action_outcomes"`
	DeviceOutcomes  []MitigationDeviceEvaluation      `json:"device_outcomes"`
	PaperSummary    MitigationEvalPaperSummary        `json:"paper_summary"`
	Recommendations []string                          `json:"recommendations"`
	Limitations     []string                          `json:"limitations"`
}

type MitigationEvaluationSources struct {
	Plan               string `json:"plan,omitempty"`
	ApplyReport        string `json:"apply_report,omitempty"`
	BeforeEvents       string `json:"before_events,omitempty"`
	BeforeFlows        string `json:"before_flows,omitempty"`
	BeforeObservations string `json:"before_observations,omitempty"`
	BeforeInventory    string `json:"before_inventory,omitempty"`
	AfterEvents        string `json:"after_events,omitempty"`
	AfterFlows         string `json:"after_flows,omitempty"`
	AfterObservations  string `json:"after_observations,omitempty"`
	AfterInventory     string `json:"after_inventory,omitempty"`
}

type MitigationEvaluationMetrics struct {
	ActionCount                  int     `json:"action_count"`
	EvaluableActionCount         int     `json:"evaluable_action_count"`
	ImprovedActionCount          int     `json:"improved_action_count"`
	ResolvedActionCount          int     `json:"resolved_action_count"`
	ResidualActionCount          int     `json:"residual_action_count"`
	RegressedActionCount         int     `json:"regressed_action_count"`
	MonitorOnlyActionCount       int     `json:"monitor_only_action_count"`
	BeforeIncidentCount          int     `json:"before_incident_count"`
	AfterIncidentCount           int     `json:"after_incident_count"`
	IncidentDelta                int     `json:"incident_delta"`
	BeforeRiskScore              int     `json:"before_risk_score"`
	AfterRiskScore               int     `json:"after_risk_score"`
	RiskScoreDelta               int     `json:"risk_score_delta"`
	BeforeTargetedSignalCount    int     `json:"before_targeted_signal_count"`
	AfterTargetedSignalCount     int     `json:"after_targeted_signal_count"`
	TargetedSignalReductionRate  float64 `json:"targeted_signal_reduction_rate,omitempty"`
	BeforeCriticalFlowCount      int     `json:"before_critical_flow_count"`
	AfterCriticalFlowCount       int     `json:"after_critical_flow_count"`
	CriticalFlowDelta            int     `json:"critical_flow_delta"`
	CriticalFlowContinuityRisk   string  `json:"critical_flow_continuity_risk"`
	EstimatedBlockedFlowsPlanned int     `json:"estimated_blocked_flows_planned"`
	RollbackRequiredCount        int     `json:"rollback_required_count"`
	FalseMitigationCount         int     `json:"false_mitigation_count"`
	ResidualRiskScore            int     `json:"residual_risk_score"`
	BeforeNormalFlowCount        int     `json:"before_normal_flow_count"`
	AfterNormalFlowCount         int     `json:"after_normal_flow_count"`
	NormalFlowDelta              int     `json:"normal_flow_delta"`
	NormalFlowPreservationRate   float64 `json:"normal_flow_preservation_rate,omitempty"`
}

type MitigationEvaluationPaperMetrics struct {
	IncidentReductionRate         float64 `json:"incident_reduction_rate,omitempty"`
	HighRiskIncidentReductionRate float64 `json:"high_risk_incident_reduction_rate,omitempty"`
	TargetedSignalReductionRate   float64 `json:"targeted_signal_reduction_rate,omitempty"`
	NormalFlowPreservationRate    float64 `json:"normal_flow_preservation_rate,omitempty"`
	CriticalFlowPreservationRate  float64 `json:"critical_flow_preservation_rate,omitempty"`
	FalseMitigationRate           float64 `json:"false_mitigation_rate,omitempty"`
	RollbackRequiredCount         int     `json:"rollback_required_count"`
	ResidualRiskScore             int     `json:"residual_risk_score"`
	BeforeHighRiskIncidentCount   int     `json:"before_high_risk_incident_count"`
	AfterHighRiskIncidentCount    int     `json:"after_high_risk_incident_count"`
	EstimatedBlockedFlowsPlanned  int     `json:"estimated_blocked_flows_planned"`
	ObservedNormalFlowDelta       int     `json:"observed_normal_flow_delta"`
	ApplyWasExplicit              bool    `json:"apply_was_explicit"`
	ApplyWasBlocked               bool    `json:"apply_was_blocked"`
}

type MitigationEvaluationApplySummary struct {
	Status                string   `json:"status"`
	Mode                  string   `json:"mode"`
	ExplicitApply         bool     `json:"explicit_apply"`
	DryRun                bool     `json:"dry_run"`
	ManagedRuleCount      int      `json:"managed_rule_count"`
	PartialApplyDetection bool     `json:"partial_apply_detection"`
	BlockingIssues        []string `json:"blocking_issues,omitempty"`
	RollbackScriptPath    string   `json:"rollback_script_path,omitempty"`
	ApplyScriptPath       string   `json:"apply_script_path,omitempty"`
}

type MitigationActionEvaluation struct {
	ActionID                  string   `json:"action_id"`
	IncidentID                string   `json:"incident_id,omitempty"`
	DeviceIP                  string   `json:"device_ip,omitempty"`
	Kind                      string   `json:"kind"`
	Status                    string   `json:"status"`
	TargetSignals             []string `json:"target_signals,omitempty"`
	TargetTaxonomy            string   `json:"target_taxonomy,omitempty"`
	BeforeTargetedSignals     int      `json:"before_targeted_signals"`
	AfterTargetedSignals      int      `json:"after_targeted_signals"`
	TargetedSignalDelta       int      `json:"targeted_signal_delta"`
	BeforeDeviceIncidentCount int      `json:"before_device_incident_count"`
	AfterDeviceIncidentCount  int      `json:"after_device_incident_count"`
	BeforeDeviceRiskScore     int      `json:"before_device_risk_score"`
	AfterDeviceRiskScore      int      `json:"after_device_risk_score"`
	DeviceRiskScoreDelta      int      `json:"device_risk_score_delta"`
	BeforeCriticalFlows       int      `json:"before_critical_flows"`
	AfterCriticalFlows        int      `json:"after_critical_flows"`
	CriticalFlowDelta         int      `json:"critical_flow_delta"`
	EstimatedBlockedFlows     int      `json:"estimated_blocked_flows"`
	NormalTrafficRisk         string   `json:"normal_traffic_risk"`
	Outcome                   string   `json:"outcome"`
	OutcomeReasons            []string `json:"outcome_reasons,omitempty"`
}

type MitigationDeviceEvaluation struct {
	DeviceIP             string `json:"device_ip"`
	BeforeIncidentCount  int    `json:"before_incident_count"`
	AfterIncidentCount   int    `json:"after_incident_count"`
	IncidentDelta        int    `json:"incident_delta"`
	BeforeRiskScore      int    `json:"before_risk_score"`
	AfterRiskScore       int    `json:"after_risk_score"`
	RiskScoreDelta       int    `json:"risk_score_delta"`
	BeforeCriticalFlows  int    `json:"before_critical_flows"`
	AfterCriticalFlows   int    `json:"after_critical_flows"`
	CriticalFlowDelta    int    `json:"critical_flow_delta"`
	ContinuityAssessment string `json:"continuity_assessment"`
}

type MitigationEvalPaperSummary struct {
	Claim                string   `json:"claim"`
	SupportedClaims      []string `json:"supported_claims"`
	MissingEvidence      []string `json:"missing_evidence"`
	TableColumns         []string `json:"table_columns"`
	PrimaryOutcomeMetric string   `json:"primary_outcome_metric"`
}

func LoadMitigationEvaluationReport(planPath, beforeEventsPath, beforeFlowsPath, beforeObservationsPath, beforeInventoryPath, afterEventsPath, afterFlowsPath, afterObservationsPath, afterInventoryPath string) (MitigationEvaluationReport, error) {
	return LoadMitigationEvaluationReportWithApply(planPath, "", beforeEventsPath, beforeFlowsPath, beforeObservationsPath, beforeInventoryPath, afterEventsPath, afterFlowsPath, afterObservationsPath, afterInventoryPath)
}

func LoadMitigationEvaluationReportWithApply(planPath, applyReportPath, beforeEventsPath, beforeFlowsPath, beforeObservationsPath, beforeInventoryPath, afterEventsPath, afterFlowsPath, afterObservationsPath, afterInventoryPath string) (MitigationEvaluationReport, error) {
	plan, err := LoadMitigationPlanJSON(planPath)
	if err != nil {
		return MitigationEvaluationReport{}, err
	}
	var applyReport *MitigationApplyReport
	if strings.TrimSpace(applyReportPath) != "" {
		loaded, err := LoadMitigationApplyReportJSON(applyReportPath)
		if err != nil {
			return MitigationEvaluationReport{}, err
		}
		applyReport = &loaded
	}
	before, err := LoadDetectionPrecisionReport(beforeEventsPath, beforeFlowsPath, beforeObservationsPath, beforeInventoryPath)
	if err != nil {
		return MitigationEvaluationReport{}, fmt.Errorf("load before precision report: %w", err)
	}
	after, err := LoadDetectionPrecisionReport(afterEventsPath, afterFlowsPath, afterObservationsPath, afterInventoryPath)
	if err != nil {
		return MitigationEvaluationReport{}, fmt.Errorf("load after precision report: %w", err)
	}
	beforeFlows, err := LoadFlows(beforeFlowsPath)
	if err != nil {
		return MitigationEvaluationReport{}, fmt.Errorf("load before flows: %w", err)
	}
	afterFlows, err := LoadFlows(afterFlowsPath)
	if err != nil {
		return MitigationEvaluationReport{}, fmt.Errorf("load after flows: %w", err)
	}
	report := BuildMitigationEvaluationReportWithApply(plan, applyReport, before, after, beforeFlows, afterFlows)
	report.Source = MitigationEvaluationSources{
		Plan:               planPath,
		ApplyReport:        applyReportPath,
		BeforeEvents:       beforeEventsPath,
		BeforeFlows:        beforeFlowsPath,
		BeforeObservations: beforeObservationsPath,
		BeforeInventory:    beforeInventoryPath,
		AfterEvents:        afterEventsPath,
		AfterFlows:         afterFlowsPath,
		AfterObservations:  afterObservationsPath,
		AfterInventory:     afterInventoryPath,
	}
	return report, nil
}

func LoadMitigationApplyReportJSON(path string) (MitigationApplyReport, error) {
	if strings.TrimSpace(path) == "" {
		return MitigationApplyReport{}, fmt.Errorf("mitigation apply report path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return MitigationApplyReport{}, fmt.Errorf("read %s: %w", path, err)
	}
	var report MitigationApplyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return MitigationApplyReport{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return report, nil
}

func LoadMitigationPlanJSON(path string) (MitigationPlan, error) {
	if strings.TrimSpace(path) == "" {
		return MitigationPlan{}, fmt.Errorf("mitigation plan path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return MitigationPlan{}, fmt.Errorf("read %s: %w", path, err)
	}
	var plan MitigationPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return MitigationPlan{}, fmt.Errorf("decode %s: %w", path, err)
	}
	return plan, nil
}

func BuildMitigationEvaluationReport(plan MitigationPlan, before, after DetectionPrecisionReport, beforeFlows, afterFlows []FlowRecord) MitigationEvaluationReport {
	return BuildMitigationEvaluationReportWithApply(plan, nil, before, after, beforeFlows, afterFlows)
}

func BuildMitigationEvaluationReportWithApply(plan MitigationPlan, applyReport *MitigationApplyReport, before, after DetectionPrecisionReport, beforeFlows, afterFlows []FlowRecord) MitigationEvaluationReport {
	report := MitigationEvaluationReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Limitations: []string{
			"This evaluates passive observations before and after mitigation; it cannot prove device firmware was patched.",
			"Outcome quality depends on comparable before/after observation windows.",
			"Residual encrypted behavior may remain invisible when only metadata is available.",
		},
	}
	beforeByDevice := incidentStatsByDevice(before.Incidents)
	afterByDevice := incidentStatsByDevice(after.Incidents)
	beforeCritical := criticalFlowCountsByDevice(beforeFlows)
	afterCritical := criticalFlowCountsByDevice(afterFlows)
	beforeNormal := normalFlowCountsByDevice(plan, beforeFlows)
	afterNormal := normalFlowCountsByDevice(plan, afterFlows)
	if applyReport != nil {
		report.ApplySummary = mitigationEvaluationApplySummary(*applyReport)
	}

	for _, action := range plan.Actions {
		eval := evaluateMitigationAction(action, before.Incidents, after.Incidents, beforeByDevice[action.DeviceIP], afterByDevice[action.DeviceIP], beforeCritical[action.DeviceIP], afterCritical[action.DeviceIP])
		report.ActionOutcomes = append(report.ActionOutcomes, eval)
		addActionEvalMetrics(&report.Metrics, eval)
	}
	for deviceIP := range mitigationEvaluationDeviceSet(plan, beforeByDevice, afterByDevice, beforeCritical, afterCritical) {
		beforeStats := beforeByDevice[deviceIP]
		afterStats := afterByDevice[deviceIP]
		device := MitigationDeviceEvaluation{
			DeviceIP:             deviceIP,
			BeforeIncidentCount:  beforeStats.Count,
			AfterIncidentCount:   afterStats.Count,
			IncidentDelta:        afterStats.Count - beforeStats.Count,
			BeforeRiskScore:      beforeStats.Score,
			AfterRiskScore:       afterStats.Score,
			RiskScoreDelta:       afterStats.Score - beforeStats.Score,
			BeforeCriticalFlows:  beforeCritical[deviceIP],
			AfterCriticalFlows:   afterCritical[deviceIP],
			CriticalFlowDelta:    afterCritical[deviceIP] - beforeCritical[deviceIP],
			ContinuityAssessment: criticalFlowContinuity(beforeCritical[deviceIP], afterCritical[deviceIP]),
		}
		report.DeviceOutcomes = append(report.DeviceOutcomes, device)
	}
	sortMitigationEvaluation(report.ActionOutcomes, report.DeviceOutcomes)
	report.Metrics.BeforeIncidentCount = len(before.Incidents)
	report.Metrics.AfterIncidentCount = len(after.Incidents)
	report.Metrics.IncidentDelta = report.Metrics.AfterIncidentCount - report.Metrics.BeforeIncidentCount
	report.Metrics.BeforeRiskScore = totalIncidentScore(before.Incidents)
	report.Metrics.AfterRiskScore = totalIncidentScore(after.Incidents)
	report.Metrics.RiskScoreDelta = report.Metrics.AfterRiskScore - report.Metrics.BeforeRiskScore
	report.Metrics.CriticalFlowDelta = report.Metrics.AfterCriticalFlowCount - report.Metrics.BeforeCriticalFlowCount
	report.Metrics.CriticalFlowContinuityRisk = mitigationContinuityRisk(report.Metrics)
	report.Metrics.TargetedSignalReductionRate = targetedSignalReductionRate(report.Metrics.BeforeTargetedSignalCount, report.Metrics.AfterTargetedSignalCount)
	report.Metrics.BeforeNormalFlowCount = totalFlowCountMap(beforeNormal)
	report.Metrics.AfterNormalFlowCount = totalFlowCountMap(afterNormal)
	report.Metrics.NormalFlowDelta = report.Metrics.AfterNormalFlowCount - report.Metrics.BeforeNormalFlowCount
	report.Metrics.NormalFlowPreservationRate = preservationRate(report.Metrics.BeforeNormalFlowCount, report.Metrics.AfterNormalFlowCount)
	report.Metrics.ResidualRiskScore = report.Metrics.AfterRiskScore
	report.Metrics.FalseMitigationCount = falseMitigationCount(report.ActionOutcomes)
	report.Metrics.RollbackRequiredCount = rollbackRequiredCount(report.ActionOutcomes, applyReport)
	report.PaperMetrics = buildMitigationEvaluationPaperMetrics(report, before.Incidents, after.Incidents, applyReport)
	report.OverallOutcome = mitigationOverallOutcome(report.Metrics)
	report.PaperSummary = buildMitigationEvalPaperSummary(report)
	report.Recommendations = mitigationEvalRecommendations(report)
	return report
}

type mitigationIncidentStats struct {
	Count int
	Score int
}

func evaluateMitigationAction(action MitigationAction, beforeIncidents, afterIncidents []PrecisionIncident, beforeStats, afterStats mitigationIncidentStats, beforeCritical, afterCritical int) MitigationActionEvaluation {
	beforeTargeted := countTargetedSignals(action, beforeIncidents)
	afterTargeted := countTargetedSignals(action, afterIncidents)
	eval := MitigationActionEvaluation{
		ActionID:                  action.ID,
		IncidentID:                action.IncidentID,
		DeviceIP:                  action.DeviceIP,
		Kind:                      action.Kind,
		Status:                    action.Status,
		TargetSignals:             uniqueSortedStrings(action.RiskReductionTarget.SignalKeys),
		TargetTaxonomy:            action.RiskReductionTarget.Taxonomy,
		BeforeTargetedSignals:     beforeTargeted,
		AfterTargetedSignals:      afterTargeted,
		TargetedSignalDelta:       afterTargeted - beforeTargeted,
		BeforeDeviceIncidentCount: beforeStats.Count,
		AfterDeviceIncidentCount:  afterStats.Count,
		BeforeDeviceRiskScore:     beforeStats.Score,
		AfterDeviceRiskScore:      afterStats.Score,
		DeviceRiskScoreDelta:      afterStats.Score - beforeStats.Score,
		BeforeCriticalFlows:       beforeCritical,
		AfterCriticalFlows:        afterCritical,
		CriticalFlowDelta:         afterCritical - beforeCritical,
		EstimatedBlockedFlows:     action.Impact.EstimatedBlockedFlows,
		NormalTrafficRisk:         action.Impact.NormalTrafficRisk,
	}
	eval.Outcome, eval.OutcomeReasons = mitigationActionOutcome(action, eval)
	return eval
}

func mitigationActionOutcome(action MitigationAction, eval MitigationActionEvaluation) (string, []string) {
	reasons := []string{}
	if action.Kind == "monitor_only" {
		reasons = append(reasons, "monitor-only action does not attempt active risk reduction")
		if eval.AfterDeviceIncidentCount > eval.BeforeDeviceIncidentCount {
			reasons = append(reasons, "device incident count increased during continued observation")
			return "regressed", uniqueSortedStrings(reasons)
		}
		return "observed", uniqueSortedStrings(reasons)
	}
	if eval.BeforeTargetedSignals == 0 && eval.BeforeDeviceIncidentCount == 0 {
		reasons = append(reasons, "no before-window incident matched this action target")
		return "not_evaluable", uniqueSortedStrings(reasons)
	}
	if eval.AfterTargetedSignals == 0 && eval.BeforeTargetedSignals > 0 {
		reasons = append(reasons, "targeted signals disappeared after mitigation")
		if eval.CriticalFlowDelta < 0 {
			reasons = append(reasons, "critical DNS/DHCP/NTP or discovery flow count decreased")
			return "resolved_with_continuity_risk", uniqueSortedStrings(reasons)
		}
		return "resolved", uniqueSortedStrings(reasons)
	}
	if eval.TargetedSignalDelta < 0 || eval.DeviceRiskScoreDelta < 0 || eval.AfterDeviceIncidentCount < eval.BeforeDeviceIncidentCount {
		reasons = append(reasons, "targeted signal, incident count, or device risk score decreased")
		if eval.CriticalFlowDelta < 0 {
			reasons = append(reasons, "critical DNS/DHCP/NTP or discovery flow count decreased")
		}
		return "improved", uniqueSortedStrings(reasons)
	}
	if eval.TargetedSignalDelta > 0 || eval.DeviceRiskScoreDelta > 0 || eval.AfterDeviceIncidentCount > eval.BeforeDeviceIncidentCount {
		reasons = append(reasons, "targeted signal, incident count, or device risk score increased")
		return "regressed", uniqueSortedStrings(reasons)
	}
	reasons = append(reasons, "targeted signals and device risk were unchanged")
	return "residual", uniqueSortedStrings(reasons)
}

func countTargetedSignals(action MitigationAction, incidents []PrecisionIncident) int {
	if strings.TrimSpace(action.DeviceIP) == "" {
		return 0
	}
	keys := map[string]bool{}
	for _, key := range action.RiskReductionTarget.SignalKeys {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			keys[key] = true
		}
	}
	taxonomy := strings.ToLower(strings.TrimSpace(action.RiskReductionTarget.Taxonomy))
	var count int
	for _, incident := range incidents {
		if strings.TrimSpace(incident.DeviceIP) != action.DeviceIP {
			continue
		}
		for _, signal := range incident.Signals {
			signalKey := strings.ToLower(strings.TrimSpace(signal.Key))
			signalTaxonomy := strings.ToLower(strings.TrimSpace(firstNonEmpty(signal.Taxonomy, incident.PrimaryTaxonomy)))
			if keys[signalKey] || (taxonomy != "" && signalTaxonomy == taxonomy) {
				count++
			}
		}
	}
	return count
}

func addActionEvalMetrics(metrics *MitigationEvaluationMetrics, eval MitigationActionEvaluation) {
	metrics.ActionCount++
	metrics.EstimatedBlockedFlowsPlanned += eval.EstimatedBlockedFlows
	metrics.BeforeTargetedSignalCount += eval.BeforeTargetedSignals
	metrics.AfterTargetedSignalCount += eval.AfterTargetedSignals
	metrics.BeforeCriticalFlowCount += eval.BeforeCriticalFlows
	metrics.AfterCriticalFlowCount += eval.AfterCriticalFlows
	if eval.Kind == "monitor_only" {
		metrics.MonitorOnlyActionCount++
		return
	}
	switch eval.Outcome {
	case "not_evaluable":
		return
	case "resolved", "resolved_with_continuity_risk":
		metrics.EvaluableActionCount++
		metrics.ResolvedActionCount++
		metrics.ImprovedActionCount++
	case "improved":
		metrics.EvaluableActionCount++
		metrics.ImprovedActionCount++
	case "regressed":
		metrics.EvaluableActionCount++
		metrics.RegressedActionCount++
	default:
		metrics.EvaluableActionCount++
		metrics.ResidualActionCount++
	}
}

func incidentStatsByDevice(incidents []PrecisionIncident) map[string]mitigationIncidentStats {
	out := map[string]mitigationIncidentStats{}
	for _, incident := range incidents {
		ip := strings.TrimSpace(incident.DeviceIP)
		if ip == "" {
			continue
		}
		stats := out[ip]
		stats.Count++
		stats.Score += incident.Score
		out[ip] = stats
	}
	return out
}

func totalIncidentScore(incidents []PrecisionIncident) int {
	var score int
	for _, incident := range incidents {
		score += incident.Score
	}
	return score
}

func criticalFlowCountsByDevice(flows []FlowRecord) map[string]int {
	out := map[string]int{}
	for _, flow := range flows {
		if !isEssentialGatewayFlow(flow) {
			continue
		}
		ip := strings.TrimSpace(flow.SrcIP)
		if ip == "" {
			ip = strings.TrimSpace(flow.DstIP)
		}
		if ip != "" {
			out[ip]++
		}
	}
	return out
}

func mitigationEvaluationDeviceSet(plan MitigationPlan, before, after map[string]mitigationIncidentStats, beforeCritical, afterCritical map[string]int) map[string]bool {
	out := map[string]bool{}
	for _, action := range plan.Actions {
		if strings.TrimSpace(action.DeviceIP) != "" {
			out[action.DeviceIP] = true
		}
	}
	for ip := range before {
		out[ip] = true
	}
	for ip := range after {
		out[ip] = true
	}
	for ip := range beforeCritical {
		out[ip] = true
	}
	for ip := range afterCritical {
		out[ip] = true
	}
	return out
}

func normalFlowCountsByDevice(plan MitigationPlan, flows []FlowRecord) map[string]int {
	out := map[string]int{}
	for _, flow := range flows {
		ip := strings.TrimSpace(flow.SrcIP)
		if ip == "" {
			ip = strings.TrimSpace(flow.DstIP)
		}
		if ip == "" {
			continue
		}
		if isEssentialGatewayFlow(flow) {
			out[ip]++
			continue
		}
		if mitigationFlowTargetsAnyAction(plan, flow) {
			continue
		}
		out[ip]++
	}
	return out
}

func mitigationFlowTargetsAnyAction(plan MitigationPlan, flow FlowRecord) bool {
	for _, action := range plan.Actions {
		if strings.TrimSpace(action.DeviceIP) != "" && flow.SrcIP != action.DeviceIP && flow.DstIP != action.DeviceIP {
			continue
		}
		for _, rule := range action.FirewallRules {
			if mitigationFlowMatchesRule(flow, rule) {
				return true
			}
		}
	}
	return false
}

func mitigationFlowMatchesRule(flow FlowRecord, rule MitigationRule) bool {
	if strings.TrimSpace(rule.DeviceIP) != "" && flow.SrcIP != rule.DeviceIP && flow.DstIP != rule.DeviceIP {
		return false
	}
	if strings.TrimSpace(rule.Protocol) != "" && !strings.EqualFold(flow.Protocol, rule.Protocol) {
		return false
	}
	if rule.DstPort != 0 && flow.DstPort != rule.DstPort {
		return false
	}
	if strings.TrimSpace(rule.DstIP) != "" && flow.DstIP != rule.DstIP {
		return false
	}
	if strings.TrimSpace(rule.Domain) != "" {
		domain := strings.ToLower(strings.TrimSpace(rule.Domain))
		return strings.EqualFold(flow.Host, domain) ||
			strings.EqualFold(flow.SNI, domain) ||
			strings.EqualFold(flow.ObservedDestination, domain)
	}
	return rule.DstPort != 0 || strings.TrimSpace(rule.DstIP) != ""
}

func totalFlowCountMap(counts map[string]int) int {
	var total int
	for _, count := range counts {
		total += count
	}
	return total
}

func sortMitigationEvaluation(actions []MitigationActionEvaluation, devices []MitigationDeviceEvaluation) {
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].DeviceIP == actions[j].DeviceIP {
			return actions[i].ActionID < actions[j].ActionID
		}
		return actions[i].DeviceIP < actions[j].DeviceIP
	})
	sort.SliceStable(devices, func(i, j int) bool {
		return devices[i].DeviceIP < devices[j].DeviceIP
	})
}

func criticalFlowContinuity(before, after int) string {
	switch {
	case before == 0 && after == 0:
		return "not_observed"
	case after == 0 && before > 0:
		return "lost"
	case after < before:
		return "reduced"
	default:
		return "maintained"
	}
}

func mitigationContinuityRisk(metrics MitigationEvaluationMetrics) string {
	metrics.CriticalFlowDelta = metrics.AfterCriticalFlowCount - metrics.BeforeCriticalFlowCount
	switch {
	case metrics.BeforeCriticalFlowCount == 0 && metrics.AfterCriticalFlowCount == 0:
		return "unknown"
	case metrics.AfterCriticalFlowCount == 0 && metrics.BeforeCriticalFlowCount > 0:
		return "high"
	case metrics.CriticalFlowDelta < 0:
		return "possible"
	default:
		return "low"
	}
}

func targetedSignalReductionRate(before, after int) float64 {
	if before <= 0 {
		return 0
	}
	reduced := before - after
	if reduced < 0 {
		reduced = 0
	}
	return ratio(reduced, before)
}

func reductionRate(before, after int) float64 {
	if before <= 0 {
		return 0
	}
	reduced := before - after
	if reduced < 0 {
		reduced = 0
	}
	return ratio(reduced, before)
}

func preservationRate(before, after int) float64 {
	if before <= 0 {
		return 0
	}
	if after >= before {
		return 1
	}
	return ratio(after, before)
}

func falseMitigationCount(actions []MitigationActionEvaluation) int {
	var count int
	for _, action := range actions {
		if action.Outcome == "regressed" || action.Outcome == "resolved_with_continuity_risk" {
			count++
		}
	}
	return count
}

func rollbackRequiredCount(actions []MitigationActionEvaluation, applyReport *MitigationApplyReport) int {
	if applyReport == nil || applyReport.Status != "apply_script_generated" {
		return 0
	}
	var count int
	for _, action := range actions {
		switch action.Outcome {
		case "regressed", "resolved_with_continuity_risk":
			count++
		}
	}
	return count
}

func highRiskIncidentCount(incidents []PrecisionIncident) int {
	var count int
	for _, incident := range incidents {
		if incident.State == "risky" || incident.Severity == "HIGH" || incident.Severity == "CRITICAL" || incident.Score >= precisionHighSeverityThreshold {
			count++
		}
	}
	return count
}

func buildMitigationEvaluationPaperMetrics(report MitigationEvaluationReport, beforeIncidents, afterIncidents []PrecisionIncident, applyReport *MitigationApplyReport) MitigationEvaluationPaperMetrics {
	beforeHigh := highRiskIncidentCount(beforeIncidents)
	afterHigh := highRiskIncidentCount(afterIncidents)
	metrics := MitigationEvaluationPaperMetrics{
		IncidentReductionRate:         reductionRate(report.Metrics.BeforeIncidentCount, report.Metrics.AfterIncidentCount),
		HighRiskIncidentReductionRate: reductionRate(beforeHigh, afterHigh),
		TargetedSignalReductionRate:   report.Metrics.TargetedSignalReductionRate,
		NormalFlowPreservationRate:    report.Metrics.NormalFlowPreservationRate,
		CriticalFlowPreservationRate:  preservationRate(report.Metrics.BeforeCriticalFlowCount, report.Metrics.AfterCriticalFlowCount),
		FalseMitigationRate:           ratio(report.Metrics.FalseMitigationCount, report.Metrics.EvaluableActionCount),
		RollbackRequiredCount:         report.Metrics.RollbackRequiredCount,
		ResidualRiskScore:             report.Metrics.ResidualRiskScore,
		BeforeHighRiskIncidentCount:   beforeHigh,
		AfterHighRiskIncidentCount:    afterHigh,
		EstimatedBlockedFlowsPlanned:  report.Metrics.EstimatedBlockedFlowsPlanned,
		ObservedNormalFlowDelta:       report.Metrics.NormalFlowDelta,
	}
	if applyReport != nil {
		metrics.ApplyWasExplicit = applyReport.ExplicitApply
		metrics.ApplyWasBlocked = strings.HasPrefix(applyReport.Status, "blocked")
	}
	return metrics
}

func mitigationEvaluationApplySummary(report MitigationApplyReport) *MitigationEvaluationApplySummary {
	return &MitigationEvaluationApplySummary{
		Status:                report.Status,
		Mode:                  report.Mode,
		ExplicitApply:         report.ExplicitApply,
		DryRun:                report.DryRun,
		ManagedRuleCount:      len(report.ManagedRules),
		PartialApplyDetection: report.Metrics.PartialApplyDetection,
		BlockingIssues:        append([]string{}, report.BlockingIssues...),
		RollbackScriptPath:    report.RollbackPath,
		ApplyScriptPath:       report.ApplyScriptPath,
	}
}

func mitigationOverallOutcome(metrics MitigationEvaluationMetrics) string {
	switch {
	case metrics.EvaluableActionCount == 0:
		return "not_evaluable"
	case metrics.RollbackRequiredCount > 0:
		return "rollback_recommended"
	case metrics.CriticalFlowContinuityRisk == "high":
		return "mixed_or_regressed"
	case metrics.RegressedActionCount > 0:
		return "mixed_or_regressed"
	case metrics.ResolvedActionCount == metrics.EvaluableActionCount:
		return "resolved"
	case metrics.ImprovedActionCount > 0:
		return "improved"
	default:
		return "residual_risk"
	}
}

func buildMitigationEvalPaperSummary(report MitigationEvaluationReport) MitigationEvalPaperSummary {
	missing := []string{}
	if report.Metrics.EvaluableActionCount == 0 {
		missing = append(missing, "no active mitigation action had before-window evidence that could be evaluated")
	}
	if report.Metrics.BeforeCriticalFlowCount == 0 && report.Metrics.AfterCriticalFlowCount == 0 {
		missing = append(missing, "critical DNS/DHCP/NTP or discovery continuity was not observable in the compared windows")
	}
	if report.Metrics.AfterTargetedSignalCount > 0 {
		missing = append(missing, "some targeted signals remained after mitigation")
	}
	if report.ApplySummary == nil {
		missing = append(missing, "apply report was not provided; evaluation cannot distinguish dry-run from generated apply execution artifacts")
	}
	return MitigationEvalPaperSummary{
		Claim: "Rule-based virtual patches can be evaluated by comparing targeted incident signals and critical normal traffic before and after mitigation.",
		SupportedClaims: []string{
			"each mitigation action is evaluated against its target signal set or taxonomy",
			"risk reduction is measured with before/after targeted signal counts and device risk score deltas",
			"normal-operation preservation is approximated with DNS/DHCP/NTP and discovery-flow continuity",
			"normal-flow preservation and false mitigation rate are exported as paper metrics",
			"rollback-required count is derived from regressed or continuity-risk outcomes after explicit apply",
			"residual and regressed outcomes are separated from resolved outcomes",
		},
		MissingEvidence: missing,
		TableColumns: []string{
			"action_id",
			"device_ip",
			"kind",
			"before_targeted_signals",
			"after_targeted_signals",
			"targeted_signal_delta",
			"device_risk_score_delta",
			"critical_flow_delta",
			"normal_flow_preservation_rate",
			"rollback_required_count",
			"outcome",
		},
		PrimaryOutcomeMetric: "targeted_signal_reduction_rate",
	}
}

func mitigationEvalRecommendations(report MitigationEvaluationReport) []string {
	recs := []string{}
	if report.Metrics.EvaluableActionCount == 0 && report.Metrics.ActionCount > 0 {
		recs = append(recs, "Use comparable before/after windows containing the original targeted incident signals.")
	}
	if report.Metrics.RegressedActionCount > 0 {
		recs = append(recs, "Inspect regressed actions before claiming mitigation effectiveness.")
	}
	if report.Metrics.ResidualActionCount > 0 {
		recs = append(recs, "Residual actions may need narrower rules, longer observation, or a stronger reviewed mitigation.")
	}
	if report.Metrics.CriticalFlowContinuityRisk == "high" || report.Metrics.CriticalFlowContinuityRisk == "possible" {
		recs = append(recs, "Review critical-flow continuity; mitigation may have affected DNS/DHCP/NTP or discovery behavior.")
	}
	if report.Metrics.RollbackRequiredCount > 0 {
		recs = append(recs, "Rollback is recommended for actions with regression or critical-flow continuity risk.")
	}
	if report.ApplySummary == nil {
		recs = append(recs, "Provide mitigation_apply_report.json to bind before/after evaluation to the apply safety record.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Report targeted signal reduction alongside critical-flow continuity for the experiment.")
	}
	return recs
}
