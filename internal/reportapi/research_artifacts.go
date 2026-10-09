package reportapi

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ResearchRunManifest struct {
	GeneratedAt     string                `json:"generated_at"`
	Scenario        string                `json:"scenario"`
	Sources         ResearchReportSources `json:"sources"`
	Artifacts       []ResearchArtifact    `json:"artifacts"`
	Reproducibility []string              `json:"reproducibility"`
	Limitations     []string              `json:"limitations"`
}

type ResearchArtifact struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
}

func BuildResearchRunManifest(report ResearchReport, scenarioPath string, artifacts []ResearchArtifact) ResearchRunManifest {
	sort.SliceStable(artifacts, func(i, j int) bool {
		return artifacts[i].Path < artifacts[j].Path
	})
	return ResearchRunManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Scenario:    scenarioPath,
		Sources:     report.Source,
		Artifacts:   artifacts,
		Reproducibility: []string{
			"Keep source JSON/JSONL files together with this manifest.",
			"Run Quarant commands with the same scenario paths and observation windows.",
			"Use the generated CSV and LaTeX tables directly for paper figures and tables.",
			"Report missing_evidence and threats_to_validity alongside effectiveness metrics.",
		},
		Limitations: report.ThreatsToValidity,
	}
}

func ResearchScenarioYAML(report ResearchReport) string {
	var b strings.Builder
	b.WriteString("experiment:\n")
	b.WriteString("  name: quarant_rule_based_virtual_patch\n")
	b.WriteString("  generated_at: " + yamlQuote(report.GeneratedAt) + "\n")
	b.WriteString("  research_question: " + yamlQuote(report.ResearchQuestion) + "\n")
	b.WriteString("  claim: " + yamlQuote(report.Claim) + "\n")
	b.WriteString("sources:\n")
	b.WriteString("  precision_report: " + yamlQuote(report.Source.PrecisionReport) + "\n")
	b.WriteString("  precision_eval_report: " + yamlQuote(report.Source.PrecisionEvalReport) + "\n")
	b.WriteString("  mitigation_plan: " + yamlQuote(report.Source.MitigationPlan) + "\n")
	b.WriteString("  mitigation_eval_report: " + yamlQuote(report.Source.MitigationEvalReport) + "\n")
	b.WriteString("metrics:\n")
	b.WriteString(fmt.Sprintf("  incident_count: %d\n", report.Metrics.IncidentCount))
	b.WriteString(fmt.Sprintf("  mitigation_action_count: %d\n", report.Metrics.MitigationActionCount))
	b.WriteString(fmt.Sprintf("  incident_reduction_rate: %.3f\n", report.Metrics.IncidentReductionRate))
	b.WriteString(fmt.Sprintf("  targeted_signal_reduction_rate: %.3f\n", report.Metrics.TargetedSignalReductionRate))
	b.WriteString(fmt.Sprintf("  normal_flow_preservation_rate: %.3f\n", report.Metrics.NormalFlowPreservationRate))
	b.WriteString(fmt.Sprintf("  false_mitigation_rate: %.3f\n", report.Metrics.FalseMitigationRate))
	b.WriteString(fmt.Sprintf("  rollback_required_count: %d\n", report.Metrics.RollbackRequiredCount))
	b.WriteString("stages:\n")
	for _, stage := range report.ExperimentStages {
		b.WriteString("  - name: " + yamlQuote(stage.Name) + "\n")
		b.WriteString("    status: " + yamlQuote(stage.Status) + "\n")
		if len(stage.Evidence) > 0 {
			b.WriteString("    evidence:\n")
			for _, item := range stage.Evidence {
				b.WriteString("      - " + yamlQuote(item) + "\n")
			}
		}
		if len(stage.Gaps) > 0 {
			b.WriteString("    gaps:\n")
			for _, item := range stage.Gaps {
				b.WriteString("      - " + yamlQuote(item) + "\n")
			}
		}
	}
	return b.String()
}

func ResearchDeviceListCSV(report ResearchReport) string {
	rowsByDevice := map[string]ResearchTableRow{}
	for _, row := range report.Tables.MitigationSummary {
		ip := row["device_ip"]
		if ip == "" {
			continue
		}
		device := ensureResearchDeviceRow(rowsByDevice, ip)
		device["mitigation_actions"] = incrementStringInt(device["mitigation_actions"])
		device["planned_action_kinds"] = appendUniqueCSVValue(device["planned_action_kinds"], row["kind"])
		device["normal_traffic_risk"] = appendUniqueCSVValue(device["normal_traffic_risk"], row["normal_traffic_risk"])
	}
	for _, row := range report.Tables.MitigationOutcomes {
		ip := row["device_ip"]
		if ip == "" {
			continue
		}
		device := ensureResearchDeviceRow(rowsByDevice, ip)
		device["evaluated_actions"] = incrementStringInt(device["evaluated_actions"])
		device["outcomes"] = appendUniqueCSVValue(device["outcomes"], row["outcome"])
		device["last_device_risk_score_delta"] = row["device_risk_score_delta"]
	}
	for _, row := range report.Tables.NormalTrafficContinuity {
		ip := row["device_ip"]
		if ip == "" {
			continue
		}
		device := ensureResearchDeviceRow(rowsByDevice, ip)
		device["continuity_assessment"] = row["continuity_assessment"]
		device["critical_flow_delta"] = row["critical_flow_delta"]
		device["incident_delta"] = row["incident_delta"]
	}
	rows := make([]ResearchTableRow, 0, len(rowsByDevice))
	for _, row := range rowsByDevice {
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return rows[i]["device_ip"] < rows[j]["device_ip"]
	})
	return researchRowsCSV(rows)
}

func ResearchReportLaTeXTables(report ResearchReport) map[string]string {
	return map[string]string{
		"metrics.tex": latexTable("Key Metrics", []ResearchTableRow{
			{"metric": "incident_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.IncidentReductionRate)},
			{"metric": "targeted_signal_reduction_rate", "value": fmt.Sprintf("%.3f", report.Metrics.TargetedSignalReductionRate)},
			{"metric": "normal_flow_preservation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.NormalFlowPreservationRate)},
			{"metric": "false_mitigation_rate", "value": fmt.Sprintf("%.3f", report.Metrics.FalseMitigationRate)},
			{"metric": "rollback_required_count", "value": fmt.Sprintf("%d", report.Metrics.RollbackRequiredCount)},
			{"metric": "residual_risk_score", "value": fmt.Sprintf("%d", report.Metrics.ResidualRiskScore)},
		}),
		"mitigation_outcomes.tex":       latexTable("Mitigation Outcomes", report.Tables.MitigationOutcomes),
		"normal_traffic_continuity.tex": latexTable("Normal Traffic Continuity", report.Tables.NormalTrafficContinuity),
	}
}

func ResearchReportFiguresSVG(report ResearchReport) map[string]string {
	return map[string]string{
		"risk_reduction.svg": researchBarFigure("Risk Reduction", []ResearchFigureBar{
			{Label: "Incident", Value: report.Metrics.IncidentReductionRate},
			{Label: "High risk", Value: report.Metrics.HighRiskIncidentReductionRate},
			{Label: "Targeted", Value: report.Metrics.TargetedSignalReductionRate},
		}),
		"traffic_safety.svg": researchBarFigure("Traffic Safety", []ResearchFigureBar{
			{Label: "Normal", Value: report.Metrics.NormalFlowPreservationRate},
			{Label: "Critical", Value: report.Metrics.CriticalFlowPreservationRate},
			{Label: "1 - false", Value: 1 - report.Metrics.FalseMitigationRate},
		}),
		"experiment_counts.svg": researchCountFigure(report),
	}
}

func ResearchPackageREADME(report ResearchReport) string {
	var b strings.Builder
	b.WriteString("# Quarant Reproducibility Package\n\n")
	b.WriteString(report.ExecutiveSummary)
	b.WriteString("\n\n")
	b.WriteString("## Contents\n\n")
	b.WriteString("- `experiment_scenario.yaml`: experiment definition and source paths\n")
	b.WriteString("- `run_manifest.json`: generated artifact inventory\n")
	b.WriteString("- `research_report.json` and `research_report.md`: integrated research report\n")
	b.WriteString("- `tables/`: CSV tables for paper analysis\n")
	b.WriteString("- `latex/`: LaTeX table snippets\n")
	b.WriteString("- `figures/`: SVG figures generated from report metrics\n")
	b.WriteString("- `device_list.csv`: device-level summary\n\n")
	b.WriteString("## Reproduction\n\n")
	b.WriteString("1. Keep the source paths listed in `experiment_scenario.yaml` available.\n")
	b.WriteString("2. Re-run the Quarant phase commands using the same before/after windows.\n")
	b.WriteString("3. Compare regenerated tables with the files in this package.\n\n")
	b.WriteString("## Limitations\n\n")
	for _, item := range report.ThreatsToValidity {
		b.WriteString("- " + item + "\n")
	}
	return b.String()
}

type ResearchFigureBar struct {
	Label string
	Value float64
}

func ensureResearchDeviceRow(rows map[string]ResearchTableRow, ip string) ResearchTableRow {
	row := rows[ip]
	if row == nil {
		row = ResearchTableRow{
			"device_ip":                    ip,
			"mitigation_actions":           "0",
			"evaluated_actions":            "0",
			"planned_action_kinds":         "",
			"normal_traffic_risk":          "",
			"outcomes":                     "",
			"continuity_assessment":        "",
			"critical_flow_delta":          "",
			"incident_delta":               "",
			"last_device_risk_score_delta": "",
		}
		rows[ip] = row
	}
	return row
}

func incrementStringInt(value string) string {
	var n int
	_, _ = fmt.Sscanf(value, "%d", &n)
	return fmt.Sprintf("%d", n+1)
}

func appendUniqueCSVValue(existing, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return existing
	}
	parts := strings.Split(existing, ";")
	for _, part := range parts {
		if strings.TrimSpace(part) == value {
			return existing
		}
	}
	if strings.TrimSpace(existing) == "" {
		return value
	}
	return existing + ";" + value
}

func yamlQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}

func latexTable(caption string, rows []ResearchTableRow) string {
	if len(rows) == 0 {
		return ""
	}
	columns := researchTableColumns(rows)
	var b strings.Builder
	b.WriteString("\\begin{table}[t]\n\\centering\n\\small\n")
	b.WriteString("\\begin{tabular}{")
	for range columns {
		b.WriteString("l")
	}
	b.WriteString("}\n\\hline\n")
	for i, col := range columns {
		if i > 0 {
			b.WriteString(" & ")
		}
		b.WriteString(latexEscape(col))
	}
	b.WriteString(" \\\\\n\\hline\n")
	for _, row := range rows {
		for i, col := range columns {
			if i > 0 {
				b.WriteString(" & ")
			}
			b.WriteString(latexEscape(row[col]))
		}
		b.WriteString(" \\\\\n")
	}
	b.WriteString("\\hline\n\\end{tabular}\n")
	b.WriteString("\\caption{" + latexEscape(caption) + "}\n")
	b.WriteString("\\end{table}\n")
	return b.String()
}

func latexEscape(value string) string {
	replacer := strings.NewReplacer(
		`\`, `\textbackslash{}`,
		`&`, `\&`,
		`%`, `\%`,
		`$`, `\$`,
		`#`, `\#`,
		`_`, `\_`,
		`{`, `\{`,
		`}`, `\}`,
		`~`, `\textasciitilde{}`,
		`^`, `\textasciicircum{}`,
	)
	return replacer.Replace(value)
}

func researchBarFigure(title string, bars []ResearchFigureBar) string {
	width := 640
	height := 260
	left := 150
	barHeight := 34
	gap := 22
	var b strings.Builder
	b.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">`, width, height, width, height))
	b.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	b.WriteString(fmt.Sprintf(`<text x="24" y="34" font-family="Arial" font-size="20" font-weight="700">%s</text>`, svgEscape(title)))
	for i, bar := range bars {
		y := 68 + i*(barHeight+gap)
		value := clamp01(bar.Value)
		barWidth := int(value * 420)
		b.WriteString(fmt.Sprintf(`<text x="24" y="%d" font-family="Arial" font-size="14">%s</text>`, y+22, svgEscape(bar.Label)))
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="420" height="%d" fill="#e5e7eb"/>`, left, y, barHeight))
		b.WriteString(fmt.Sprintf(`<rect x="%d" y="%d" width="%d" height="%d" fill="#2563eb"/>`, left, y, barWidth, barHeight))
		b.WriteString(fmt.Sprintf(`<text x="%d" y="%d" font-family="Arial" font-size="14">%.3f</text>`, left+430, y+22, value))
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func researchCountFigure(report ResearchReport) string {
	maxValue := researchMaxInt(1, report.Metrics.IncidentCount, report.Metrics.MitigationActionCount, report.Metrics.EstimatedBlockedFlows, report.Metrics.ResidualRiskScore)
	return researchBarFigure("Experiment Counts", []ResearchFigureBar{
		{Label: "Incidents", Value: float64(report.Metrics.IncidentCount) / float64(maxValue)},
		{Label: "Actions", Value: float64(report.Metrics.MitigationActionCount) / float64(maxValue)},
		{Label: "Blocked flows", Value: float64(report.Metrics.EstimatedBlockedFlows) / float64(maxValue)},
		{Label: "Residual risk", Value: float64(report.Metrics.ResidualRiskScore) / float64(maxValue)},
	})
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func researchMaxInt(values ...int) int {
	max := values[0]
	for _, value := range values[1:] {
		if value > max {
			max = value
		}
	}
	return max
}

func svgEscape(value string) string {
	replacer := strings.NewReplacer(`&`, `&amp;`, `<`, `&lt;`, `>`, `&gt;`, `"`, `&quot;`)
	return replacer.Replace(value)
}

func PackageArtifactPath(root, name string) string {
	if strings.TrimSpace(root) == "" {
		return name
	}
	return filepath.Join(root, name)
}
