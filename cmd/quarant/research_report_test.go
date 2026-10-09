package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunResearchReportWritesJSONAndMarkdown(t *testing.T) {
	dir := t.TempDir()
	precisionPath := filepath.Join(dir, "precision_report.json")
	precisionEvalPath := filepath.Join(dir, "precision_eval_report.json")
	mitigationPath := filepath.Join(dir, "mitigation_plan.json")
	mitigationEvalPath := filepath.Join(dir, "mitigation_eval_report.json")
	reportPath := filepath.Join(dir, "research_report.json")
	markdownPath := filepath.Join(dir, "research_report.md")
	csvDir := filepath.Join(dir, "tables")
	scenarioPath := filepath.Join(dir, "experiment_scenario.yaml")
	manifestPath := filepath.Join(dir, "run_manifest.json")
	deviceListPath := filepath.Join(dir, "device_list.csv")
	latexDir := filepath.Join(dir, "latex")
	figuresDir := filepath.Join(dir, "figures")
	packageDir := filepath.Join(dir, "paper_package")

	writeTestFile(t, precisionPath, `{
		"metrics": {
			"incident_count": 1,
			"risky_incident_count": 1,
			"suppressed_signal_count": 2,
			"baseline_ready_device_count": 1
		},
		"evaluation_readiness": {},
		"paper_summary": {
			"research_claims_supported": ["passive observations can be promoted into incidents"]
		}
	}`)
	writeTestFile(t, precisionEvalPath, `{
		"metrics": {
			"label_coverage": 1,
			"precision": 1,
			"false_positive_rate": 0
		}
	}`)
	writeTestFile(t, mitigationPath, `{
		"metrics": {
			"action_count": 1,
			"review_required_count": 1,
			"estimated_blocked_flows": 3
		},
		"paper_summary": {
			"normal_traffic_impact_measurable": true,
			"supported_claims": ["historical flows estimate blocked communications"]
		},
		"actions": [{
			"id": "action-telnet",
			"device_ip": "192.168.50.92",
			"kind": "block_service",
			"status": "review_required",
			"risk_reduction_target": {"exposure": "insecure service"},
			"impact": {
				"estimated_blocked_flows": 3,
				"normal_traffic_risk": "possible",
				"baseline_impact": "blocks_non_baseline_observed_flows"
			}
		}]
	}`)
	writeTestFile(t, mitigationEvalPath, `{
		"overall_outcome": "resolved",
		"metrics": {
			"evaluable_action_count": 1,
			"improved_action_count": 1,
			"resolved_action_count": 1,
			"targeted_signal_reduction_rate": 1,
			"critical_flow_continuity_risk": "low"
		},
		"paper_summary": {
			"supported_claims": ["before and after targeted signals can evaluate mitigation"]
		},
		"action_outcomes": [{
			"action_id": "action-telnet",
			"device_ip": "192.168.50.92",
			"kind": "block_service",
			"before_targeted_signals": 1,
			"after_targeted_signals": 0,
			"targeted_signal_delta": -1,
			"outcome": "resolved"
		}],
		"device_outcomes": [{
			"device_ip": "192.168.50.92",
			"before_critical_flows": 1,
			"after_critical_flows": 1,
			"continuity_assessment": "maintained"
		}]
	}`)

	var out bytes.Buffer
	err := runResearchReport([]string{
		"--precision", precisionPath,
		"--precision-eval", precisionEvalPath,
		"--mitigation", mitigationPath,
		"--mitigation-eval", mitigationEvalPath,
		"--out", reportPath,
		"--markdown-out", markdownPath,
		"--csv-dir", csvDir,
		"--scenario-out", scenarioPath,
		"--manifest-out", manifestPath,
		"--device-list-out", deviceListPath,
		"--latex-dir", latexDir,
		"--figures-dir", figuresDir,
		"--package-dir", packageDir,
	}, &out)
	if err != nil {
		t.Fatalf("runResearchReport: %v", err)
	}
	if !strings.Contains(out.String(), "Research report complete") {
		t.Fatalf("output=%q, want completion", out.String())
	}
	if !strings.Contains(out.String(), "csv_tables=") {
		t.Fatalf("output=%q, want CSV table count", out.String())
	}
	if !strings.Contains(out.String(), "artifacts=") || !strings.Contains(out.String(), "package=") {
		t.Fatalf("output=%q, want artifact and package summary", out.String())
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(reportData), `"overall_outcome": "resolved"`) ||
		!strings.Contains(string(reportData), `"estimated_blocked_flows": 3`) {
		t.Fatalf("report=%s, want research metrics", reportData)
	}
	markdownData, err := os.ReadFile(markdownPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	if !strings.Contains(string(markdownData), "# Quarant Research Report") ||
		!strings.Contains(string(markdownData), "Mitigation Summary") {
		t.Fatalf("markdown=%s, want research markdown", markdownData)
	}
	metricsCSV, err := os.ReadFile(filepath.Join(csvDir, "metrics.csv"))
	if err != nil {
		t.Fatalf("read metrics csv: %v", err)
	}
	if !strings.Contains(string(metricsCSV), "estimated_blocked_flows") ||
		!strings.Contains(string(metricsCSV), "overall_outcome") {
		t.Fatalf("metrics csv=%s, want research metrics", metricsCSV)
	}
	mitigationCSV, err := os.ReadFile(filepath.Join(csvDir, "mitigation_summary.csv"))
	if err != nil {
		t.Fatalf("read mitigation csv: %v", err)
	}
	if !strings.Contains(string(mitigationCSV), "action-telnet") ||
		!strings.Contains(string(mitigationCSV), "block_service") {
		t.Fatalf("mitigation csv=%s, want mitigation table", mitigationCSV)
	}
	scenarioData, err := os.ReadFile(scenarioPath)
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}
	if !strings.Contains(string(scenarioData), "quarant_rule_based_virtual_patch") ||
		!strings.Contains(string(scenarioData), "targeted_signal_reduction_rate") {
		t.Fatalf("scenario=%s, want experiment YAML", scenarioData)
	}
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifestData), `"artifacts"`) ||
		!strings.Contains(string(manifestData), `"reproducibility"`) {
		t.Fatalf("manifest=%s, want run manifest", manifestData)
	}
	deviceListData, err := os.ReadFile(deviceListPath)
	if err != nil {
		t.Fatalf("read device list: %v", err)
	}
	if !strings.Contains(string(deviceListData), "192.168.50.92") ||
		!strings.Contains(string(deviceListData), "block_service") {
		t.Fatalf("device list=%s, want device summary", deviceListData)
	}
	latexData, err := os.ReadFile(filepath.Join(latexDir, "metrics.tex"))
	if err != nil {
		t.Fatalf("read latex metrics: %v", err)
	}
	if !strings.Contains(string(latexData), `\begin{table}`) ||
		!strings.Contains(string(latexData), "targeted\\_signal\\_reduction\\_rate") {
		t.Fatalf("latex=%s, want LaTeX table", latexData)
	}
	figureData, err := os.ReadFile(filepath.Join(figuresDir, "risk_reduction.svg"))
	if err != nil {
		t.Fatalf("read figure: %v", err)
	}
	if !strings.Contains(string(figureData), "<svg") ||
		!strings.Contains(string(figureData), "Risk Reduction") {
		t.Fatalf("figure=%s, want SVG figure", figureData)
	}
	for _, path := range []string{
		filepath.Join(packageDir, "README.md"),
		filepath.Join(packageDir, "experiment_scenario.yaml"),
		filepath.Join(packageDir, "run_manifest.json"),
		filepath.Join(packageDir, "device_list.csv"),
		filepath.Join(packageDir, "tables", "metrics.csv"),
		filepath.Join(packageDir, "latex", "metrics.tex"),
		filepath.Join(packageDir, "figures", "traffic_safety.svg"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("package artifact %s: %v", path, err)
		}
	}
}
