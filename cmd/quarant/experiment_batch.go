package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"quarant/internal/reportapi"
)

type experimentBatchConfig struct {
	Version            string                     `json:"version,omitempty"`
	TaxonomyPolicyPath string                     `json:"taxonomy_policy,omitempty"`
	Runs               []experimentBatchRunConfig `json:"runs"`
}

type experimentBatchRunConfig struct {
	ID                 string `json:"id"`
	BeforeOpenWrtDir   string `json:"before_openwrt,omitempty"`
	BeforeSuricataEVE  string `json:"before_suricata,omitempty"`
	BeforeZeekDir      string `json:"before_zeek,omitempty"`
	BeforeSnortAlerts  string `json:"before_snort,omitempty"`
	AfterOpenWrtDir    string `json:"after_openwrt,omitempty"`
	AfterSuricataEVE   string `json:"after_suricata,omitempty"`
	AfterZeekDir       string `json:"after_zeek,omitempty"`
	AfterSnortAlerts   string `json:"after_snort,omitempty"`
	BeforeNow          string `json:"before_now,omitempty"`
	AfterNow           string `json:"after_now,omitempty"`
	TaxonomyPolicyPath string `json:"taxonomy_policy,omitempty"`
	PackageDir         string `json:"package_dir,omitempty"`
}

type ExperimentBatchSummary struct {
	GeneratedAt string                       `json:"generated_at"`
	Version     string                       `json:"version"`
	Source      ExperimentBatchSummarySource `json:"source"`
	Metrics     ExperimentBatchMetrics       `json:"metrics"`
	Runs        []ExperimentBatchRunSummary  `json:"runs"`
	Warnings    []string                     `json:"warnings,omitempty"`
}

type ExperimentBatchSummarySource struct {
	Config string `json:"config"`
	OutDir string `json:"out_dir"`
}

type ExperimentBatchMetrics struct {
	RunCount          int `json:"run_count"`
	CompletedRunCount int `json:"completed_run_count"`
	FailedRunCount    int `json:"failed_run_count"`
	PassCount         int `json:"pass_count"`
	WarnCount         int `json:"warn_count"`
	FailCount         int `json:"fail_count"`
}

type ExperimentBatchRunSummary struct {
	ID                                  string   `json:"id"`
	Status                              string   `json:"status"`
	OutputDir                           string   `json:"output_dir"`
	Manifest                            string   `json:"manifest,omitempty"`
	QualityGateStatus                   string   `json:"quality_gate_status,omitempty"`
	QualityGateWarnings                 []string `json:"quality_gate_warnings,omitempty"`
	IncidentCount                       int      `json:"incident_count,omitempty"`
	MitigationActionCount               int      `json:"mitigation_action_count,omitempty"`
	AcceptedAttackEvidenceReductionRate float64  `json:"accepted_attack_evidence_reduction_rate,omitempty"`
	ExposedServiceAttemptReductionRate  float64  `json:"exposed_service_attempt_reduction_rate,omitempty"`
	IDSExposedOverlapReductionRate      float64  `json:"ids_exposed_overlap_reduction_rate,omitempty"`
	SourceCount                         int      `json:"source_count,omitempty"`
	MultiSourceServiceCount             int      `json:"multi_source_service_count,omitempty"`
	TaxonomyClassificationCoverage      float64  `json:"taxonomy_classification_coverage,omitempty"`
	TaxonomyCount                       int      `json:"taxonomy_count,omitempty"`
	Error                               string   `json:"error,omitempty"`
}

func runExperimentBatchCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("experiment batch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "experiments.yaml", "batch experiment config YAML or JSON path")
	outDir := fs.String("out", "runs/batch-001", "batch output directory")
	summaryOut := fs.String("summary-out", "", "batch summary JSON output path (default: out/batch_summary_report.json)")
	csvOut := fs.String("csv-out", "", "batch summary CSV output path (default: out/batch_summary.csv)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse experiment batch flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("experiment batch accepts flags only")
	}
	if strings.TrimSpace(*summaryOut) == "" {
		*summaryOut = filepath.Join(*outDir, "batch_summary_report.json")
	}
	if strings.TrimSpace(*csvOut) == "" {
		*csvOut = filepath.Join(*outDir, "batch_summary.csv")
	}
	summary, err := runExperimentBatch(*configPath, *outDir)
	if err != nil {
		return err
	}
	if err := writePrettyJSON(*summaryOut, summary); err != nil {
		return err
	}
	if err := writeTextFile(*csvOut, experimentBatchSummaryCSV(summary)); err != nil {
		return err
	}
	fmt.Fprintf(out, "Experiment batch complete: runs=%d completed=%d failed=%d pass=%d warn=%d fail=%d summary=%s csv=%s\n",
		summary.Metrics.RunCount,
		summary.Metrics.CompletedRunCount,
		summary.Metrics.FailedRunCount,
		summary.Metrics.PassCount,
		summary.Metrics.WarnCount,
		summary.Metrics.FailCount,
		*summaryOut,
		*csvOut,
	)
	return nil
}

func runExperimentBatch(configPath, outDir string) (ExperimentBatchSummary, error) {
	cfg, err := loadExperimentBatchConfig(configPath)
	if err != nil {
		return ExperimentBatchSummary{}, err
	}
	if len(cfg.Runs) == 0 {
		return ExperimentBatchSummary{}, fmt.Errorf("batch config requires at least one run")
	}
	if strings.TrimSpace(outDir) == "" {
		return ExperimentBatchSummary{}, fmt.Errorf("--out is required")
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return ExperimentBatchSummary{}, err
	}
	summary := ExperimentBatchSummary{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "experiment-batch-summary-v1",
		Source:      ExperimentBatchSummarySource{Config: configPath, OutDir: outDir},
	}
	for i, run := range cfg.Runs {
		runID := strings.TrimSpace(run.ID)
		if runID == "" {
			runID = fmt.Sprintf("run-%03d", i+1)
		}
		runOutDir := filepath.Join(outDir, safePathName(runID))
		runCfg, err := experimentRunConfigFromBatch(run, cfg, runOutDir)
		if err != nil {
			summary.Runs = append(summary.Runs, ExperimentBatchRunSummary{ID: runID, Status: "failed", OutputDir: runOutDir, Error: err.Error()})
			continue
		}
		manifest, err := runExperimentRun(runCfg)
		if err != nil {
			summary.Runs = append(summary.Runs, ExperimentBatchRunSummary{ID: runID, Status: "failed", OutputDir: runOutDir, Error: err.Error()})
			continue
		}
		runSummary := buildExperimentBatchRunSummary(runID, runOutDir, manifest)
		summary.Runs = append(summary.Runs, runSummary)
	}
	summary.Metrics = buildExperimentBatchMetrics(summary.Runs)
	sort.SliceStable(summary.Runs, func(i, j int) bool { return summary.Runs[i].ID < summary.Runs[j].ID })
	return summary, nil
}

func loadExperimentBatchConfig(path string) (experimentBatchConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return experimentBatchConfig{}, fmt.Errorf("read batch config %s: %w", path, err)
	}
	var cfg experimentBatchConfig
	if err := json.Unmarshal(data, &cfg); err == nil && len(cfg.Runs) > 0 {
		return cfg, nil
	}
	cfg, err = parseExperimentBatchYAML(string(data))
	if err != nil {
		return experimentBatchConfig{}, fmt.Errorf("parse batch config %s: %w", path, err)
	}
	return cfg, nil
}

func parseExperimentBatchYAML(data string) (experimentBatchConfig, error) {
	cfg := experimentBatchConfig{}
	var current *experimentBatchRunConfig
	for lineNo, rawLine := range strings.Split(data, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "runs:" {
			continue
		}
		if strings.HasPrefix(line, "- ") {
			cfg.Runs = append(cfg.Runs, experimentBatchRunConfig{})
			current = &cfg.Runs[len(cfg.Runs)-1]
			line = strings.TrimSpace(strings.TrimPrefix(line, "- "))
			if line == "" {
				continue
			}
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return experimentBatchConfig{}, fmt.Errorf("line %d: expected key: value", lineNo+1)
		}
		key = strings.TrimSpace(key)
		value = trimYAMLScalar(value)
		if current == nil && key != "version" && key != "taxonomy_policy" {
			return experimentBatchConfig{}, fmt.Errorf("line %d: run field before runs list", lineNo+1)
		}
		if current == nil {
			switch key {
			case "version":
				cfg.Version = value
			case "taxonomy_policy":
				cfg.TaxonomyPolicyPath = value
			}
			continue
		}
		setExperimentBatchRunField(current, key, value)
	}
	if len(cfg.Runs) == 0 {
		return experimentBatchConfig{}, fmt.Errorf("runs list is empty")
	}
	return cfg, nil
}

func trimYAMLScalar(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return value
}

func setExperimentBatchRunField(run *experimentBatchRunConfig, key, value string) {
	switch key {
	case "id":
		run.ID = value
	case "before_openwrt":
		run.BeforeOpenWrtDir = value
	case "before_suricata":
		run.BeforeSuricataEVE = value
	case "before_zeek":
		run.BeforeZeekDir = value
	case "before_snort":
		run.BeforeSnortAlerts = value
	case "after_openwrt":
		run.AfterOpenWrtDir = value
	case "after_suricata":
		run.AfterSuricataEVE = value
	case "after_zeek":
		run.AfterZeekDir = value
	case "after_snort":
		run.AfterSnortAlerts = value
	case "before_now":
		run.BeforeNow = value
	case "after_now":
		run.AfterNow = value
	case "taxonomy_policy":
		run.TaxonomyPolicyPath = value
	case "package_dir":
		run.PackageDir = value
	}
}

func experimentRunConfigFromBatch(run experimentBatchRunConfig, batch experimentBatchConfig, outDir string) (experimentRunConfig, error) {
	cfg := experimentRunConfig{
		BeforeOpenWrtDir:   run.BeforeOpenWrtDir,
		BeforeSuricataEVE:  run.BeforeSuricataEVE,
		BeforeZeekDir:      run.BeforeZeekDir,
		BeforeSnortAlerts:  run.BeforeSnortAlerts,
		AfterOpenWrtDir:    run.AfterOpenWrtDir,
		AfterSuricataEVE:   run.AfterSuricataEVE,
		AfterZeekDir:       run.AfterZeekDir,
		AfterSnortAlerts:   run.AfterSnortAlerts,
		OutDir:             outDir,
		PackageDir:         firstNonEmptyString(run.PackageDir, filepath.Join(outDir, "package")),
		TaxonomyPolicyPath: firstNonEmptyString(run.TaxonomyPolicyPath, batch.TaxonomyPolicyPath),
	}
	var err error
	if strings.TrimSpace(run.BeforeNow) != "" {
		cfg.BeforeNow, err = time.Parse(time.RFC3339, strings.TrimSpace(run.BeforeNow))
		if err != nil {
			return experimentRunConfig{}, fmt.Errorf("parse before_now for %s: %w", run.ID, err)
		}
	}
	if strings.TrimSpace(run.AfterNow) != "" {
		cfg.AfterNow, err = time.Parse(time.RFC3339, strings.TrimSpace(run.AfterNow))
		if err != nil {
			return experimentRunConfig{}, fmt.Errorf("parse after_now for %s: %w", run.ID, err)
		}
	}
	return cfg, nil
}

func buildExperimentBatchRunSummary(id, outDir string, manifest ExperimentRunManifest) ExperimentBatchRunSummary {
	run := ExperimentBatchRunSummary{
		ID:                    id,
		Status:                "complete",
		OutputDir:             outDir,
		Manifest:              manifest.Outputs.ExperimentManifest,
		IncidentCount:         manifest.Metrics.IncidentCount,
		MitigationActionCount: manifest.Metrics.MitigationActionCount,
	}
	if manifest.Outputs.MitigationEval != "" {
		var report reportapi.MitigationEvaluationReport
		if ok, err := readOptionalJSONFileLocal(manifest.Outputs.MitigationEval, &report); err == nil && ok {
			run.AcceptedAttackEvidenceReductionRate = report.Metrics.AcceptedAttackEvidenceReductionRate
			run.ExposedServiceAttemptReductionRate = report.Metrics.ExposedServiceAttemptReductionRate
			run.IDSExposedOverlapReductionRate = report.Metrics.IDSExposedOverlapReductionRate
		}
	}
	if manifest.Outputs.SourceCoverage != "" {
		var report reportapi.SourceCoverageReport
		if ok, err := readOptionalJSONFileLocal(manifest.Outputs.SourceCoverage, &report); err == nil && ok {
			run.SourceCount = report.Metrics.SourceCount
			run.MultiSourceServiceCount = report.Metrics.MultiSourceServiceCount
		}
	}
	if manifest.Outputs.TaxonomyCoverage != "" {
		var report reportapi.TaxonomyCoverageReport
		if ok, err := readOptionalJSONFileLocal(manifest.Outputs.TaxonomyCoverage, &report); err == nil && ok {
			run.TaxonomyClassificationCoverage = report.Metrics.ClassificationCoverage
			run.TaxonomyCount = report.Metrics.TaxonomyCount
		}
	}
	if manifest.Outputs.QualityGate != "" {
		var report reportapi.QualityGateReport
		if ok, err := readOptionalJSONFileLocal(manifest.Outputs.QualityGate, &report); err == nil && ok {
			run.QualityGateStatus = report.OverallStatus
			for _, check := range report.Checks {
				if check.Status != "pass" {
					run.QualityGateWarnings = append(run.QualityGateWarnings, check.Key+": "+check.Summary)
				}
			}
		}
	}
	return run
}

func buildExperimentBatchMetrics(runs []ExperimentBatchRunSummary) ExperimentBatchMetrics {
	metrics := ExperimentBatchMetrics{RunCount: len(runs)}
	for _, run := range runs {
		if run.Status == "complete" {
			metrics.CompletedRunCount++
		} else {
			metrics.FailedRunCount++
		}
		switch run.QualityGateStatus {
		case "pass":
			metrics.PassCount++
		case "fail":
			metrics.FailCount++
		default:
			if run.Status == "complete" {
				metrics.WarnCount++
			}
		}
	}
	return metrics
}

func experimentBatchSummaryCSV(summary ExperimentBatchSummary) string {
	var b strings.Builder
	writer := csv.NewWriter(&b)
	columns := []string{
		"id",
		"status",
		"quality_gate_status",
		"incident_count",
		"mitigation_action_count",
		"accepted_attack_evidence_reduction_rate",
		"exposed_service_attempt_reduction_rate",
		"ids_exposed_overlap_reduction_rate",
		"source_count",
		"multi_source_service_count",
		"taxonomy_classification_coverage",
		"taxonomy_count",
		"warnings",
		"output_dir",
	}
	_ = writer.Write(columns)
	for _, run := range summary.Runs {
		_ = writer.Write([]string{
			run.ID,
			run.Status,
			run.QualityGateStatus,
			strconv.Itoa(run.IncidentCount),
			strconv.Itoa(run.MitigationActionCount),
			fmt.Sprintf("%.3f", run.AcceptedAttackEvidenceReductionRate),
			fmt.Sprintf("%.3f", run.ExposedServiceAttemptReductionRate),
			fmt.Sprintf("%.3f", run.IDSExposedOverlapReductionRate),
			strconv.Itoa(run.SourceCount),
			strconv.Itoa(run.MultiSourceServiceCount),
			fmt.Sprintf("%.3f", run.TaxonomyClassificationCoverage),
			strconv.Itoa(run.TaxonomyCount),
			strings.Join(run.QualityGateWarnings, "; "),
			run.OutputDir,
		})
	}
	writer.Flush()
	return b.String()
}

func experimentBatchQualityFigureSVG(summary ExperimentBatchSummary) string {
	maxValue := researchMaxIntLocal(1, summary.Metrics.PassCount, summary.Metrics.WarnCount, summary.Metrics.FailCount, summary.Metrics.CompletedRunCount, summary.Metrics.FailedRunCount)
	bars := []reportapi.ResearchFigureBar{
		{Label: "Pass", Value: float64(summary.Metrics.PassCount) / float64(maxValue), Display: strconv.Itoa(summary.Metrics.PassCount)},
		{Label: "Warn", Value: float64(summary.Metrics.WarnCount) / float64(maxValue), Display: strconv.Itoa(summary.Metrics.WarnCount)},
		{Label: "Fail", Value: float64(summary.Metrics.FailCount) / float64(maxValue), Display: strconv.Itoa(summary.Metrics.FailCount)},
		{Label: "Completed", Value: float64(summary.Metrics.CompletedRunCount) / float64(maxValue), Display: strconv.Itoa(summary.Metrics.CompletedRunCount)},
		{Label: "Run errors", Value: float64(summary.Metrics.FailedRunCount) / float64(maxValue), Display: strconv.Itoa(summary.Metrics.FailedRunCount)},
	}
	for _, run := range summary.Runs {
		bars = append(bars, reportapi.ResearchFigureBar{
			Label:   run.ID,
			Value:   run.TaxonomyClassificationCoverage,
			Display: fmt.Sprintf("taxonomy %.3f", run.TaxonomyClassificationCoverage),
		})
	}
	return reportapi.SimpleBarFigureSVG("Batch Quality", bars)
}

func researchMaxIntLocal(values ...int) int {
	max := values[0]
	for _, value := range values[1:] {
		if value > max {
			max = value
		}
	}
	return max
}

func readOptionalJSONFileLocal(path string, dst any) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return false, err
	}
	return true, nil
}

func safePathName(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "run"
	}
	return out
}
