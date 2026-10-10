package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quarant/internal/reportapi"
)

type experimentRunConfig struct {
	BeforeOpenWrtDir  string
	BeforeSuricataEVE string
	BeforeZeekDir     string
	BeforeSnortAlerts string
	AfterOpenWrtDir   string
	AfterSuricataEVE  string
	AfterZeekDir      string
	AfterSnortAlerts  string
	OutDir            string
	BeforeNow         time.Time
	AfterNow          time.Time
	PackageDir        string
}

type ExperimentRunManifest struct {
	GeneratedAt string                       `json:"generated_at"`
	Version     string                       `json:"version"`
	OutputDir   string                       `json:"output_dir"`
	Steps       []ExperimentRunStep          `json:"steps"`
	Outputs     ExperimentRunOutputs         `json:"outputs"`
	Metrics     ExperimentRunManifestMetrics `json:"metrics"`
	Warnings    []string                     `json:"warnings,omitempty"`
}

type ExperimentRunStep struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Output string `json:"output,omitempty"`
}

type ExperimentRunOutputs struct {
	BeforeAssembled    string `json:"before_assembled,omitempty"`
	AfterAssembled     string `json:"after_assembled,omitempty"`
	PrecisionReport    string `json:"precision_report,omitempty"`
	Incidents          string `json:"incidents,omitempty"`
	MitigationPlan     string `json:"mitigation_plan,omitempty"`
	GatewayPlan        string `json:"gateway_backend_plan,omitempty"`
	MitigationEval     string `json:"mitigation_eval_report,omitempty"`
	ResearchReport     string `json:"research_report,omitempty"`
	ResearchMarkdown   string `json:"research_report_markdown,omitempty"`
	ResearchPackage    string `json:"research_package,omitempty"`
	SourceCoverage     string `json:"source_coverage_report,omitempty"`
	ExperimentManifest string `json:"experiment_manifest,omitempty"`
}

type ExperimentRunManifestMetrics struct {
	BeforeSourceCount     int `json:"before_source_count"`
	AfterSourceCount      int `json:"after_source_count"`
	BeforeSecurityEvents  int `json:"before_security_event_count"`
	AfterSecurityEvents   int `json:"after_security_event_count"`
	BeforeFlows           int `json:"before_flow_count"`
	AfterFlows            int `json:"after_flow_count"`
	BeforeObservations    int `json:"before_observation_count"`
	AfterObservations     int `json:"after_observation_count"`
	IncidentCount         int `json:"incident_count"`
	MitigationActionCount int `json:"mitigation_action_count"`
}

func runExperiment(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("experiment requires subcommand: run")
	}
	switch args[0] {
	case "run":
		return runExperimentRunCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown experiment subcommand %q; use run", args[0])
	}
}

func runExperimentRunCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("experiment run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := experimentRunConfig{}
	beforeNow := fs.String("before-now", "", "before OpenWrt base time, RFC3339")
	afterNow := fs.String("after-now", "", "after OpenWrt base time, RFC3339")
	fs.StringVar(&cfg.BeforeOpenWrtDir, "before-openwrt", "", "before OpenWrt raw directory")
	fs.StringVar(&cfg.BeforeSuricataEVE, "before-suricata", "", "before Suricata eve.json path")
	fs.StringVar(&cfg.BeforeZeekDir, "before-zeek", "", "before Zeek raw directory")
	fs.StringVar(&cfg.BeforeSnortAlerts, "before-snort", "", "before Snort alert log path")
	fs.StringVar(&cfg.AfterOpenWrtDir, "after-openwrt", "", "after OpenWrt raw directory")
	fs.StringVar(&cfg.AfterSuricataEVE, "after-suricata", "", "after Suricata eve.json path")
	fs.StringVar(&cfg.AfterZeekDir, "after-zeek", "", "after Zeek raw directory")
	fs.StringVar(&cfg.AfterSnortAlerts, "after-snort", "", "after Snort alert log path")
	fs.StringVar(&cfg.OutDir, "out", "runs/experiment-001", "experiment output directory")
	fs.StringVar(&cfg.PackageDir, "package-dir", "", "research package directory (default: out/package)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse experiment run flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("experiment run accepts flags only")
	}
	var err error
	if strings.TrimSpace(*beforeNow) != "" {
		cfg.BeforeNow, err = time.Parse(time.RFC3339, strings.TrimSpace(*beforeNow))
		if err != nil {
			return fmt.Errorf("parse --before-now: %w", err)
		}
	}
	if strings.TrimSpace(*afterNow) != "" {
		cfg.AfterNow, err = time.Parse(time.RFC3339, strings.TrimSpace(*afterNow))
		if err != nil {
			return fmt.Errorf("parse --after-now: %w", err)
		}
	}
	manifest, err := runExperimentRun(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Experiment run complete: incidents=%d actions=%d before_sources=%d after_sources=%d out=%s package=%s manifest=%s\n",
		manifest.Metrics.IncidentCount,
		manifest.Metrics.MitigationActionCount,
		manifest.Metrics.BeforeSourceCount,
		manifest.Metrics.AfterSourceCount,
		cfg.OutDir,
		manifest.Outputs.ResearchPackage,
		manifest.Outputs.ExperimentManifest,
	)
	return nil
}

func runExperimentRun(cfg experimentRunConfig) (ExperimentRunManifest, error) {
	if strings.TrimSpace(cfg.OutDir) == "" {
		return ExperimentRunManifest{}, fmt.Errorf("--out is required")
	}
	if strings.TrimSpace(cfg.PackageDir) == "" {
		cfg.PackageDir = filepath.Join(cfg.OutDir, "package")
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return ExperimentRunManifest{}, err
	}
	manifest := ExperimentRunManifest{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "experiment-run-v1",
		OutputDir:   cfg.OutDir,
	}
	beforeSources, err := runExperimentImports("before", cfg, &manifest)
	if err != nil {
		return ExperimentRunManifest{}, err
	}
	if len(beforeSources) == 0 {
		return ExperimentRunManifest{}, fmt.Errorf("at least one before source is required")
	}
	afterSources, err := runExperimentImports("after", cfg, &manifest)
	if err != nil {
		return ExperimentRunManifest{}, err
	}
	beforeAssembled := filepath.Join(cfg.OutDir, "before", "assembled")
	beforeManifest, err := assembleEvidenceRun(beforeSources, beforeAssembled)
	if err != nil {
		return ExperimentRunManifest{}, err
	}
	manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "before_assemble", Status: "complete", Output: beforeAssembled})
	manifest.Outputs.BeforeAssembled = beforeAssembled
	manifest.Outputs.SourceCoverage = beforeManifest.Outputs.SourceCoverageReport
	manifest.Metrics.BeforeSourceCount = beforeManifest.Metrics.SourceCount
	manifest.Metrics.BeforeSecurityEvents = beforeManifest.Metrics.SecurityEventCount
	manifest.Metrics.BeforeFlows = beforeManifest.Metrics.FlowCount
	manifest.Metrics.BeforeObservations = beforeManifest.Metrics.ObservationCount

	var afterAssembled string
	if len(afterSources) > 0 {
		afterAssembled = filepath.Join(cfg.OutDir, "after", "assembled")
		afterManifest, err := assembleEvidenceRun(afterSources, afterAssembled)
		if err != nil {
			return ExperimentRunManifest{}, err
		}
		manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "after_assemble", Status: "complete", Output: afterAssembled})
		manifest.Outputs.AfterAssembled = afterAssembled
		manifest.Metrics.AfterSourceCount = afterManifest.Metrics.SourceCount
		manifest.Metrics.AfterSecurityEvents = afterManifest.Metrics.SecurityEventCount
		manifest.Metrics.AfterFlows = afterManifest.Metrics.FlowCount
		manifest.Metrics.AfterObservations = afterManifest.Metrics.ObservationCount
	} else {
		manifest.Warnings = append(manifest.Warnings, "after sources were not provided; mitigation evaluation was skipped")
	}

	if err := runExperimentPrecision(cfg.OutDir, beforeAssembled, &manifest); err != nil {
		return ExperimentRunManifest{}, err
	}
	if err := runExperimentMitigate(cfg.OutDir, beforeAssembled, &manifest); err != nil {
		return ExperimentRunManifest{}, err
	}
	if afterAssembled != "" {
		if err := runExperimentMitigationEval(cfg.OutDir, beforeAssembled, afterAssembled, &manifest); err != nil {
			return ExperimentRunManifest{}, err
		}
	}
	if err := runExperimentResearchReport(cfg, &manifest); err != nil {
		return ExperimentRunManifest{}, err
	}
	manifest.Outputs.ExperimentManifest = filepath.Join(cfg.OutDir, "experiment_manifest.json")
	if err := writePrettyJSON(manifest.Outputs.ExperimentManifest, manifest); err != nil {
		return ExperimentRunManifest{}, err
	}
	return manifest, nil
}

func runExperimentImports(window string, cfg experimentRunConfig, manifest *ExperimentRunManifest) ([]evidenceSourceDir, error) {
	base := filepath.Join(cfg.OutDir, window)
	sources := []evidenceSourceDir{}
	openwrtDir, suricataEVE, zeekDir, snortAlerts := experimentWindowInputs(window, cfg)
	now := cfg.BeforeNow
	if window == "after" {
		now = cfg.AfterNow
	}
	if strings.TrimSpace(openwrtDir) != "" {
		outDir := filepath.Join(base, "openwrt")
		_, err := runOpenWrtImport(openWrtImportConfig{
			DHCPLeasesPath:  filepath.Join(openwrtDir, "dhcp.leases"),
			DNSLogPath:      filepath.Join(openwrtDir, "dnsmasq.log"),
			FirewallLogPath: filepath.Join(openwrtDir, "firewall.log"),
			ConntrackPath:   filepath.Join(openwrtDir, "conntrack.txt"),
			OutDir:          outDir,
			BaseTime:        now,
		})
		if err != nil {
			return nil, fmt.Errorf("%s openwrt import: %w", window, err)
		}
		manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: window + "_openwrt_import", Status: "complete", Output: outDir})
		sources = append(sources, evidenceSourceDir{name: "openwrt", path: outDir})
	}
	if strings.TrimSpace(suricataEVE) != "" {
		outDir := filepath.Join(base, "suricata")
		if _, err := runSuricataImport(suricataImportConfig{EVEPath: suricataEVE, OutDir: outDir}); err != nil {
			return nil, fmt.Errorf("%s suricata import: %w", window, err)
		}
		manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: window + "_suricata_import", Status: "complete", Output: outDir})
		sources = append(sources, evidenceSourceDir{name: "suricata", path: outDir})
	}
	if strings.TrimSpace(zeekDir) != "" {
		outDir := filepath.Join(base, "zeek")
		if _, err := runZeekImport(experimentZeekConfig(zeekDir, outDir)); err != nil {
			return nil, fmt.Errorf("%s zeek import: %w", window, err)
		}
		manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: window + "_zeek_import", Status: "complete", Output: outDir})
		sources = append(sources, evidenceSourceDir{name: "zeek", path: outDir})
	}
	if strings.TrimSpace(snortAlerts) != "" {
		outDir := filepath.Join(base, "snort")
		if _, err := runSnortImport(snortImportConfig{AlertsPath: snortAlerts, OutDir: outDir}); err != nil {
			return nil, fmt.Errorf("%s snort import: %w", window, err)
		}
		manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: window + "_snort_import", Status: "complete", Output: outDir})
		sources = append(sources, evidenceSourceDir{name: "snort", path: outDir})
	}
	return sources, nil
}

func experimentWindowInputs(window string, cfg experimentRunConfig) (openwrtDir, suricataEVE, zeekDir, snortAlerts string) {
	if window == "after" {
		return cfg.AfterOpenWrtDir, cfg.AfterSuricataEVE, cfg.AfterZeekDir, cfg.AfterSnortAlerts
	}
	return cfg.BeforeOpenWrtDir, cfg.BeforeSuricataEVE, cfg.BeforeZeekDir, cfg.BeforeSnortAlerts
}

func experimentZeekConfig(rawDir, outDir string) zeekImportConfig {
	cfg := zeekImportConfig{
		ConnPath: filepath.Join(rawDir, "conn.log"),
		DNSPath:  filepath.Join(rawDir, "dns.log"),
		HTTPPath: filepath.Join(rawDir, "http.log"),
		OutDir:   outDir,
	}
	if fileExists(filepath.Join(rawDir, "tls.log")) {
		cfg.TLSPath = filepath.Join(rawDir, "tls.log")
	} else {
		cfg.SSLPath = filepath.Join(rawDir, "ssl.log")
	}
	return cfg
}

func runExperimentPrecision(outDir, assembled string, manifest *ExperimentRunManifest) error {
	reportOut := filepath.Join(outDir, "precision_report.json")
	incidentsOut := filepath.Join(outDir, "incidents.jsonl")
	var sink strings.Builder
	if err := runPrecision([]string{
		"--events", filepath.Join(assembled, "events.jsonl"),
		"--security-events", filepath.Join(assembled, "security_events.jsonl"),
		"--flows", filepath.Join(assembled, "flows.jsonl"),
		"--observations", filepath.Join(assembled, "observations.jsonl"),
		"--out", reportOut,
		"--incidents-out", incidentsOut,
	}, &sink); err != nil {
		return err
	}
	report, err := reportapi.LoadDetectionPrecisionReportWithSecurityEvents(
		filepath.Join(assembled, "events.jsonl"),
		filepath.Join(assembled, "security_events.jsonl"),
		filepath.Join(assembled, "flows.jsonl"),
		filepath.Join(assembled, "observations.jsonl"),
		filepath.Join(assembled, "device_inventory.json"),
	)
	if err == nil {
		manifest.Metrics.IncidentCount = report.Metrics.IncidentCount
	}
	manifest.Outputs.PrecisionReport = reportOut
	manifest.Outputs.Incidents = incidentsOut
	manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "precision", Status: "complete", Output: reportOut})
	return nil
}

func runExperimentMitigate(outDir, assembled string, manifest *ExperimentRunManifest) error {
	planOut := filepath.Join(outDir, "mitigation_plan.json")
	gatewayOut := filepath.Join(outDir, "gateway_backend_plan.json")
	rulesOut := filepath.Join(outDir, "openwrt_mitigation_dryrun.sh")
	rollbackOut := filepath.Join(outDir, "openwrt_mitigation_rollback.sh")
	applyReportOut := filepath.Join(outDir, "mitigation_apply_report.json")
	var sink strings.Builder
	if err := runMitigate([]string{
		"--events", filepath.Join(assembled, "events.jsonl"),
		"--security-events", filepath.Join(assembled, "security_events.jsonl"),
		"--flows", filepath.Join(assembled, "flows.jsonl"),
		"--observations", filepath.Join(assembled, "observations.jsonl"),
		"--out", planOut,
		"--gateway-out", gatewayOut,
		"--rules-out", rulesOut,
		"--rollback-out", rollbackOut,
		"--apply-report-out", applyReportOut,
	}, &sink); err != nil {
		return err
	}
	plan, err := reportapi.LoadMitigationPlanWithSecurityEvents(
		filepath.Join(assembled, "events.jsonl"),
		filepath.Join(assembled, "security_events.jsonl"),
		filepath.Join(assembled, "flows.jsonl"),
		filepath.Join(assembled, "observations.jsonl"),
		filepath.Join(assembled, "device_inventory.json"),
	)
	if err == nil {
		manifest.Metrics.MitigationActionCount = plan.Metrics.ActionCount
	}
	manifest.Outputs.MitigationPlan = planOut
	manifest.Outputs.GatewayPlan = gatewayOut
	manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "mitigation", Status: "complete", Output: planOut})
	return nil
}

func runExperimentMitigationEval(outDir, beforeAssembled, afterAssembled string, manifest *ExperimentRunManifest) error {
	evalOut := filepath.Join(outDir, "mitigation_eval_report.json")
	var sink strings.Builder
	if err := runMitigationEval([]string{
		"--plan", filepath.Join(outDir, "mitigation_plan.json"),
		"--apply-report", filepath.Join(outDir, "mitigation_apply_report.json"),
		"--before-events", filepath.Join(beforeAssembled, "events.jsonl"),
		"--before-security-events", filepath.Join(beforeAssembled, "security_events.jsonl"),
		"--before-flows", filepath.Join(beforeAssembled, "flows.jsonl"),
		"--before-observations", filepath.Join(beforeAssembled, "observations.jsonl"),
		"--after-events", filepath.Join(afterAssembled, "events.jsonl"),
		"--after-security-events", filepath.Join(afterAssembled, "security_events.jsonl"),
		"--after-flows", filepath.Join(afterAssembled, "flows.jsonl"),
		"--after-observations", filepath.Join(afterAssembled, "observations.jsonl"),
		"--out", evalOut,
	}, &sink); err != nil {
		return err
	}
	manifest.Outputs.MitigationEval = evalOut
	manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "mitigation_eval", Status: "complete", Output: evalOut})
	return nil
}

func runExperimentResearchReport(cfg experimentRunConfig, manifest *ExperimentRunManifest) error {
	reportOut := filepath.Join(cfg.OutDir, "research_report.json")
	markdownOut := filepath.Join(cfg.OutDir, "research_report.md")
	csvDir := filepath.Join(cfg.OutDir, "tables")
	args := []string{
		"--precision", filepath.Join(cfg.OutDir, "precision_report.json"),
		"--mitigation", filepath.Join(cfg.OutDir, "mitigation_plan.json"),
		"--source-coverage", manifest.Outputs.SourceCoverage,
		"--out", reportOut,
		"--markdown-out", markdownOut,
		"--csv-dir", csvDir,
		"--package-dir", cfg.PackageDir,
	}
	if manifest.Outputs.MitigationEval != "" {
		args = append(args, "--mitigation-eval", manifest.Outputs.MitigationEval)
	}
	var sink strings.Builder
	if err := runResearchReport(args, &sink); err != nil {
		return err
	}
	manifest.Outputs.ResearchReport = reportOut
	manifest.Outputs.ResearchMarkdown = markdownOut
	manifest.Outputs.ResearchPackage = cfg.PackageDir
	manifest.Steps = append(manifest.Steps, ExperimentRunStep{Name: "research_report", Status: "complete", Output: reportOut})
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
