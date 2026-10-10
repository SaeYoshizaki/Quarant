package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExperimentBatchYAML(t *testing.T) {
	cfg, err := parseExperimentBatchYAML(`
version: experiment-batch-v1
taxonomy_policy: taxonomy_policy.json
runs:
  - id: integrated
    before_openwrt: examples/integrated/before/openwrt/raw
    before_suricata: examples/integrated/before/suricata/raw/eve.json
    before_now: 2026-09-26T12:30:00Z
`)
	if err != nil {
		t.Fatalf("parseExperimentBatchYAML: %v", err)
	}
	if cfg.TaxonomyPolicyPath != "taxonomy_policy.json" || len(cfg.Runs) != 1 || cfg.Runs[0].ID != "integrated" || cfg.Runs[0].BeforeNow == "" {
		t.Fatalf("cfg=%+v, want parsed batch config", cfg)
	}
}

func TestRunExperimentBatchCreatesSummaryAndCSV(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "experiments.yaml")
	outDir := filepath.Join(dir, "batch")
	writeTestFile(t, configPath, `
version: experiment-batch-v1
runs:
  - id: integrated-demo
    before_openwrt: ../../examples/integrated/before/openwrt/raw
    before_suricata: ../../examples/integrated/before/suricata/raw/eve.json
    before_zeek: ../../examples/integrated/before/zeek/raw
    before_snort: ../../examples/integrated/before/snort/raw/alert.fast
    after_openwrt: ../../examples/integrated/after/openwrt/raw
    after_suricata: ../../examples/integrated/after/suricata/raw/eve.json
    after_zeek: ../../examples/integrated/after/zeek/raw
    after_snort: ../../examples/integrated/after/snort/raw/alert.fast
    before_now: 2026-09-26T12:30:00Z
    after_now: 2026-09-26T13:30:00Z
`)
	var out bytes.Buffer
	if err := runExperiment([]string{"batch", "--config", configPath, "--out", outDir}, &out); err != nil {
		t.Fatalf("runExperiment batch: %v", err)
	}
	summaryPath := filepath.Join(outDir, "batch_summary_report.json")
	csvPath := filepath.Join(outDir, "batch_summary.csv")
	summary, err := os.ReadFile(summaryPath)
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if !strings.Contains(string(summary), `"completed_run_count": 1`) || !strings.Contains(string(summary), `"taxonomy_classification_coverage"`) {
		t.Fatalf("summary=%s, want completed taxonomy-aware batch summary", summary)
	}
	if !strings.Contains(string(csvData), "integrated-demo") || !strings.Contains(out.String(), "Experiment batch complete") {
		t.Fatalf("csv=%s output=%s, want run row and completion output", csvData, out.String())
	}
}
