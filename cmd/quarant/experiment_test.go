package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunExperimentRunCLIExecutesIntegratedPipeline(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "experiment")
	var out bytes.Buffer
	err := runExperimentRunCLI([]string{
		"--before-openwrt", filepath.Join("..", "..", "examples", "integrated", "before", "openwrt", "raw"),
		"--before-suricata", filepath.Join("..", "..", "examples", "integrated", "before", "suricata", "raw", "eve.json"),
		"--before-zeek", filepath.Join("..", "..", "examples", "integrated", "before", "zeek", "raw"),
		"--before-snort", filepath.Join("..", "..", "examples", "integrated", "before", "snort", "raw", "alert.fast"),
		"--after-openwrt", filepath.Join("..", "..", "examples", "integrated", "after", "openwrt", "raw"),
		"--after-suricata", filepath.Join("..", "..", "examples", "integrated", "after", "suricata", "raw", "eve.json"),
		"--after-zeek", filepath.Join("..", "..", "examples", "integrated", "after", "zeek", "raw"),
		"--after-snort", filepath.Join("..", "..", "examples", "integrated", "after", "snort", "raw", "alert.fast"),
		"--before-now", "2026-09-26T12:30:00Z",
		"--after-now", "2026-09-26T13:30:00Z",
		"--out", outDir,
	}, &out)
	if err != nil {
		t.Fatalf("runExperimentRunCLI: %v", err)
	}
	for _, path := range []string{
		filepath.Join(outDir, "before", "assembled", "security_events.jsonl"),
		filepath.Join(outDir, "after", "assembled", "security_events.jsonl"),
		filepath.Join(outDir, "before", "assembled", "source_coverage_report.json"),
		filepath.Join(outDir, "precision_report.json"),
		filepath.Join(outDir, "mitigation_plan.json"),
		filepath.Join(outDir, "mitigation_eval_report.json"),
		filepath.Join(outDir, "research_report.json"),
		filepath.Join(outDir, "quality_gate_report.json"),
		filepath.Join(outDir, "guarded_research_report.json"),
		filepath.Join(outDir, "package", "run_manifest.json"),
		filepath.Join(outDir, "experiment_manifest.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected output %s: %v", path, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(outDir, "experiment_manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifest), `"before_source_count": 4`) || !strings.Contains(string(manifest), `"after_source_count": 4`) {
		t.Fatalf("manifest=%s, want before/after source counts", manifest)
	}
	if !strings.Contains(out.String(), "Experiment run complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}
