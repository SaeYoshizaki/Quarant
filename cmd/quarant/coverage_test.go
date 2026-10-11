package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCoverageFigureWritesSVGs(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "source_coverage_report.json")
	taxonomyPath := filepath.Join(dir, "taxonomy_coverage_report.json")
	batchPath := filepath.Join(dir, "batch_summary_report.json")
	figuresDir := filepath.Join(dir, "figures")
	writeTestFile(t, sourcePath, `{"version":"source-coverage-v1","metrics":{"source_count":3,"openwrt_only_service_count":1,"suricata_only_service_count":1,"zeek_only_service_count":1,"multi_source_service_count":2,"openwrt_suricata_overlap_count":1}}`)
	writeTestFile(t, taxonomyPath, `{"version":"taxonomy-coverage-v1","metrics":{"security_event_count":2,"classification_coverage":1,"taxonomy_count":2},"by_taxonomy":[{"taxonomy":"port_scan","event_count":2},{"taxonomy":"exploit_attempt","event_count":1}]}`)
	writeTestFile(t, batchPath, `{"version":"experiment-batch-summary-v1","metrics":{"run_count":1,"completed_run_count":1,"warn_count":1},"runs":[{"id":"demo","status":"complete","quality_gate_status":"warn","taxonomy_classification_coverage":1}]}`)

	var out bytes.Buffer
	if err := runCoverage([]string{
		"figure",
		"--source-coverage", sourcePath,
		"--taxonomy-coverage", taxonomyPath,
		"--batch-summary", batchPath,
		"--out-dir", figuresDir,
	}, &out); err != nil {
		t.Fatalf("runCoverage figure: %v", err)
	}
	for _, name := range []string{"source_coverage.svg", "taxonomy_coverage.svg", "batch_quality.svg"} {
		data, err := os.ReadFile(filepath.Join(figuresDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(data), "<svg") {
			t.Fatalf("%s=%s, want SVG", name, data)
		}
	}
	if !strings.Contains(out.String(), "Coverage figures complete") {
		t.Fatalf("output=%q", out.String())
	}
}
