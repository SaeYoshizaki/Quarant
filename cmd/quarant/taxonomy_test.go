package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunTaxonomyCoverageWritesReport(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "security_events.jsonl")
	outPath := filepath.Join(dir, "taxonomy_coverage_report.json")
	writeTestFile(t, eventsPath, `{"ts":"2026-09-26T12:00:00Z","source":"suricata","engine":"suricata","event_type":"ids_alert","signature":"ET EXPLOIT Web Probe","classtype":"Attempted Administrator Privilege Gain","src_ip":"203.0.113.9","dst_ip":"192.168.8.42","device_ip":"192.168.8.42","dst_port":80,"protocol":"tcp"}`+"\n")

	var out bytes.Buffer
	if err := runTaxonomy([]string{"coverage", "--security-events", eventsPath, "--out", outPath}, &out); err != nil {
		t.Fatalf("runTaxonomy coverage: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(data), `"taxonomy": "exploit_attempt"`) || !strings.Contains(out.String(), "Taxonomy coverage complete") {
		t.Fatalf("report=%s output=%s, want exploit taxonomy", data, out.String())
	}
}

func TestRunTaxonomyPolicyWritesDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "taxonomy_policy.json")
	var out bytes.Buffer
	if err := runTaxonomy([]string{"policy", "--out", outPath}, &out); err != nil {
		t.Fatalf("runTaxonomy policy: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	if !strings.Contains(string(data), `"quarant-security-taxonomy-v1"`) || !strings.Contains(string(data), `"match_any"`) {
		t.Fatalf("policy=%s, want default taxonomy policy", data)
	}
}
