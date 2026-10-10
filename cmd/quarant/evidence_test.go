package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quarant/internal/reportapi"
)

func TestRunEvidenceAssembleMergesSourcesAndWritesCoverage(t *testing.T) {
	dir := t.TempDir()
	openwrtDir := filepath.Join(dir, "openwrt")
	suricataDir := filepath.Join(dir, "suricata")
	zeekDir := filepath.Join(dir, "zeek")
	outDir := filepath.Join(dir, "assembled")
	mustMkdir(t, openwrtDir)
	mustMkdir(t, suricataDir)
	mustMkdir(t, zeekDir)

	openwrtSecurity := `{"ts":"2026-09-26T12:00:00Z","source":"openwrt_firewall","event_type":"firewall_accepted","verdict":"accepted","direction":"inbound","src_ip":"203.0.113.9","dst_ip":"192.168.8.42","device_ip":"192.168.8.42","dst_port":80,"protocol":"tcp"}` + "\n"
	writeTestFile(t, filepath.Join(openwrtDir, "security_events.jsonl"), openwrtSecurity)
	writeTestFile(t, filepath.Join(openwrtDir, "flows.jsonl"), "")
	writeTestFile(t, filepath.Join(openwrtDir, "observations.jsonl"), "")
	writeTestFile(t, filepath.Join(openwrtDir, "events.jsonl"), "")

	suricataSecurity := `{"ts":"2026-09-26T12:00:00Z","source":"suricata","engine":"suricata","event_type":"ids_alert","sid":"2100001","signature":"ET WEB Probe","verdict":"observed","direction":"inbound","src_ip":"203.0.113.9","dst_ip":"192.168.8.42","device_ip":"192.168.8.42","dst_port":80,"protocol":"tcp"}` + "\n"
	writeTestFile(t, filepath.Join(suricataDir, "security_events.jsonl"), suricataSecurity+suricataSecurity)
	writeTestFile(t, filepath.Join(suricataDir, "flows.jsonl"), "")
	writeTestFile(t, filepath.Join(suricataDir, "observations.jsonl"), "")
	writeTestFile(t, filepath.Join(suricataDir, "events.jsonl"), "")

	writeTestFile(t, filepath.Join(zeekDir, "flows.jsonl"), `{"ts":"2026-09-26T12:00:01Z","flow_key":"H1","src_ip":"192.168.8.42","src_port":50000,"dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","host":"camera-cloud.example","direction":"external","observed_destination":"camera-cloud.example"}`+"\n")
	writeTestFile(t, filepath.Join(zeekDir, "observations.jsonl"), `{"ts":"2026-09-26T12:00:01Z","kind":"http_request","flow_key":"H1","src_ip":"192.168.8.42","src_port":50000,"dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","host":"camera-cloud.example","direction":"external","observed_destination":"camera-cloud.example"}`+"\n")
	writeTestFile(t, filepath.Join(zeekDir, "security_events.jsonl"), "")
	writeTestFile(t, filepath.Join(zeekDir, "events.jsonl"), "")

	var out bytes.Buffer
	err := runEvidenceAssembleCLI([]string{
		"--openwrt", openwrtDir,
		"--suricata", suricataDir,
		"--zeek", zeekDir,
		"--out", outDir,
	}, &out)
	if err != nil {
		t.Fatalf("runEvidenceAssembleCLI: %v", err)
	}
	securityEvents := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(securityEvents) != 2 {
		t.Fatalf("securityEvents=%+v, want deduped OpenWrt+Suricata events", securityEvents)
	}
	coverageData, err := os.ReadFile(filepath.Join(outDir, "source_coverage_report.json"))
	if err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	if !strings.Contains(string(coverageData), `"openwrt_suricata_overlap_count": 1`) ||
		!strings.Contains(string(coverageData), `"source": "zeek"`) {
		t.Fatalf("coverage=%s, want source overlap and Zeek source", coverageData)
	}
	manifestData, err := os.ReadFile(filepath.Join(outDir, "evidence_manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifestData), `"deduped_security_event_count": 1`) {
		t.Fatalf("manifest=%s, want deduped security count", manifestData)
	}
	if !strings.Contains(out.String(), "Evidence assemble complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}
