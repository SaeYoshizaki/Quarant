package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quarant/internal/reportapi"
)

func TestRunSnortImportParsesFastAlerts(t *testing.T) {
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alert.fast")
	rulesPath := filepath.Join(dir, "local.rules")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, alertPath,
		`09/26-12:00:00.000000 [**] [1:1000001:1] ET SCAN Telnet Probe [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.9:45123 -> 192.168.8.42:23`+"\n"+
			`{"timestamp":"2026-09-26T12:00:01Z","sid":1000002,"msg":"ET WEB Probe","classtype":"Attempted Recon","priority":2,"src_ip":"203.0.113.9","src_port":45124,"dst_ip":"192.168.8.42","dst_port":80,"proto":"TCP","action":"alert"}`+"\n")
	writeTestFile(t, rulesPath, `alert tcp any any -> $HOME_NET 23 (msg:"ET SCAN Telnet Probe"; classtype:attempted-recon; sid:1000001; rev:2; priority:2; metadata: former_category SCAN, deployment Perimeter; reference:url,example.com/telnet;)`+"\n")

	var out bytes.Buffer
	if err := runSnortImportCLI([]string{"--alerts", alertPath, "--rules", rulesPath, "--out-dir", outDir}, &out); err != nil {
		t.Fatalf("runSnortImportCLI: %v", err)
	}
	events := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(events) != 2 {
		t.Fatalf("events=%+v, want two Snort alerts", events)
	}
	if events[0].Source != "snort" || events[0].SID != "1000001" || events[0].Signature != "ET SCAN Telnet Probe" || events[0].ClassType != "Attempted Information Leak" || events[0].Priority != 2 {
		t.Fatalf("event=%+v, want parsed Snort metadata", events[0])
	}
	if events[0].Evidence["rule_metadata"] == "" || events[0].Evidence["rule_references"] == "" || events[0].RuleSource != "snort_alert+rules" {
		t.Fatalf("event evidence=%+v source=%q, want rule metadata enrichment", events[0].Evidence, events[0].RuleSource)
	}
	attackEvidence, err := os.ReadFile(filepath.Join(outDir, "attack_evidence_report.json"))
	if err != nil {
		t.Fatalf("read attack evidence: %v", err)
	}
	if !strings.Contains(string(attackEvidence), `"security_event_count": 2`) {
		t.Fatalf("attackEvidence=%s, want security event count", attackEvidence)
	}
	metadataReport, err := os.ReadFile(filepath.Join(outDir, "snort_metadata_report.json"))
	if err != nil {
		t.Fatalf("read metadata report: %v", err)
	}
	if !strings.Contains(string(metadataReport), `"metadata_enriched_count": 1`) || !strings.Contains(string(metadataReport), `"rule_metadata_count": 1`) {
		t.Fatalf("metadataReport=%s, want enrichment metrics", metadataReport)
	}
	if !strings.Contains(out.String(), "Snort import complete") || !strings.Contains(out.String(), "enriched=1") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}

func TestRunSnortImportParsesJSONAliasesAndIPv6FastAlert(t *testing.T) {
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alert.fast")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, alertPath,
		`2026-09-26-12:00:00.000000 [**] [1:1000003:1] ET POLICY IPv6 Probe [**] [Priority: 3] {TCP} [2001:db8::10]:45123 -> [fd00::42]:8080`+"\n"+
			`{"ts":"2026-09-26T12:00:01Z","rule":{"sid":1000004,"classtype":"A Network Trojan was detected","priority":1},"message":"ET TROJAN JSON Alias","src_addr":"203.0.113.9","src_ap":"203.0.113.9:45124","dst_addr":"192.168.8.42","dst_ap":"192.168.8.42:4444","ip_proto":"TCP"}`+"\n")

	if _, err := runSnortImport(snortImportConfig{AlertsPath: alertPath, OutDir: outDir}); err != nil {
		t.Fatalf("runSnortImport: %v", err)
	}
	events := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(events) != 2 {
		t.Fatalf("events=%+v, want two parsed alerts", events)
	}
	if events[0].SrcIP != "2001:db8::10" || events[0].DstIP != "fd00::42" || events[0].DstPort != 8080 {
		t.Fatalf("ipv6 event=%+v, want bracketed IPv6 endpoint parsed", events[0])
	}
	if events[1].SID != "1000004" || events[1].ClassType != "A Network Trojan was detected" || events[1].Priority != 1 || events[1].DstPort != 4444 {
		t.Fatalf("json alias event=%+v, want nested rule and addr/addr-port aliases", events[1])
	}
}

func TestRunSnortImportEnrichesAlertWithSIDOnly(t *testing.T) {
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alert.jsonl")
	rulesPath := filepath.Join(dir, "local.rules")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, alertPath, `{"ts":"2026-09-26T12:00:01Z","sid":1000005,"src_addr":"203.0.113.9","dst_addr":"192.168.8.42","dst_port":8080,"ip_proto":"TCP"}`+"\n")
	writeTestFile(t, rulesPath, `alert tcp any any -> $HOME_NET 8080 (msg:"ET WEB Rule Metadata Only"; classtype:web-application-attack; sid:1000005; rev:1; priority:1; metadata: attack_target IoT;)`+"\n")

	if _, err := runSnortImport(snortImportConfig{AlertsPath: alertPath, RulesPaths: []string{rulesPath}, OutDir: outDir}); err != nil {
		t.Fatalf("runSnortImport: %v", err)
	}
	events := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(events) != 1 || events[0].Signature != "ET WEB Rule Metadata Only" || events[0].ClassType != "web-application-attack" || events[0].Priority != 1 {
		t.Fatalf("events=%+v, want SID-only alert enriched from rules", events)
	}
}
