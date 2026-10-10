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
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, alertPath,
		`09/26-12:00:00.000000 [**] [1:1000001:1] ET SCAN Telnet Probe [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 203.0.113.9:45123 -> 192.168.8.42:23`+"\n"+
			`{"timestamp":"2026-09-26T12:00:01Z","sid":1000002,"msg":"ET WEB Probe","classtype":"Attempted Recon","priority":2,"src_ip":"203.0.113.9","src_port":45124,"dst_ip":"192.168.8.42","dst_port":80,"proto":"TCP","action":"alert"}`+"\n")

	var out bytes.Buffer
	if err := runSnortImportCLI([]string{"--alerts", alertPath, "--out-dir", outDir}, &out); err != nil {
		t.Fatalf("runSnortImportCLI: %v", err)
	}
	events := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(events) != 2 {
		t.Fatalf("events=%+v, want two Snort alerts", events)
	}
	if events[0].Source != "snort" || events[0].SID != "1000001" || events[0].Signature != "ET SCAN Telnet Probe" || events[0].ClassType != "Attempted Information Leak" || events[0].Priority != 2 {
		t.Fatalf("event=%+v, want parsed Snort metadata", events[0])
	}
	attackEvidence, err := os.ReadFile(filepath.Join(outDir, "attack_evidence_report.json"))
	if err != nil {
		t.Fatalf("read attack evidence: %v", err)
	}
	if !strings.Contains(string(attackEvidence), `"security_event_count": 2`) {
		t.Fatalf("attackEvidence=%s, want security event count", attackEvidence)
	}
	if !strings.Contains(out.String(), "Snort import complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}
