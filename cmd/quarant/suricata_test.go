package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"quarant/analyzer"
	"quarant/internal/reportapi"
)

func TestRunSuricataImportWritesSecurityEventsAndPassiveEvidence(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, evePath,
		`{"timestamp":"2026-09-26T12:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.9","src_port":45123,"dest_ip":"192.168.8.42","dest_port":23,"proto":"TCP","flow_id":1001,"alert":{"action":"allowed","signature_id":2100001,"signature":"ET SCAN Telnet Probe","category":"Attempted Information Leak","severity":2}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:01.000000+0000","event_type":"alert","src_ip":"203.0.113.9","src_port":45124,"dest_ip":"192.168.8.42","dest_port":80,"proto":"TCP","flow_id":1002,"alert":{"action":"allowed","signature_id":2100002,"signature":"ET SCAN HTTP Probe","category":"Attempted Recon","severity":2}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:02.000000+0000","event_type":"alert","src_ip":"203.0.113.9","src_port":45125,"dest_ip":"192.168.8.42","dest_port":8080,"proto":"TCP","flow_id":1003,"alert":{"action":"allowed","signature_id":2100003,"signature":"ET SCAN Web Probe","category":"Attempted Recon","severity":2}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:03.000000+0000","event_type":"dns","src_ip":"192.168.8.42","src_port":53000,"dest_ip":"8.8.8.8","dest_port":53,"proto":"UDP","app_proto":"dns","flow_id":2001,"dns":{"rrname":"api.camera.example"}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:04.000000+0000","event_type":"http","src_ip":"192.168.8.42","src_port":50000,"dest_ip":"198.51.100.10","dest_port":80,"proto":"TCP","app_proto":"http","flow_id":2002,"http":{"hostname":"camera-cloud.example","url":"/ping","http_method":"GET"}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:05.000000+0000","event_type":"tls","src_ip":"192.168.8.42","src_port":50001,"dest_ip":"198.51.100.11","dest_port":443,"proto":"TCP","app_proto":"tls","flow_id":2003,"tls":{"sni":"tls.camera.example"}}`+"\n")

	var out bytes.Buffer
	err := runSuricataImportCLI([]string{"--eve", evePath, "--out-dir", outDir}, &out)
	if err != nil {
		t.Fatalf("runSuricataImportCLI: %v", err)
	}
	securityEvents := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(securityEvents) != 3 {
		t.Fatalf("securityEvents=%+v, want three alerts", securityEvents)
	}
	if securityEvents[0].Source != "suricata" || securityEvents[0].SID != "2100001" || securityEvents[0].Signature == "" || securityEvents[0].ClassType == "" || securityEvents[0].Priority != 2 || securityEvents[0].Engine != "suricata" || securityEvents[0].AlertAction != "allowed" {
		t.Fatalf("securityEvent=%+v, want Suricata IDS metadata", securityEvents[0])
	}
	attackEvidence, err := os.ReadFile(filepath.Join(outDir, "attack_evidence_report.json"))
	if err != nil {
		t.Fatalf("read attack evidence: %v", err)
	}
	if !strings.Contains(string(attackEvidence), `"scan_candidate_count": 1`) {
		t.Fatalf("attackEvidence=%s, want port scan finding", attackEvidence)
	}
	flows := readJSONLLines[analyzer.FlowRecord](t, filepath.Join(outDir, "flows.jsonl"))
	if len(flows) != 6 {
		t.Fatalf("flows=%+v, want all alert/passive records as flows", flows)
	}
	observations := readJSONLLines[analyzer.ObservationRecord](t, filepath.Join(outDir, "observations.jsonl"))
	if !suricataObservationExists(observations, "dns_query", "api.camera.example") ||
		!suricataObservationExists(observations, "suricata_http", "camera-cloud.example") ||
		!suricataObservationExists(observations, "suricata_tls", "tls.camera.example") {
		t.Fatalf("observations=%+v, want DNS/HTTP/TLS passive evidence", observations)
	}
	if !strings.Contains(out.String(), "Suricata import complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}

func suricataObservationExists(observations []analyzer.ObservationRecord, kind, destination string) bool {
	for _, observation := range observations {
		if observation.Kind == kind && observation.ObservedDestination == destination {
			return true
		}
	}
	return false
}
