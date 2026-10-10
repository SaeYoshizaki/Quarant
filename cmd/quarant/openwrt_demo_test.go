package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWrtExamplePipeline(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	outDir := t.TempDir()
	beforeOut := filepath.Join(outDir, "before")
	afterOut := filepath.Join(outDir, "after")
	precisionPath := filepath.Join(outDir, "precision_report.json")
	incidentsPath := filepath.Join(outDir, "incidents.jsonl")
	mitigationPath := filepath.Join(outDir, "mitigation_plan.json")
	gatewayPath := filepath.Join(outDir, "gateway_backend_plan.json")
	rulesPath := filepath.Join(outDir, "openwrt_mitigation_dryrun.sh")
	rollbackPath := filepath.Join(outDir, "openwrt_mitigation_rollback.sh")
	applyReportPath := filepath.Join(outDir, "mitigation_apply_report.json")
	evalPath := filepath.Join(outDir, "mitigation_eval_report.json")

	runExampleImport(t, "examples/openwrt/before/raw", beforeOut, "2026-09-26T12:30:00Z")
	runExampleImport(t, "examples/openwrt/after/raw", afterOut, "2026-09-26T13:30:00Z")

	var precisionOut bytes.Buffer
	if err := runPrecision([]string{
		"--events", filepath.Join(beforeOut, "events.jsonl"),
		"--security-events", filepath.Join(beforeOut, "security_events.jsonl"),
		"--flows", filepath.Join(beforeOut, "flows.jsonl"),
		"--observations", filepath.Join(beforeOut, "observations.jsonl"),
		"--inventory", filepath.Join(beforeOut, "device_inventory.json"),
		"--out", precisionPath,
		"--incidents-out", incidentsPath,
	}, &precisionOut); err != nil {
		t.Fatalf("runPrecision: %v", err)
	}
	precisionData := readDemoFile(t, precisionPath)
	for _, want := range []string{
		`"attack_evidence_port_scan"`,
		`"attack_evidence_sensitive_service_probe"`,
		`"attack_evidence_suspicious_tcp_flags"`,
	} {
		if !strings.Contains(precisionData, want) {
			t.Fatalf("precision report missing %s:\n%s", want, precisionData)
		}
	}

	var mitigateOut bytes.Buffer
	if err := runMitigate([]string{
		"--events", filepath.Join(beforeOut, "events.jsonl"),
		"--security-events", filepath.Join(beforeOut, "security_events.jsonl"),
		"--flows", filepath.Join(beforeOut, "flows.jsonl"),
		"--observations", filepath.Join(beforeOut, "observations.jsonl"),
		"--inventory", filepath.Join(beforeOut, "device_inventory.json"),
		"--out", mitigationPath,
		"--gateway-out", gatewayPath,
		"--rules-out", rulesPath,
		"--rollback-out", rollbackPath,
		"--apply-report-out", applyReportPath,
	}, &mitigateOut); err != nil {
		t.Fatalf("runMitigate: %v", err)
	}
	mitigationData := readDemoFile(t, mitigationPath)
	if !strings.Contains(mitigationData, "Review inbound exposure and tighten gateway policy") {
		t.Fatalf("mitigation plan=%s, want inbound exposure review action", mitigationData)
	}

	var evalOut bytes.Buffer
	if err := runMitigationEval([]string{
		"--plan", mitigationPath,
		"--before-events", filepath.Join(beforeOut, "events.jsonl"),
		"--before-security-events", filepath.Join(beforeOut, "security_events.jsonl"),
		"--before-flows", filepath.Join(beforeOut, "flows.jsonl"),
		"--before-observations", filepath.Join(beforeOut, "observations.jsonl"),
		"--before-inventory", filepath.Join(beforeOut, "device_inventory.json"),
		"--after-events", filepath.Join(afterOut, "events.jsonl"),
		"--after-security-events", filepath.Join(afterOut, "security_events.jsonl"),
		"--after-flows", filepath.Join(afterOut, "flows.jsonl"),
		"--after-observations", filepath.Join(afterOut, "observations.jsonl"),
		"--after-inventory", filepath.Join(afterOut, "device_inventory.json"),
		"--out", evalPath,
	}, &evalOut); err != nil {
		t.Fatalf("runMitigationEval: %v", err)
	}
	evalData := readDemoFile(t, evalPath)
	for _, want := range []string{
		`"before_accepted_attack_evidence_count": 1`,
		`"after_accepted_attack_evidence_count": 0`,
		`"accepted_attack_evidence_reduction_rate": 1`,
		`"before_exposed_service_attempt_count": 1`,
		`"after_exposed_service_attempt_count": 0`,
		`"exposed_service_attempt_reduction_rate": 1`,
	} {
		if !strings.Contains(evalData, want) {
			t.Fatalf("mitigation eval missing %s:\n%s", want, evalData)
		}
	}
}

func runExampleImport(t *testing.T, rawDir, outDir, now string) {
	t.Helper()
	var out bytes.Buffer
	if err := runOpenWrtImportCLI([]string{
		"--dhcp-leases", filepath.Join(rawDir, "dhcp.leases"),
		"--dns-log", filepath.Join(rawDir, "dnsmasq.log"),
		"--firewall-log", filepath.Join(rawDir, "firewall.log"),
		"--conntrack", filepath.Join(rawDir, "conntrack.txt"),
		"--out-dir", outDir,
		"--now", now,
	}, &out); err != nil {
		t.Fatalf("runOpenWrtImportCLI(%s): %v", rawDir, err)
	}
	securityEvents := readDemoFile(t, filepath.Join(outDir, "security_events.jsonl"))
	if !strings.Contains(securityEvents, `"source":"openwrt_firewall"`) {
		t.Fatalf("security events=%s, want OpenWrt source", securityEvents)
	}
	attackEvidence := readDemoFile(t, filepath.Join(outDir, "attack_evidence_report.json"))
	if !strings.Contains(attackEvidence, `"security_event_count": 5`) {
		t.Fatalf("attack evidence=%s, want five security events", attackEvidence)
	}
}

func readDemoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
