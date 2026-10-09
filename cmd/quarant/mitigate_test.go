package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMitigateWritesPlanAndDryRunRules(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")
	observationsPath := filepath.Join(dir, "observations.jsonl")
	inventoryPath := filepath.Join(dir, "device_inventory.json")
	planPath := filepath.Join(dir, "mitigation_plan.json")
	rulesPath := filepath.Join(dir, "openwrt_dryrun.sh")
	gatewayPath := filepath.Join(dir, "gateway_backend_plan.json")
	rollbackPath := filepath.Join(dir, "openwrt_rollback.sh")
	applyReportPath := filepath.Join(dir, "mitigation_apply_report.json")
	applyScriptPath := filepath.Join(dir, "openwrt_apply.sh")

	writeTestFile(t, eventsPath, `{"ts":"2026-09-27T10:00:00Z","rule_id":"I7_HTTP_AUTH","type":"INSECURE_HTTP_AUTH","category":"I7","severity":"CRITICAL","confidence":"high","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80}`+"\n")
	writeTestFile(t, flowsPath, `{"ts":"2026-09-27T10:00:00Z","flow_key":"tcp|auth","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.example"}`+"\n")
	writeTestFile(t, observationsPath, "")
	writeTestFile(t, inventoryPath, `{"devices":[{"ip":"192.168.50.20","category_candidate":"Camera"}]}`)

	var out bytes.Buffer
	err := runMitigate([]string{
		"--events", eventsPath,
		"--flows", flowsPath,
		"--observations", observationsPath,
		"--inventory", inventoryPath,
		"--out", planPath,
		"--rules-out", rulesPath,
		"--gateway-out", gatewayPath,
		"--rollback-out", rollbackPath,
		"--apply-report-out", applyReportPath,
		"--apply-script-out", applyScriptPath,
	}, &out)
	if err != nil {
		t.Fatalf("runMitigate: %v", err)
	}
	if !strings.Contains(out.String(), "Mitigation plan complete") ||
		!strings.Contains(out.String(), "gateway=") ||
		!strings.Contains(out.String(), "rollback=") ||
		!strings.Contains(out.String(), "apply_report=") {
		t.Fatalf("output=%q, want completion", out.String())
	}
	planData, err := os.ReadFile(planPath)
	if err != nil {
		t.Fatalf("read plan: %v", err)
	}
	if !strings.Contains(string(planData), `"kind": "block_service"`) ||
		!strings.Contains(string(planData), `"risk_reduction_target"`) ||
		!strings.Contains(string(planData), `"why_this_action"`) {
		t.Fatalf("plan=%s, want structured block_service mitigation", planData)
	}
	rulesData, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read rules: %v", err)
	}
	if !strings.Contains(string(rulesData), "uci set firewall.") || !strings.Contains(string(rulesData), ".dest_port='80'") {
		t.Fatalf("rules=%s, want dry-run UCI rule for port 80", rulesData)
	}
	if !strings.Contains(string(rulesData), "quarant-managed") {
		t.Fatalf("rules=%s, want managed tag", rulesData)
	}
	gatewayData, err := os.ReadFile(gatewayPath)
	if err != nil {
		t.Fatalf("read gateway plan: %v", err)
	}
	if !strings.Contains(string(gatewayData), `"managed_tag": "quarant-managed"`) ||
		!strings.Contains(string(gatewayData), `"requires_stable_dhcp_lease"`) ||
		!strings.Contains(string(gatewayData), `"rollback_commands"`) {
		t.Fatalf("gateway plan=%s, want managed backend plan", gatewayData)
	}
	rollbackData, err := os.ReadFile(rollbackPath)
	if err != nil {
		t.Fatalf("read rollback: %v", err)
	}
	if !strings.Contains(string(rollbackData), "uci -q delete firewall.") ||
		!strings.Contains(string(rollbackData), "rollback dry-run") {
		t.Fatalf("rollback=%s, want rollback preview", rollbackData)
	}
	applyReportData, err := os.ReadFile(applyReportPath)
	if err != nil {
		t.Fatalf("read apply report: %v", err)
	}
	if !strings.Contains(string(applyReportData), `"status": "dry_run_only"`) ||
		!strings.Contains(string(applyReportData), `"partial_apply_detection": true`) ||
		!strings.Contains(string(applyReportData), `"managed_rules"`) {
		t.Fatalf("apply report=%s, want dry-run apply safety report", applyReportData)
	}
	if _, err := os.Stat(applyScriptPath); !os.IsNotExist(err) {
		t.Fatalf("apply script should not be generated without --apply, stat err=%v", err)
	}
}

func TestRunMitigateApplyWritesApplyAndRollbackScripts(t *testing.T) {
	dir := t.TempDir()
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")
	observationsPath := filepath.Join(dir, "observations.jsonl")
	inventoryPath := filepath.Join(dir, "device_inventory.json")
	planPath := filepath.Join(dir, "mitigation_plan.json")
	rulesPath := filepath.Join(dir, "openwrt_dryrun.sh")
	gatewayPath := filepath.Join(dir, "gateway_backend_plan.json")
	rollbackPath := filepath.Join(dir, "openwrt_rollback.sh")
	applyReportPath := filepath.Join(dir, "mitigation_apply_report.json")
	applyScriptPath := filepath.Join(dir, "openwrt_apply.sh")

	writeTestFile(t, eventsPath, `{"ts":"2026-09-27T10:00:00Z","rule_id":"I7_HTTP_AUTH","type":"INSECURE_HTTP_AUTH","category":"I7","severity":"CRITICAL","confidence":"high","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80}`+"\n")
	writeTestFile(t, flowsPath, `{"ts":"2026-09-27T10:00:00Z","flow_key":"tcp|auth","src_ip":"192.168.50.20","dst_ip":"198.51.100.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.example"}`+"\n")
	writeTestFile(t, observationsPath, "")
	writeTestFile(t, inventoryPath, `{"devices":[{"ip":"192.168.50.20","mac_address":"aa:bb:cc:dd:ee:ff","category_candidate":"Camera"}]}`)

	var out bytes.Buffer
	err := runMitigate([]string{
		"--events", eventsPath,
		"--flows", flowsPath,
		"--observations", observationsPath,
		"--inventory", inventoryPath,
		"--out", planPath,
		"--rules-out", rulesPath,
		"--gateway-out", gatewayPath,
		"--rollback-out", rollbackPath,
		"--apply-report-out", applyReportPath,
		"--apply-script-out", applyScriptPath,
		"--apply",
	}, &out)
	if err != nil {
		t.Fatalf("runMitigate apply: %v", err)
	}

	applyData, err := os.ReadFile(applyScriptPath)
	if err != nil {
		t.Fatalf("read apply script: %v", err)
	}
	if !strings.Contains(string(applyData), "SNAPSHOT_DIR=") ||
		!strings.Contains(string(applyData), "partial_sections.txt") ||
		!strings.Contains(string(applyData), "uci commit firewall") ||
		!strings.Contains(string(applyData), "uci set firewall.quarant_") {
		t.Fatalf("apply script=%s, want snapshot, partial detection, and real UCI apply", applyData)
	}
	rollbackData, err := os.ReadFile(rollbackPath)
	if err != nil {
		t.Fatalf("read rollback: %v", err)
	}
	if !strings.Contains(string(rollbackData), "Deletes only Quarant-managed sections") ||
		!strings.Contains(string(rollbackData), "uci -q delete firewall.") ||
		!strings.Contains(string(rollbackData), "rolled_back_sections.txt") {
		t.Fatalf("rollback=%s, want executable managed rollback script", rollbackData)
	}
	reportData, err := os.ReadFile(applyReportPath)
	if err != nil {
		t.Fatalf("read apply report: %v", err)
	}
	if !strings.Contains(string(reportData), `"status": "apply_script_generated"`) ||
		!strings.Contains(string(reportData), `"explicit_apply": true`) ||
		!strings.Contains(string(reportData), `"required": true`) {
		t.Fatalf("apply report=%s, want explicit apply report", reportData)
	}
}
