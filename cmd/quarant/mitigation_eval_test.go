package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMitigationEvalWritesReport(t *testing.T) {
	dir := t.TempDir()
	beforeEvents := filepath.Join(dir, "before_events.jsonl")
	beforeFlows := filepath.Join(dir, "before_flows.jsonl")
	beforeObservations := filepath.Join(dir, "before_observations.jsonl")
	beforeInventory := filepath.Join(dir, "before_inventory.json")
	afterEvents := filepath.Join(dir, "after_events.jsonl")
	afterFlows := filepath.Join(dir, "after_flows.jsonl")
	afterObservations := filepath.Join(dir, "after_observations.jsonl")
	afterInventory := filepath.Join(dir, "after_inventory.json")
	planPath := filepath.Join(dir, "mitigation_plan.json")
	applyReportPath := filepath.Join(dir, "mitigation_apply_report.json")
	reportPath := filepath.Join(dir, "mitigation_eval_report.json")

	writeTestFile(t, planPath, `{"actions":[{"id":"action-telnet","device_ip":"192.168.50.92","kind":"block_service","status":"review_required","risk_reduction_target":{"taxonomy":"insecure_service","signal_keys":["event_i2_telnet_service_observed"]},"firewall_rules":[{"id":"rule-telnet","backend":"openwrt_uci","action":"REJECT","device_ip":"192.168.50.92","protocol":"tcp","dst_port":23,"dst_zone":"wan"}],"impact":{"estimated_blocked_flows":1,"normal_traffic_risk":"possible"}}]}`)
	writeTestFile(t, applyReportPath, `{"status":"apply_script_generated","mode":"apply_script_generated","explicit_apply":true,"dry_run":false,"rollback_script_path":"openwrt_mitigation_rollback.sh","metrics":{"partial_apply_detection":true},"managed_rules":[{"id":"rule-telnet"}]}`)
	writeTestFile(t, beforeEvents, `{"ts":"2026-09-27T10:00:00Z","rule_id":"I2_TELNET_SERVICE_OBSERVED","type":"I2_TELNET_SERVICE_OBSERVED","category":"I2","severity":"HIGH","confidence":"high","src_ip":"192.168.50.92","dst_ip":"203.0.113.23","dst_port":23}`+"\n")
	writeTestFile(t, beforeFlows, `{"ts":"2026-09-27T10:00:00Z","flow_key":"telnet-1","src_ip":"192.168.50.92","dst_ip":"203.0.113.23","dst_port":23,"protocol":"tcp","app_protocol":"telnet","direction":"external"}`+"\n"+
		`{"ts":"2026-09-27T10:00:01Z","flow_key":"dns-1","src_ip":"192.168.50.92","dst_ip":"192.168.50.1","dst_port":53,"protocol":"udp","app_protocol":"dns","direction":"local"}`+"\n"+
		`{"ts":"2026-09-27T10:00:02Z","flow_key":"https-1","src_ip":"192.168.50.92","dst_ip":"198.51.100.5","dst_port":443,"protocol":"tcp","app_protocol":"https","direction":"external"}`+"\n")
	writeTestFile(t, beforeObservations, "")
	writeTestFile(t, beforeInventory, `{"devices":[{"ip":"192.168.50.92","category_candidate":"Camera"}]}`)
	writeTestFile(t, afterEvents, "")
	writeTestFile(t, afterFlows, `{"ts":"2026-09-27T11:00:00Z","flow_key":"dns-2","src_ip":"192.168.50.92","dst_ip":"192.168.50.1","dst_port":53,"protocol":"udp","app_protocol":"dns","direction":"local"}`+"\n")
	writeTestFile(t, afterObservations, "")
	writeTestFile(t, afterInventory, `{"devices":[{"ip":"192.168.50.92","category_candidate":"Camera"}]}`)

	var out bytes.Buffer
	err := runMitigationEval([]string{
		"--plan", planPath,
		"--apply-report", applyReportPath,
		"--before-events", beforeEvents,
		"--before-flows", beforeFlows,
		"--before-observations", beforeObservations,
		"--before-inventory", beforeInventory,
		"--after-events", afterEvents,
		"--after-flows", afterFlows,
		"--after-observations", afterObservations,
		"--after-inventory", afterInventory,
		"--out", reportPath,
	}, &out)
	if err != nil {
		t.Fatalf("runMitigationEval: %v", err)
	}
	if !strings.Contains(out.String(), "Mitigation evaluation complete") {
		t.Fatalf("output=%q, want completion", out.String())
	}
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	report := string(data)
	if !strings.Contains(report, `"overall_outcome": "resolved"`) ||
		!strings.Contains(report, `"targeted_signal_reduction_rate": 1`) ||
		!strings.Contains(report, `"critical_flow_continuity_risk": "low"`) ||
		!strings.Contains(report, `"normal_flow_preservation_rate": 0.5`) ||
		!strings.Contains(report, `"apply_was_explicit": true`) {
		t.Fatalf("report=%s, want resolved mitigation evaluation", report)
	}
}
