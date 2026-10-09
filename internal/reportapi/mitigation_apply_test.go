package reportapi

import "testing"

func TestBuildMitigationApplyReportDefaultsToDryRun(t *testing.T) {
	plan := BuildOpenWrtGatewayBackendPlan(MitigationPlan{Actions: []MitigationAction{
		{
			ID:       "action-http",
			DeviceIP: "192.168.50.20",
			Kind:     "block_service",
			FirewallRules: []MitigationRule{
				{ID: "rule-http", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.20", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
			},
		},
	}}, "iot", "wan")

	got := BuildMitigationApplyReport(plan, MitigationApplyOptions{
		ExplicitApply:      false,
		DryRun:             true,
		GatewayPlanPath:    "gateway_backend_plan.json",
		ApplyScriptPath:    "openwrt_mitigation_apply.sh",
		RollbackScriptPath: "openwrt_mitigation_rollback.sh",
	})

	if got.Status != "dry_run_only" || got.Mode != "dry_run" || !got.DryRun || got.ExplicitApply {
		t.Fatalf("report=%+v, want dry-run only report", got)
	}
	if got.Metrics.PlannedRuleCount != 1 || !got.Metrics.PartialApplyDetection || !got.Metrics.ManagedRuleTaggingOnly {
		t.Fatalf("Metrics=%+v, want managed apply safety metrics", got.Metrics)
	}
	if !got.Snapshot.Required || !applyStringSliceContains(got.Snapshot.ExpectedArtifacts, "firewall.before") {
		t.Fatalf("Snapshot=%+v, want required OpenWrt snapshot", got.Snapshot)
	}
	if len(got.ManagedRules) != 1 || got.ManagedRules[0].OpenWrtSection != "quarant_rule_http" {
		t.Fatalf("ManagedRules=%+v, want managed rule summary", got.ManagedRules)
	}
}

func TestBuildMitigationApplyReportBlocksConflictingPlan(t *testing.T) {
	plan := BuildOpenWrtGatewayBackendPlan(MitigationPlan{Actions: []MitigationAction{
		{
			ID:       "deny-http",
			DeviceIP: "192.168.50.30",
			Kind:     "block_service",
			FirewallRules: []MitigationRule{
				{ID: "deny-http-rule", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.30", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
			},
		},
		{
			ID:       "allow-http",
			DeviceIP: "192.168.50.30",
			Kind:     "allow_service",
			FirewallRules: []MitigationRule{
				{ID: "allow-http-rule", Backend: "openwrt_uci", Action: "ACCEPT", DeviceIP: "192.168.50.30", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
			},
		},
	}}, "iot", "wan")

	got := BuildMitigationApplyReport(plan, MitigationApplyOptions{
		ExplicitApply: true,
		DryRun:        false,
	})

	if got.Status != "blocked_by_conflicts" || got.Mode != "apply_blocked" {
		t.Fatalf("report=%+v, want conflict-blocked apply report", got)
	}
	if got.Metrics.BlockingConflictCount != 1 || len(got.BlockingIssues) == 0 || len(got.Conflicts) == 0 {
		t.Fatalf("report=%+v, want blocking conflict details", got)
	}
}

func TestBuildMitigationApplyReportAllowsExplicitApplyScriptGeneration(t *testing.T) {
	plan := BuildOpenWrtGatewayBackendPlan(MitigationPlan{Actions: []MitigationAction{
		{
			ID:       "action-http",
			DeviceIP: "192.168.50.20",
			Kind:     "block_service",
			FirewallRules: []MitigationRule{
				{ID: "rule-http", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.20", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
			},
		},
	}}, "iot", "wan")

	got := BuildMitigationApplyReport(plan, MitigationApplyOptions{
		ExplicitApply: true,
		DryRun:        false,
	})

	if got.Status != "apply_script_generated" || got.Mode != "apply_script_generated" || got.DryRun {
		t.Fatalf("report=%+v, want explicit apply-script report", got)
	}
	if len(got.BlockingIssues) != 0 {
		t.Fatalf("BlockingIssues=%+v, want none", got.BlockingIssues)
	}
}

func applyStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
