package reportapi

import (
	"strings"
	"time"
)

type MitigationApplyOptions struct {
	ExplicitApply      bool
	DryRun             bool
	GatewayPlanPath    string
	ApplyScriptPath    string
	RollbackScriptPath string
}

type MitigationApplyReport struct {
	GeneratedAt     string                  `json:"generated_at"`
	Backend         string                  `json:"backend"`
	Mode            string                  `json:"mode"`
	Status          string                  `json:"status"`
	ExplicitApply   bool                    `json:"explicit_apply"`
	DryRun          bool                    `json:"dry_run"`
	ManagedTag      string                  `json:"managed_tag"`
	GatewayPlanPath string                  `json:"gateway_plan_path,omitempty"`
	ApplyScriptPath string                  `json:"apply_script_path,omitempty"`
	RollbackPath    string                  `json:"rollback_script_path,omitempty"`
	Snapshot        MitigationApplySnapshot `json:"snapshot"`
	Metrics         MitigationApplyMetrics  `json:"metrics"`
	ManagedRules    []MitigationManagedRule `json:"managed_rules"`
	SafetyChecks    []string                `json:"safety_checks"`
	BlockingIssues  []string                `json:"blocking_issues,omitempty"`
	Warnings        []string                `json:"warnings,omitempty"`
	Limitations     []string                `json:"limitations,omitempty"`
	Conflicts       []GatewayRuleConflict   `json:"conflicts,omitempty"`
}

type MitigationApplySnapshot struct {
	Required          bool     `json:"required"`
	PathTemplate      string   `json:"path_template"`
	ExpectedArtifacts []string `json:"expected_artifacts"`
	Commands          []string `json:"commands"`
}

type MitigationApplyMetrics struct {
	PlannedRuleCount       int  `json:"planned_rule_count"`
	FirewallRuleCount      int  `json:"firewall_rule_count"`
	DNSRuleCount           int  `json:"dns_rule_count"`
	RollbackCommandCount   int  `json:"rollback_command_count"`
	BlockingConflictCount  int  `json:"blocking_conflict_count"`
	WarningConflictCount   int  `json:"warning_conflict_count"`
	InfoConflictCount      int  `json:"info_conflict_count"`
	PartialApplyDetection  bool `json:"partial_apply_detection"`
	ManagedRuleTaggingOnly bool `json:"managed_rule_tagging_only"`
}

type MitigationManagedRule struct {
	ID               string   `json:"id"`
	ActionID         string   `json:"action_id"`
	IncidentID       string   `json:"incident_id,omitempty"`
	Family           string   `json:"family"`
	Policy           string   `json:"policy"`
	Intent           string   `json:"intent"`
	OpenWrtSection   string   `json:"openwrt_section"`
	ManagedTag       string   `json:"managed_tag"`
	DeviceIP         string   `json:"device_ip,omitempty"`
	DeviceMAC        string   `json:"device_mac,omitempty"`
	Domain           string   `json:"domain,omitempty"`
	DstIP            string   `json:"dst_ip,omitempty"`
	DstPort          uint16   `json:"dst_port,omitempty"`
	RollbackCommands []string `json:"rollback_commands"`
}

func BuildMitigationApplyReport(plan GatewayBackendPlan, opts MitigationApplyOptions) MitigationApplyReport {
	dryRun := opts.DryRun
	if !opts.ExplicitApply {
		dryRun = true
	}
	report := MitigationApplyReport{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Backend:         firstNonEmpty(plan.Backend, "openwrt_uci"),
		Mode:            "dry_run",
		Status:          "dry_run_only",
		ExplicitApply:   opts.ExplicitApply,
		DryRun:          dryRun,
		ManagedTag:      plan.ManagedTag,
		GatewayPlanPath: strings.TrimSpace(opts.GatewayPlanPath),
		ApplyScriptPath: strings.TrimSpace(opts.ApplyScriptPath),
		RollbackPath:    strings.TrimSpace(opts.RollbackScriptPath),
		Snapshot:        mitigationApplySnapshot(),
		Metrics: MitigationApplyMetrics{
			PlannedRuleCount:       plan.Metrics.RuleCount,
			FirewallRuleCount:      plan.Metrics.FirewallRules,
			DNSRuleCount:           plan.Metrics.DNSRules,
			RollbackCommandCount:   plan.Metrics.RollbackCommands,
			BlockingConflictCount:  plan.Metrics.BlockingConflicts,
			WarningConflictCount:   plan.Metrics.WarningConflicts,
			InfoConflictCount:      plan.Metrics.InfoConflicts,
			PartialApplyDetection:  true,
			ManagedRuleTaggingOnly: true,
		},
		ManagedRules: mitigationManagedRules(plan),
		SafetyChecks: []string{
			"apply requires explicit --apply flag",
			"--dry-run is the default mode",
			"snapshot is required before generated commands are applied",
			"rollback script deletes only Quarant-managed generated sections",
			"partial apply detection records sections attempted before failure",
			"blocking gateway conflicts prevent apply script generation",
		},
		Warnings:    append([]string{}, plan.Warnings...),
		Limitations: mitigationApplyLimitations(plan),
		Conflicts:   append([]GatewayRuleConflict{}, plan.Conflicts...),
	}
	if report.ManagedTag == "" {
		report.ManagedTag = "quarant-managed"
	}
	if opts.ExplicitApply && !dryRun {
		report.Mode = "apply_script_generated"
		report.Status = "apply_script_generated"
	}
	if plan.Metrics.BlockingConflicts > 0 {
		report.Status = "blocked_by_conflicts"
		if opts.ExplicitApply && !dryRun {
			report.Mode = "apply_blocked"
		}
		report.BlockingIssues = append(report.BlockingIssues, "gateway plan has blocking rule conflicts; review conflicts before applying")
	}
	if len(plan.Rules) == 0 {
		report.BlockingIssues = append(report.BlockingIssues, "gateway plan contains no generated rules to apply")
		if opts.ExplicitApply && !dryRun {
			report.Status = "blocked_no_rules"
			report.Mode = "apply_blocked"
		}
	}
	return report
}

func mitigationApplySnapshot() MitigationApplySnapshot {
	return MitigationApplySnapshot{
		Required:     true,
		PathTemplate: "/root/quarant-mitigation-$(date +%Y%m%d-%H%M%S)",
		ExpectedArtifacts: []string{
			"firewall.before",
			"dhcp.before",
			"dhcp.leases.before",
			"applied_sections.txt",
			"partial_sections.txt when a command fails",
		},
		Commands: []string{
			"mkdir -p \"$SNAPSHOT_DIR\"",
			"cp /etc/config/firewall \"$SNAPSHOT_DIR/firewall.before\"",
			"cp /etc/config/dhcp \"$SNAPSHOT_DIR/dhcp.before\"",
			"cat /tmp/dhcp.leases > \"$SNAPSHOT_DIR/dhcp.leases.before\"",
		},
	}
}

func mitigationManagedRules(plan GatewayBackendPlan) []MitigationManagedRule {
	out := make([]MitigationManagedRule, 0, len(plan.Rules))
	for _, rule := range plan.Rules {
		out = append(out, MitigationManagedRule{
			ID:               rule.ID,
			ActionID:         rule.ActionID,
			IncidentID:       rule.IncidentID,
			Family:           rule.Family,
			Policy:           rule.Policy,
			Intent:           rule.Intent,
			OpenWrtSection:   rule.OpenWrtSection,
			ManagedTag:       rule.ManagedTag,
			DeviceIP:         rule.DeviceIP,
			DeviceMAC:        rule.DeviceMAC,
			Domain:           rule.Domain,
			DstIP:            rule.DstIP,
			DstPort:          rule.DstPort,
			RollbackCommands: append([]string{}, rule.RollbackCommands...),
		})
	}
	return out
}

func mitigationApplyLimitations(plan GatewayBackendPlan) []string {
	limitations := []string{
		"the generated apply script must be run on the target OpenWrt gateway",
		"Quarant manages only sections tagged in this generated plan",
		"external firewall changes made outside Quarant are not rolled back",
	}
	if plan.Metrics.DNSRules > 0 {
		limitations = append(limitations, "dns blocks may not affect devices that bypass gateway DNS")
	}
	if plan.Metrics.ZonePolicyRules > 0 {
		limitations = append(limitations, "zone policy rules should be reviewed manually before apply")
	}
	return limitations
}
