package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"quarant/internal/reportapi"
)

func runMitigate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mitigate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	eventsPath := fs.String("events", "events.jsonl", "events JSONL path")
	flowsPath := fs.String("flows", "", "flows JSONL path (default: sibling flows.jsonl)")
	observationsPath := fs.String("observations", "", "observations JSONL path (default: sibling observations.jsonl)")
	inventoryPath := fs.String("inventory", "", "device inventory JSON path (default: sibling device_inventory.json)")
	planOut := fs.String("out", "mitigation_plan.json", "mitigation plan JSON output path, or - for stdout")
	rulesOut := fs.String("rules-out", "openwrt_mitigation_dryrun.sh", "OpenWrt dry-run rules script output path, empty to disable")
	gatewayOut := fs.String("gateway-out", "gateway_backend_plan.json", "backend-neutral gateway plan JSON output path, empty to disable")
	rollbackOut := fs.String("rollback-out", "openwrt_mitigation_rollback.sh", "OpenWrt rollback script output path, empty to disable")
	applyReportOut := fs.String("apply-report-out", "mitigation_apply_report.json", "mitigation apply report JSON output path, empty to disable")
	applyScriptOut := fs.String("apply-script-out", "openwrt_mitigation_apply.sh", "OpenWrt apply script output path used only with --apply, empty to disable")
	dryRun := fs.Bool("dry-run", true, "default safety mode; --apply overrides this for script generation")
	apply := fs.Bool("apply", false, "generate an explicit OpenWrt apply script after safety checks")
	iotZone := fs.String("iot-zone", "iot", "OpenWrt source zone for IoT devices")
	wanZone := fs.String("wan-zone", "wan", "OpenWrt destination zone for internet egress")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse mitigate flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("mitigate accepts flags only")
	}

	dir := filepath.Dir(*eventsPath)
	if dir == "." {
		dir = ""
	}
	plan, err := reportapi.LoadMitigationPlan(
		*eventsPath,
		defaultSibling(*flowsPath, dir, "flows.jsonl"),
		defaultSibling(*observationsPath, dir, "observations.jsonl"),
		defaultSibling(*inventoryPath, dir, "device_inventory.json"),
	)
	if err != nil {
		return err
	}

	if strings.TrimSpace(*planOut) == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(plan); err != nil {
			return err
		}
	} else if strings.TrimSpace(*planOut) != "" {
		if err := writePrettyJSON(*planOut, plan); err != nil {
			return err
		}
	}
	needsGatewayPlan := strings.TrimSpace(*rulesOut) != "" ||
		strings.TrimSpace(*gatewayOut) != "" ||
		strings.TrimSpace(*rollbackOut) != "" ||
		strings.TrimSpace(*applyReportOut) != "" ||
		*apply
	var gatewayPlan reportapi.GatewayBackendPlan
	if needsGatewayPlan {
		gatewayPlan = reportapi.BuildOpenWrtGatewayBackendPlan(plan, *iotZone, *wanZone)
		if strings.TrimSpace(*gatewayOut) != "" {
			if err := writePrettyJSON(*gatewayOut, gatewayPlan); err != nil {
				return err
			}
		}
	}
	effectiveDryRun := true
	if *apply {
		effectiveDryRun = false
	} else if !*dryRun {
		return fmt.Errorf("--dry-run=false is not accepted without --apply")
	}
	if needsGatewayPlan && strings.TrimSpace(*applyReportOut) != "" {
		report := reportapi.BuildMitigationApplyReport(gatewayPlan, reportapi.MitigationApplyOptions{
			ExplicitApply:      *apply,
			DryRun:             effectiveDryRun,
			GatewayPlanPath:    *gatewayOut,
			ApplyScriptPath:    *applyScriptOut,
			RollbackScriptPath: *rollbackOut,
		})
		if err := writePrettyJSON(*applyReportOut, report); err != nil {
			return err
		}
	}
	if needsGatewayPlan && strings.TrimSpace(*rulesOut) != "" {
		script := buildOpenWrtMitigationDryRun(gatewayPlan)
		if err := os.WriteFile(*rulesOut, []byte(script), 0644); err != nil {
			return err
		}
	}
	if needsGatewayPlan && strings.TrimSpace(*rollbackOut) != "" {
		rollbackScript := buildOpenWrtMitigationRollbackDryRun(gatewayPlan)
		if *apply {
			rollbackScript = buildOpenWrtMitigationRollbackApplyScript(gatewayPlan)
		}
		if err := os.WriteFile(*rollbackOut, []byte(rollbackScript), 0644); err != nil {
			return err
		}
	}
	if *apply {
		if gatewayPlan.Metrics.BlockingConflicts > 0 {
			return fmt.Errorf("apply blocked: gateway plan has %d blocking conflict(s); review %s", gatewayPlan.Metrics.BlockingConflicts, *applyReportOut)
		}
		if gatewayPlan.Metrics.RuleCount == 0 {
			return fmt.Errorf("apply blocked: gateway plan has no generated rules; review %s", *applyReportOut)
		}
		if strings.TrimSpace(*applyScriptOut) != "" {
			applyScript := buildOpenWrtMitigationApplyScript(gatewayPlan)
			if err := os.WriteFile(*applyScriptOut, []byte(applyScript), 0755); err != nil {
				return err
			}
		}
	}
	if strings.TrimSpace(*planOut) != "-" {
		fmt.Fprintf(out, "Mitigation plan complete: actions=%d auto_eligible=%d review_required=%d plan=%s rules=%s gateway=%s rollback=%s apply_report=%s apply_script=%s\n",
			plan.Metrics.ActionCount,
			plan.Metrics.AutoEligibleCount,
			plan.Metrics.ReviewRequiredCount,
			*planOut,
			*rulesOut,
			*gatewayOut,
			*rollbackOut,
			*applyReportOut,
			applyScriptSummary(*apply, *applyScriptOut),
		)
	}
	return nil
}

func buildOpenWrtMitigationDryRun(plan reportapi.GatewayBackendPlan) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Generated by Quarant mitigation dry-run.\n")
	b.WriteString("# Review this file before applying. It intentionally prints UCI commands instead of executing them.\n\n")
	b.WriteString("echo '[quarant] mitigation dry-run; no firewall changes are applied'\n\n")
	for _, warning := range plan.Warnings {
		b.WriteString("echo '[quarant][warning] " + shellEscapeEcho(warning) + "'\n")
	}
	if len(plan.Warnings) > 0 {
		b.WriteString("\n")
	}
	for _, rule := range plan.Rules {
		b.WriteString("cat <<'QUARANT_RULE_" + rule.OpenWrtSection + "'\n")
		for _, cmd := range rule.UCICommands {
			b.WriteString(cmd)
			b.WriteString("\n")
		}
		b.WriteString("QUARANT_RULE_" + rule.OpenWrtSection + "\n\n")
	}
	if len(plan.Rules) == 0 {
		b.WriteString("echo '[quarant] no OpenWrt UCI rules were generated from this plan'\n")
	} else {
		b.WriteString("echo '[quarant] generated ")
		b.WriteString(fmt.Sprintf("%d", len(plan.Rules)))
		b.WriteString(" dry-run rule(s). To apply manually, review the commands above, run them on OpenWrt, then run: uci commit firewall && /etc/init.d/firewall reload'\n")
	}
	return b.String()
}

func buildOpenWrtMitigationRollbackDryRun(plan reportapi.GatewayBackendPlan) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Generated by Quarant mitigation rollback dry-run.\n")
	b.WriteString("# Review this file before applying. It intentionally prints rollback UCI commands instead of executing them.\n\n")
	b.WriteString("echo '[quarant] mitigation rollback dry-run; no firewall or DNS changes are applied'\n\n")
	for _, rule := range plan.Rules {
		b.WriteString("cat <<'QUARANT_ROLLBACK_" + rule.OpenWrtSection + "'\n")
		for _, cmd := range rule.RollbackCommands {
			b.WriteString(cmd)
			b.WriteString("\n")
		}
		b.WriteString("QUARANT_ROLLBACK_" + rule.OpenWrtSection + "\n\n")
	}
	if len(plan.Rules) == 0 {
		b.WriteString("echo '[quarant] no OpenWrt rollback rules were generated from this plan'\n")
	} else {
		b.WriteString("echo '[quarant] generated rollback preview for ")
		b.WriteString(fmt.Sprintf("%d", len(plan.Rules)))
		b.WriteString(" managed rule(s). To apply manually, review the commands above, then run matching uci commit/reload commands.'\n")
	}
	return b.String()
}

func buildOpenWrtMitigationApplyScript(plan reportapi.GatewayBackendPlan) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Generated by Quarant mitigation apply.\n")
	b.WriteString("# Run this on the target OpenWrt gateway only after reviewing gateway_backend_plan.json.\n\n")
	writeOpenWrtScriptPreamble(&b, "apply")
	for _, warning := range plan.Warnings {
		b.WriteString("echo '[quarant][warning] " + shellEscapeEcho(warning) + "'\n")
	}
	if len(plan.Warnings) > 0 {
		b.WriteString("\n")
	}
	for _, rule := range plan.Rules {
		writeOpenWrtTrackedCommands(&b, rule, rule.UCICommands)
	}
	writeOpenWrtCommitReload(&b, plan)
	b.WriteString("printf '%s\\n' \"$APPLIED_SECTIONS\" > \"$SNAPSHOT_DIR/applied_sections.txt\"\n")
	b.WriteString("trap - ERR\n")
	b.WriteString("echo '[quarant] mitigation apply complete; snapshot saved at '\"$SNAPSHOT_DIR\"\n")
	return b.String()
}

func buildOpenWrtMitigationRollbackApplyScript(plan reportapi.GatewayBackendPlan) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Generated by Quarant mitigation rollback.\n")
	b.WriteString("# Deletes only Quarant-managed sections generated in the matching gateway plan.\n\n")
	writeOpenWrtScriptPreamble(&b, "rollback")
	for _, rule := range plan.Rules {
		writeOpenWrtTrackedCommands(&b, rule, rule.RollbackCommands)
	}
	writeOpenWrtCommitReload(&b, plan)
	b.WriteString("printf '%s\\n' \"$APPLIED_SECTIONS\" > \"$SNAPSHOT_DIR/rolled_back_sections.txt\"\n")
	b.WriteString("trap - ERR\n")
	b.WriteString("echo '[quarant] mitigation rollback complete; snapshot saved at '\"$SNAPSHOT_DIR\"\n")
	return b.String()
}

func writeOpenWrtScriptPreamble(b *strings.Builder, operation string) {
	b.WriteString("SNAPSHOT_DIR=\"${QUARANT_SNAPSHOT_DIR:-/root/quarant-mitigation-")
	b.WriteString(operation)
	b.WriteString("-$(date +%Y%m%d-%H%M%S)}\"\n")
	b.WriteString("APPLIED_SECTIONS=\"\"\n\n")
	b.WriteString("on_error() {\n")
	b.WriteString("  echo '[quarant][error] ")
	b.WriteString(operation)
	b.WriteString(" failed; partial sections:' \"$APPLIED_SECTIONS\" >&2\n")
	b.WriteString("  printf '%s\\n' \"$APPLIED_SECTIONS\" > \"$SNAPSHOT_DIR/partial_sections.txt\" 2>/dev/null || true\n")
	b.WriteString("}\n")
	b.WriteString("trap on_error ERR\n\n")
	b.WriteString("mkdir -p \"$SNAPSHOT_DIR\"\n")
	b.WriteString("cp /etc/config/firewall \"$SNAPSHOT_DIR/firewall.before\" 2>/dev/null || true\n")
	b.WriteString("cp /etc/config/dhcp \"$SNAPSHOT_DIR/dhcp.before\" 2>/dev/null || true\n")
	b.WriteString("cat /tmp/dhcp.leases > \"$SNAPSHOT_DIR/dhcp.leases.before\" 2>/dev/null || true\n")
	b.WriteString("echo '[quarant] snapshot saved at '\"$SNAPSHOT_DIR\"\n\n")
}

func writeOpenWrtTrackedCommands(b *strings.Builder, rule reportapi.GatewayRule, commands []string) {
	b.WriteString("echo '[quarant] applying managed section " + shellEscapeEcho(rule.OpenWrtSection) + "'\n")
	for _, cmd := range commands {
		b.WriteString(cmd)
		b.WriteString("\n")
	}
	b.WriteString("APPLIED_SECTIONS=\"$APPLIED_SECTIONS ")
	b.WriteString(rule.Family)
	b.WriteString(".")
	b.WriteString(rule.OpenWrtSection)
	b.WriteString("\"\n\n")
}

func writeOpenWrtCommitReload(b *strings.Builder, plan reportapi.GatewayBackendPlan) {
	if plan.Metrics.FirewallRules > 0 {
		b.WriteString("uci commit firewall\n")
		b.WriteString("/etc/init.d/firewall reload\n")
	}
	if plan.Metrics.DNSRules > 0 {
		b.WriteString("uci commit dhcp\n")
		b.WriteString("/etc/init.d/dnsmasq restart\n")
	}
	b.WriteString("\n")
}

func applyScriptSummary(apply bool, path string) string {
	if !apply {
		return "(not generated; use --apply)"
	}
	return path
}

func shellEscapeEcho(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `'`, `'\''`)
	return value
}
