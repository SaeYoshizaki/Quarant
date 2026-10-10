package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"quarant/internal/reportapi"
)

func runMitigationEval(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("mitigation-eval", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	planPath := fs.String("plan", "mitigation_plan.json", "mitigation plan JSON path")
	applyReportPath := fs.String("apply-report", "", "optional mitigation apply report JSON path")
	beforeEvents := fs.String("before-events", "", "before mitigation events JSONL path")
	beforeSecurityEvents := fs.String("before-security-events", "", "before mitigation security events JSONL path (default: sibling security_events.jsonl)")
	beforeFlows := fs.String("before-flows", "", "before mitigation flows JSONL path (default: sibling flows.jsonl)")
	beforeObservations := fs.String("before-observations", "", "before mitigation observations JSONL path (default: sibling observations.jsonl)")
	beforeInventory := fs.String("before-inventory", "", "before mitigation inventory JSON path (default: sibling device_inventory.json)")
	afterEvents := fs.String("after-events", "", "after mitigation events JSONL path")
	afterSecurityEvents := fs.String("after-security-events", "", "after mitigation security events JSONL path (default: sibling security_events.jsonl)")
	afterFlows := fs.String("after-flows", "", "after mitigation flows JSONL path (default: sibling flows.jsonl)")
	afterObservations := fs.String("after-observations", "", "after mitigation observations JSONL path (default: sibling observations.jsonl)")
	afterInventory := fs.String("after-inventory", "", "after mitigation inventory JSON path (default: sibling device_inventory.json)")
	reportOut := fs.String("out", "mitigation_eval_report.json", "mitigation evaluation report JSON output path, or - for stdout")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse mitigation-eval flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("mitigation-eval accepts flags only")
	}
	if strings.TrimSpace(*beforeEvents) == "" {
		return fmt.Errorf("mitigation-eval requires --before-events")
	}
	if strings.TrimSpace(*afterEvents) == "" {
		return fmt.Errorf("mitigation-eval requires --after-events")
	}

	beforeDir := filepath.Dir(*beforeEvents)
	if beforeDir == "." {
		beforeDir = ""
	}
	afterDir := filepath.Dir(*afterEvents)
	if afterDir == "." {
		afterDir = ""
	}
	report, err := reportapi.LoadMitigationEvaluationReportWithApplyAndSecurityEvents(
		*planPath,
		*applyReportPath,
		*beforeEvents,
		defaultSibling(*beforeSecurityEvents, beforeDir, "security_events.jsonl"),
		defaultSibling(*beforeFlows, beforeDir, "flows.jsonl"),
		defaultSibling(*beforeObservations, beforeDir, "observations.jsonl"),
		defaultSibling(*beforeInventory, beforeDir, "device_inventory.json"),
		*afterEvents,
		defaultSibling(*afterSecurityEvents, afterDir, "security_events.jsonl"),
		defaultSibling(*afterFlows, afterDir, "flows.jsonl"),
		defaultSibling(*afterObservations, afterDir, "observations.jsonl"),
		defaultSibling(*afterInventory, afterDir, "device_inventory.json"),
	)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reportOut) == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if strings.TrimSpace(*reportOut) != "" {
		if err := writePrettyJSON(*reportOut, report); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Mitigation evaluation complete: outcome=%s actions=%d improved=%d residual=%d regressed=%d targeted_reduction=%.3f attack_evidence_reduction=%.3f normal_preservation=%.3f rollback_required=%d report=%s\n",
		report.OverallOutcome,
		report.Metrics.ActionCount,
		report.Metrics.ImprovedActionCount,
		report.Metrics.ResidualActionCount,
		report.Metrics.RegressedActionCount,
		report.Metrics.TargetedSignalReductionRate,
		report.Metrics.AttackEvidenceReductionRate,
		report.Metrics.NormalFlowPreservationRate,
		report.Metrics.RollbackRequiredCount,
		*reportOut,
	)
	return nil
}
