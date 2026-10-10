package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"quarant/internal/reportapi"
)

func runTaxonomy(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("taxonomy requires subcommand: policy or coverage")
	}
	switch args[0] {
	case "policy":
		return runTaxonomyPolicy(args[1:], out)
	case "coverage":
		return runTaxonomyCoverage(args[1:], out)
	default:
		return fmt.Errorf("unknown taxonomy subcommand %q; use policy or coverage", args[0])
	}
}

func runTaxonomyPolicy(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("taxonomy policy", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outPath := fs.String("out", "-", "taxonomy policy JSON output path, or - for stdout")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse taxonomy policy flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("taxonomy policy accepts flags only")
	}
	policy := reportapi.SecurityTaxonomyDecisionPolicy()
	if *outPath == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(policy)
	}
	if err := writePrettyJSON(*outPath, policy); err != nil {
		return err
	}
	fmt.Fprintf(out, "Taxonomy policy written: %s terms=%d\n", *outPath, len(policy.Taxonomies))
	return nil
}

func runTaxonomyCoverage(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("taxonomy coverage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	securityEventsPath := fs.String("security-events", "security_events.jsonl", "security events JSONL path")
	policyPath := fs.String("policy", "", "taxonomy policy JSON path, empty for built-in default")
	outPath := fs.String("out", "taxonomy_coverage_report.json", "taxonomy coverage report JSON output path, or - for stdout")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse taxonomy coverage flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("taxonomy coverage accepts flags only")
	}
	report, err := reportapi.LoadTaxonomyCoverageReport(*securityEventsPath, *policyPath)
	if err != nil {
		return err
	}
	if *outPath == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	if err := writePrettyJSON(*outPath, report); err != nil {
		return err
	}
	fmt.Fprintf(out, "Taxonomy coverage complete: events=%d taxonomy=%d coverage=%.3f fallback_only=%d report=%s\n",
		report.Metrics.SecurityEventCount,
		report.Metrics.TaxonomyCount,
		report.Metrics.ClassificationCoverage,
		report.Metrics.IDSFallbackOnlyCount,
		*outPath,
	)
	return nil
}
