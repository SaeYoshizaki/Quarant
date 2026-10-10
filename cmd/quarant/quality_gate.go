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

func runQualityGate(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("quality-gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	experimentDir := fs.String("experiment", "", "experiment output directory for default report paths")
	precisionEvalPath := fs.String("precision-eval", "", "precision evaluation report JSON path")
	attackEvalPath := fs.String("attack-eval", "", "attack evidence evaluation report JSON path")
	mitigationEvalPath := fs.String("mitigation-eval", "", "mitigation evaluation report JSON path")
	sourceCoveragePath := fs.String("source-coverage", "", "source coverage report JSON path")
	researchPath := fs.String("research", "", "research report JSON path")
	reportOut := fs.String("out", "", "quality gate report JSON output path")
	researchOut := fs.String("research-out", "", "guarded research report JSON output path, empty to disable")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse quality-gate flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("quality-gate accepts flags only")
	}
	sources := qualityGateSourcesFromFlags(
		*experimentDir,
		*precisionEvalPath,
		*attackEvalPath,
		*mitigationEvalPath,
		*sourceCoveragePath,
		*researchPath,
	)
	if strings.TrimSpace(*reportOut) == "" {
		*reportOut = defaultQualityGateOut(*experimentDir)
	}
	gate, err := reportapi.LoadQualityGateReport(sources)
	if err != nil {
		return err
	}
	gate.Checks = reportapi.SortedQualityGateChecks(gate.Checks)
	if err := writePrettyJSON(*reportOut, gate); err != nil {
		return err
	}
	if strings.TrimSpace(*researchOut) != "" {
		var research reportapi.ResearchReport
		ok, err := readQualityGateResearch(sources.ResearchReport, &research)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("--research-out requires an existing research report; checked %s", sources.ResearchReport)
		}
		guarded := reportapi.ApplyQualityGateToResearchReport(research, gate)
		if err := writePrettyJSON(*researchOut, guarded); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Quality gate complete: status=%s checks=%d adjustments=%d report=%s guarded_research=%s\n",
		gate.OverallStatus,
		len(gate.Checks),
		len(gate.ClaimAdjustments),
		*reportOut,
		*researchOut,
	)
	return nil
}

func qualityGateSourcesFromFlags(experimentDir, precisionEvalPath, attackEvalPath, mitigationEvalPath, sourceCoveragePath, researchPath string) reportapi.QualityGateSources {
	if strings.TrimSpace(experimentDir) == "" {
		return reportapi.QualityGateSources{
			PrecisionEvalReport:      precisionEvalPath,
			AttackEvidenceEvalReport: attackEvalPath,
			MitigationEvalReport:     mitigationEvalPath,
			SourceCoverageReport:     sourceCoveragePath,
			ResearchReport:           researchPath,
		}
	}
	return reportapi.QualityGateSources{
		PrecisionEvalReport:      firstExistingPath(precisionEvalPath, filepath.Join(experimentDir, "precision_eval_report.json")),
		AttackEvidenceEvalReport: firstExistingPath(attackEvalPath, filepath.Join(experimentDir, "before", "assembled", "attack_evidence_eval_report.json"), filepath.Join(experimentDir, "attack_evidence_eval_report.json")),
		MitigationEvalReport:     firstExistingPath(mitigationEvalPath, filepath.Join(experimentDir, "mitigation_eval_report.json")),
		SourceCoverageReport:     firstExistingPath(sourceCoveragePath, filepath.Join(experimentDir, "before", "assembled", "source_coverage_report.json"), filepath.Join(experimentDir, "source_coverage_report.json")),
		ResearchReport:           firstExistingPath(researchPath, filepath.Join(experimentDir, "research_report.json")),
	}
}

func defaultQualityGateOut(experimentDir string) string {
	if strings.TrimSpace(experimentDir) != "" {
		return filepath.Join(experimentDir, "quality_gate_report.json")
	}
	return "quality_gate_report.json"
}

func firstExistingPath(paths ...string) string {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if fileExists(path) {
			return path
		}
	}
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			return path
		}
	}
	return ""
}

func readQualityGateResearch(path string, dst *reportapi.ResearchReport) (bool, error) {
	if strings.TrimSpace(path) == "" {
		return false, nil
	}
	if !fileExists(path) {
		return false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return false, err
	}
	return true, nil
}
