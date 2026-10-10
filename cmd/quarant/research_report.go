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

func runResearchReport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("research-report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	precisionPath := fs.String("precision", "precision_report.json", "precision report JSON path")
	precisionEvalPath := fs.String("precision-eval", "", "precision evaluation report JSON path")
	mitigationPath := fs.String("mitigation", "mitigation_plan.json", "mitigation plan JSON path")
	mitigationEvalPath := fs.String("mitigation-eval", "", "mitigation evaluation report JSON path")
	sourceCoveragePath := fs.String("source-coverage", "", "source coverage report JSON path")
	taxonomyCoveragePath := fs.String("taxonomy-coverage", "", "taxonomy coverage report JSON path")
	reportOut := fs.String("out", "research_report.json", "research report JSON output path, or - for stdout")
	markdownOut := fs.String("markdown-out", "research_report.md", "research report Markdown output path, empty to disable")
	csvDir := fs.String("csv-dir", "", "directory to write paper table CSV files, empty to disable")
	scenarioOut := fs.String("scenario-out", "", "experiment scenario YAML output path, empty to disable")
	manifestOut := fs.String("manifest-out", "", "run manifest JSON output path, empty to disable")
	deviceListOut := fs.String("device-list-out", "", "device list CSV output path, empty to disable")
	latexDir := fs.String("latex-dir", "", "directory to write LaTeX table snippets, empty to disable")
	figuresDir := fs.String("figures-dir", "", "directory to write SVG research figures, empty to disable")
	packageDir := fs.String("package-dir", "", "directory to write a reproducibility package, empty to disable")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse research-report flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("research-report accepts flags only")
	}

	report, err := reportapi.LoadResearchReportWithCoverage(*precisionPath, *precisionEvalPath, *mitigationPath, *mitigationEvalPath, *sourceCoveragePath, *taxonomyCoveragePath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*reportOut) == "-" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else if strings.TrimSpace(*reportOut) != "" {
		if err := writePrettyJSON(*reportOut, report); err != nil {
			return err
		}
	}
	if strings.TrimSpace(*markdownOut) != "" {
		if err := writeTextFile(*markdownOut, reportapi.ResearchReportMarkdown(report)); err != nil {
			return err
		}
	}
	csvCount := 0
	if strings.TrimSpace(*csvDir) != "" {
		var err error
		csvCount, err = writeResearchCSVs(*csvDir, report)
		if err != nil {
			return err
		}
	}
	artifactCount := csvCount
	artifacts := []reportapi.ResearchArtifact{}
	if strings.TrimSpace(*scenarioOut) != "" {
		if err := writeTextFile(*scenarioOut, reportapi.ResearchScenarioYAML(report)); err != nil {
			return err
		}
		artifacts = append(artifacts, researchArtifact("experiment_scenario", *scenarioOut, "yaml", "experiment scenario and source paths"))
		artifactCount++
	}
	if strings.TrimSpace(*deviceListOut) != "" {
		if err := writeTextFile(*deviceListOut, reportapi.ResearchDeviceListCSV(report)); err != nil {
			return err
		}
		artifacts = append(artifacts, researchArtifact("device_list", *deviceListOut, "csv", "device-level experiment summary"))
		artifactCount++
	}
	if strings.TrimSpace(*latexDir) != "" {
		count, err := writeResearchTextFiles(*latexDir, reportapi.ResearchReportLaTeXTables(report))
		if err != nil {
			return err
		}
		artifactCount += count
		artifacts = append(artifacts, researchDirArtifact("latex_tables", *latexDir, "latex", "LaTeX table snippets"))
	}
	if strings.TrimSpace(*figuresDir) != "" {
		count, err := writeResearchTextFiles(*figuresDir, reportapi.ResearchReportFiguresSVG(report))
		if err != nil {
			return err
		}
		artifactCount += count
		artifacts = append(artifacts, researchDirArtifact("figures", *figuresDir, "svg", "SVG research figures"))
	}
	if strings.TrimSpace(*packageDir) != "" {
		count, packageArtifacts, err := writeResearchPackage(*packageDir, report)
		if err != nil {
			return err
		}
		artifactCount += count
		artifacts = append(artifacts, packageArtifacts...)
	}
	if strings.TrimSpace(*manifestOut) != "" {
		manifest := reportapi.BuildResearchRunManifest(report, *scenarioOut, artifacts)
		if err := writePrettyJSON(*manifestOut, manifest); err != nil {
			return err
		}
		artifactCount++
	}
	if strings.TrimSpace(*reportOut) != "-" {
		fmt.Fprintf(out, "Research report complete: incidents=%d actions=%d estimated_blocked_flows=%d outcome=%s report=%s markdown=%s csv_tables=%d artifacts=%d package=%s\n",
			report.Metrics.IncidentCount,
			report.Metrics.MitigationActionCount,
			report.Metrics.EstimatedBlockedFlows,
			firstNonEmptyString(report.Metrics.OverallOutcome, "not_evaluated"),
			*reportOut,
			*markdownOut,
			csvCount,
			artifactCount,
			*packageDir,
		)
	}
	return nil
}

func writeTextFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, []byte(content), 0644)
}

func writeResearchCSVs(dir string, report reportapi.ResearchReport) (int, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, err
	}
	files := reportapi.ResearchReportCSVs(report)
	count := 0
	for name, content := range files {
		if strings.TrimSpace(content) == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func writeResearchTextFiles(dir string, files map[string]string) (int, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, err
	}
	count := 0
	for name, content := range files {
		if strings.TrimSpace(content) == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func writeResearchPackage(dir string, report reportapi.ResearchReport) (int, []reportapi.ResearchArtifact, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, nil, err
	}
	artifacts := []reportapi.ResearchArtifact{}
	count := 0
	write := func(name, kind, description, content string) error {
		path := filepath.Join(dir, name)
		if err := writeTextFile(path, content); err != nil {
			return err
		}
		artifacts = append(artifacts, researchArtifact(strings.TrimSuffix(name, filepath.Ext(name)), path, kind, description))
		count++
		return nil
	}
	if err := write("experiment_scenario.yaml", "yaml", "experiment scenario and source paths", reportapi.ResearchScenarioYAML(report)); err != nil {
		return count, artifacts, err
	}
	if err := writePrettyJSON(filepath.Join(dir, "research_report.json"), report); err != nil {
		return count, artifacts, err
	}
	artifacts = append(artifacts, researchArtifact("research_report", filepath.Join(dir, "research_report.json"), "json", "integrated research report"))
	count++
	if err := write("research_report.md", "markdown", "human-readable research report", reportapi.ResearchReportMarkdown(report)); err != nil {
		return count, artifacts, err
	}
	if err := write("device_list.csv", "csv", "device-level experiment summary", reportapi.ResearchDeviceListCSV(report)); err != nil {
		return count, artifacts, err
	}
	taxonomyPolicy := report.TaxonomyPolicy
	if taxonomyPolicy.Version == "" && len(taxonomyPolicy.Taxonomies) == 0 {
		taxonomyPolicy = reportapi.SecurityTaxonomyDecisionPolicy()
	}
	if err := writePrettyJSON(filepath.Join(dir, "taxonomy_policy.json"), taxonomyPolicy); err != nil {
		return count, artifacts, err
	}
	artifacts = append(artifacts, researchArtifact("taxonomy_policy", filepath.Join(dir, "taxonomy_policy.json"), "json", "taxonomy normalization policy"))
	count++
	tablesDir := filepath.Join(dir, "tables")
	tableCount, err := writeResearchCSVs(tablesDir, report)
	if err != nil {
		return count, artifacts, err
	}
	count += tableCount
	artifacts = append(artifacts, researchDirArtifact("tables", tablesDir, "csv", "paper CSV tables"))
	latexDir := filepath.Join(dir, "latex")
	latexCount, err := writeResearchTextFiles(latexDir, reportapi.ResearchReportLaTeXTables(report))
	if err != nil {
		return count, artifacts, err
	}
	count += latexCount
	artifacts = append(artifacts, researchDirArtifact("latex", latexDir, "latex", "LaTeX table snippets"))
	figuresDir := filepath.Join(dir, "figures")
	figureCount, err := writeResearchTextFiles(figuresDir, reportapi.ResearchReportFiguresSVG(report))
	if err != nil {
		return count, artifacts, err
	}
	count += figureCount
	artifacts = append(artifacts, researchDirArtifact("figures", figuresDir, "svg", "research SVG figures"))
	manifestPath := filepath.Join(dir, "run_manifest.json")
	manifest := reportapi.BuildResearchRunManifest(report, filepath.Join(dir, "experiment_scenario.yaml"), artifacts)
	if err := writePrettyJSON(manifestPath, manifest); err != nil {
		return count, artifacts, err
	}
	artifacts = append(artifacts, researchArtifact("run_manifest", manifestPath, "json", "artifact inventory and reproducibility notes"))
	count++
	if err := write("README.md", "markdown", "reproducibility package README", reportapi.ResearchPackageREADME(report)); err != nil {
		return count, artifacts, err
	}
	return count, artifacts, nil
}

func researchArtifact(name, path, kind, description string) reportapi.ResearchArtifact {
	return reportapi.ResearchArtifact{Name: name, Path: path, Kind: kind, Description: description}
}

func researchDirArtifact(name, path, kind, description string) reportapi.ResearchArtifact {
	return reportapi.ResearchArtifact{Name: name, Path: path, Kind: kind, Description: description}
}
