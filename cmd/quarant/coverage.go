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

func runCoverage(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("coverage requires subcommand: figure")
	}
	switch args[0] {
	case "figure":
		return runCoverageFigure(args[1:], out)
	default:
		return fmt.Errorf("unknown coverage subcommand %q; use figure", args[0])
	}
}

func runCoverageFigure(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("coverage figure", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	sourceCoveragePath := fs.String("source-coverage", "", "source coverage report JSON path")
	taxonomyCoveragePath := fs.String("taxonomy-coverage", "", "taxonomy coverage report JSON path")
	batchSummaryPath := fs.String("batch-summary", "", "batch summary report JSON path")
	outDir := fs.String("out-dir", "figures", "directory to write SVG figures")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse coverage figure flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("coverage figure accepts flags only")
	}
	if strings.TrimSpace(*outDir) == "" {
		return fmt.Errorf("--out-dir is required")
	}
	count := 0
	if strings.TrimSpace(*sourceCoveragePath) != "" {
		var report reportapi.SourceCoverageReport
		if err := readJSONFileLocal(*sourceCoveragePath, &report); err != nil {
			return err
		}
		if err := writeTextFile(filepath.Join(*outDir, "source_coverage.svg"), reportapi.SourceCoverageFigureSVG(report)); err != nil {
			return err
		}
		count++
	}
	if strings.TrimSpace(*taxonomyCoveragePath) != "" {
		var report reportapi.TaxonomyCoverageReport
		if err := readJSONFileLocal(*taxonomyCoveragePath, &report); err != nil {
			return err
		}
		if err := writeTextFile(filepath.Join(*outDir, "taxonomy_coverage.svg"), reportapi.TaxonomyCoverageFigureSVG(report)); err != nil {
			return err
		}
		count++
	}
	if strings.TrimSpace(*batchSummaryPath) != "" {
		var summary ExperimentBatchSummary
		if err := readJSONFileLocal(*batchSummaryPath, &summary); err != nil {
			return err
		}
		if err := writeTextFile(filepath.Join(*outDir, "batch_quality.svg"), experimentBatchQualityFigureSVG(summary)); err != nil {
			return err
		}
		count++
	}
	if count == 0 {
		return fmt.Errorf("provide at least one of --source-coverage, --taxonomy-coverage, or --batch-summary")
	}
	fmt.Fprintf(out, "Coverage figures complete: figures=%d out=%s\n", count, *outDir)
	return nil
}

func readJSONFileLocal(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
