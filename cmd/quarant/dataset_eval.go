package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"quarant/internal/dataseteval"
)

// runDatasetEval evaluates an analysis run against a public dataset's ground
// truth: `dataset-eval iot23` (flow labels) or `dataset-eval unsw` (device list).
func runDatasetEval(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: quarant dataset-eval iot23|unsw|unsw-attacks --run <analysis dir> ...")
	}
	kind := args[0]
	fs := flag.NewFlagSet("dataset-eval "+kind, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	runDir := fs.String("run", "", "analysis output directory (events.jsonl, device_inventory.json)")
	labels := fs.String("labels", "", "iot23: conn.log.labeled")
	host := fs.String("host", "", "iot23: infected/benign host IP (default: most frequent originator)")
	scenario := fs.String("scenario", "", "iot23: scenario name for the report")
	devices := fs.String("devices", "", "unsw: List_Of_Devices.txt")
	annotations := fs.String("annotations", "", "unsw-attacks: directory with <mac>.csv attack annotations")
	slack := fs.Duration("slack", 2*time.Minute, "unsw-attacks: tolerance around annotated windows")
	format := fs.String("format", "markdown", "markdown|json")
	if err := fs.Parse(normalizeFlagArgs(fs, args[1:])); err != nil {
		return fmt.Errorf("parse dataset-eval flags: %w", err)
	}
	if *runDir == "" {
		return fmt.Errorf("--run is required")
	}
	events, inventory, bad, err := dataseteval.LoadRun(*runDir)
	if err != nil {
		return err
	}
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "dataset-eval: skipped %d malformed event lines\n", bad)
	}
	asJSON := strings.EqualFold(*format, "json")
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	switch kind {
	case "iot23":
		f, err := os.Open(*labels)
		if err != nil {
			return fmt.Errorf("--labels: %w", err)
		}
		defer f.Close()
		flows, err := dataseteval.ParseIoT23Labels(f)
		if err != nil {
			return err
		}
		rep := dataseteval.EvaluateIoT23(*scenario, flows, events, *host)
		if asJSON {
			return enc.Encode(rep)
		}
		dataseteval.WriteIoT23Markdown(out, rep)
	case "unsw":
		f, err := os.Open(*devices)
		if err != nil {
			return fmt.Errorf("--devices: %w", err)
		}
		defer f.Close()
		truth, err := dataseteval.ParseUNSWDevices(f)
		if err != nil {
			return err
		}
		rep := dataseteval.EvaluateUNSW(truth, inventory, events)
		if asJSON {
			return enc.Encode(rep)
		}
		dataseteval.WriteUNSWMarkdown(out, rep)
	case "unsw-attacks":
		windows, err := dataseteval.LoadUNSWAnnotations(*annotations)
		if err != nil {
			return err
		}
		rep := dataseteval.EvaluateUNSWAttacks(windows, inventory, events, *slack)
		return enc.Encode(rep)
	default:
		return fmt.Errorf("unknown dataset %q (use iot23, unsw or unsw-attacks)", kind)
	}
	return nil
}
