package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/knowledge"
	"quarant/internal/viewer"
)

func main() {
	log.SetFlags(log.LstdFlags)

	args := os.Args[1:]
	if len(args) == 0 {
		runLegacyCapture(nil)
		return
	}

	switch args[0] {
	case "analyze":
		if err := runAnalyze(args[1:]); err != nil {
			log.Fatal(err)
		}
	case "report":
		if err := runReport(args[1:]); err != nil {
			log.Fatal(err)
		}
	default:
		// Preserve the previous interface-driven entrypoint when called without subcommands.
		runLegacyCapture(args)
	}
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	outPath := fs.String("out", "events.jsonl", "path to write events JSONL")
	flowsOutPath := fs.String("flows-out", "", "path to write flow summaries JSONL (default: sibling flows.jsonl)")
	inventoryOut := fs.String("inventory-out", "", "path to write device inventory snapshot JSON (default: sibling device_inventory.json, empty to disable with --inventory-out=-)")
	inventoryInterval := fs.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON")
	debug := fs.Bool("debug", false, "enable debug payload logging")
	appendOutput := fs.Bool("append", false, "append to existing events/flows outputs instead of replacing them")
	reportAfter := fs.Bool("report", false, "launch the local report viewer after analysis completes")
	openViewer := fs.Bool("open", false, "open the local report viewer in a browser")
	addr := fs.String("addr", "127.0.0.1:8080", "HTTP listen address for the report viewer")
	webDist := fs.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse analyze flags: %w", err)
	}

	inputPath := "-"
	if fs.NArg() > 0 {
		inputPath = fs.Arg(0)
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("analyze accepts exactly one input path or - for stdin")
	}

	eventsDir := filepath.Dir(*outPath)
	if eventsDir == "." {
		eventsDir = ""
	}
	flowsPath := defaultSibling(*flowsOutPath, eventsDir, "flows.jsonl")
	inventoryPath := defaultSibling(*inventoryOut, eventsDir, "device_inventory.json")
	if *inventoryOut == "-" {
		inventoryPath = ""
	}

	cfg := analysisConfig{
		InputPath:         inputPath,
		EventsOut:         *outPath,
		FlowsOut:          flowsPath,
		InventoryOut:      inventoryPath,
		InventoryInterval: *inventoryInterval,
		Debug:             *debug,
		AppendOutput:      *appendOutput,
	}
	if err := analyzePCAP(cfg); err != nil {
		return err
	}

	if *reportAfter {
		return viewer.Serve(viewer.Options{
			EventsPath:    *outPath,
			FlowsPath:     flowsPath,
			InventoryPath: inventoryPath,
			Addr:          *addr,
			OpenBrowser:   *openViewer,
			WebDist:       *webDist,
		})
	}
	return nil
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	openViewer := fs.Bool("open", false, "open the local report viewer in a browser")
	demoMode := fs.Bool("demo", false, "use bundled demo data from examples/demo")
	addr := fs.String("addr", "127.0.0.1:8080", "HTTP listen address")
	webDist := fs.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets")
	flowsPath := fs.String("flows-in", "", "input flows JSONL path (default: sibling flows.jsonl)")
	inventoryPath := fs.String("inventory-in", "", "input inventory JSON path (default: sibling device_inventory.json)")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse report flags: %w", err)
	}
	if *demoMode {
		if fs.NArg() > 0 {
			return fmt.Errorf("report --demo does not accept an input path")
		}
		demoDir := filepath.Join("examples", "demo")
		return viewer.Serve(viewer.Options{
			EventsPath:    filepath.Join(demoDir, "events.jsonl"),
			FlowsPath:     defaultSibling(*flowsPath, demoDir, "flows.jsonl"),
			InventoryPath: defaultSibling(*inventoryPath, demoDir, "device_inventory.json"),
			Addr:          *addr,
			OpenBrowser:   *openViewer,
			WebDist:       *webDist,
			DemoMode:      true,
		})
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("report requires exactly one input path: events.jsonl or report.json")
	}

	inputPath := fs.Arg(0)
	dir := filepath.Dir(inputPath)
	if dir == "." {
		dir = ""
	}

	opts := viewer.Options{
		Addr:          *addr,
		OpenBrowser:   *openViewer,
		WebDist:       *webDist,
		FlowsPath:     defaultSibling(*flowsPath, dir, "flows.jsonl"),
		InventoryPath: defaultSibling(*inventoryPath, dir, "device_inventory.json"),
	}
	if strings.EqualFold(filepath.Ext(inputPath), ".json") {
		opts.ReportPath = inputPath
		opts.EventsPath = defaultSibling("", dir, "events.jsonl")
	} else {
		opts.EventsPath = inputPath
	}
	return viewer.Serve(opts)
}

type analysisConfig struct {
	InputPath         string
	EventsOut         string
	FlowsOut          string
	InventoryOut      string
	InventoryInterval time.Duration
	Debug             bool
	AppendOutput      bool
}

func analyzePCAP(cfg analysisConfig) error {
	if strings.TrimSpace(cfg.EventsOut) == "" {
		return fmt.Errorf("events output path is required")
	}
	if strings.TrimSpace(cfg.FlowsOut) == "" {
		return fmt.Errorf("flows output path is required")
	}
	if !cfg.AppendOutput {
		if err := resetOutputFile(cfg.EventsOut); err != nil {
			return err
		}
		if err := resetOutputFile(cfg.FlowsOut); err != nil {
			return err
		}
	}

	db, err := knowledge.LoadAll()
	if err != nil {
		return fmt.Errorf("load knowledge db: %w", err)
	}

	log.Printf(
		"knowledge db loaded: categories=%d communication_types=%d pii_types=%d policies=%d inference_categories=%d behavior_baselines=%d i5_vulnerable_components=%d",
		len(db.DeviceCategories.Categories),
		len(db.CommunicationTypes.CommunicationTypes),
		len(db.PIITypes.PIITypes),
		len(db.CategoryPolicy),
		len(db.CategoryInference.Categories),
		len(db.BehaviorBaselines)-1,
		len(*db.I5Vulnerable),
	)

	sink, err := analyzer.NewJSONSink(cfg.EventsOut)
	if err != nil {
		return err
	}
	defer sink.Close()

	flowSink, err := analyzer.NewJSONSink(cfg.FlowsOut)
	if err != nil {
		return err
	}
	defer flowSink.Close()

	handler := analyzer.NewFlowHandler(sink, flowSink, cfg.Debug, db)
	var inventoryWriter *analyzer.DeviceInventoryWriter
	if cfg.InventoryOut != "" {
		inventoryWriter = analyzer.NewDeviceInventoryWriter(cfg.InventoryOut, cfg.InventoryInterval, handler.DeviceInventory)
		inventoryWriter.Start()
		defer inventoryWriter.Stop()
	}

	engine := analyzer.NewEngine(handler)
	if cfg.InputPath == "-" {
		return engine.RunPCAPStream(os.Stdin)
	}
	return engine.RunOffline(cfg.InputPath)
}

func resetOutputFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}

func defaultSibling(explicit, dir, name string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}

func normalizeFlagArgs(fs *flag.FlagSet, args []string) []string {
	flagArgs := make([]string, 0, len(args))
	positionals := make([]string, 0, 1)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}

		flagArgs = append(flagArgs, arg)
		name := strings.TrimLeft(arg, "-")
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name = name[:eq]
		}
		f := fs.Lookup(name)
		if f == nil || isBoolFlag(f) || strings.Contains(arg, "=") {
			continue
		}
		if i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return append(flagArgs, positionals...)
}

func isBoolFlag(f *flag.Flag) bool {
	type boolFlag interface {
		IsBoolFlag() bool
	}
	v, ok := f.Value.(boolFlag)
	return ok && v.IsBoolFlag()
}

func runLegacyCapture(args []string) {
	fs := flag.NewFlagSet("quarant", flag.ExitOnError)
	debug := fs.Bool("debug", false, "enable debug payload logging")
	iface := fs.String("i", "eth1", "interface to capture on")
	pcapPath := fs.String("pcap", "", "pcap file to read, or - to read pcap stream from stdin")
	inventoryOut := fs.String("inventory-out", "device_inventory.json", "path to write device inventory snapshot JSON (empty to disable)")
	inventoryInterval := fs.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON")
	_ = fs.Parse(args)

	if *iface != "" && *pcapPath != "" {
		log.Fatal("use either -i <interface> or -pcap <file|->, not both")
	}

	db, err := knowledge.LoadAll()
	if err != nil {
		log.Fatalf("load knowledge db: %v", err)
	}

	log.Printf(
		"knowledge db loaded: categories=%d communication_types=%d pii_types=%d policies=%d inference_categories=%d behavior_baselines=%d i5_vulnerable_components=%d",
		len(db.DeviceCategories.Categories),
		len(db.CommunicationTypes.CommunicationTypes),
		len(db.PIITypes.PIITypes),
		len(db.CategoryPolicy),
		len(db.CategoryInference.Categories),
		len(db.BehaviorBaselines)-1,
		len(*db.I5Vulnerable),
	)

	sink, err := analyzer.NewJSONSink("events.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	defer sink.Close()

	flowSink, err := analyzer.NewJSONSink("flows.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	defer flowSink.Close()

	handler := analyzer.NewFlowHandler(sink, flowSink, *debug, db)
	var inventoryWriter *analyzer.DeviceInventoryWriter
	if *inventoryOut != "" {
		inventoryWriter = analyzer.NewDeviceInventoryWriter(*inventoryOut, *inventoryInterval, handler.DeviceInventory)
		inventoryWriter.Start()
		defer inventoryWriter.Stop()
	}
	engine := analyzer.NewEngine(handler)

	switch {
	case *pcapPath == "-":
		err = engine.RunPCAPStream(os.Stdin)
	case *pcapPath != "":
		err = engine.RunOffline(*pcapPath)
	default:
		err = engine.RunLive(*iface)
	}
	if err != nil {
		log.Fatal(err)
	}
}
