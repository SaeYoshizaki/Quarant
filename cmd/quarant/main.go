package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	case "live":
		if err := runLive(args[1:]); err != nil {
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

	flags := bindCaptureFlags(fs, captureFlagDefaults{
		outPath:       "events.jsonl",
		allowIface:    false,
		reportHelp:    "launch the local report viewer while analysis is running",
		appendHelp:    "append to existing events/flows outputs instead of replacing them",
		flowsHelp:     "path to write flow summaries JSONL (default: sibling flows.jsonl)",
		inventoryHelp: "path to write device inventory snapshot JSON (default: sibling device_inventory.json, empty to disable with --inventory-out=-)",
	})

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

	cfg := buildAnalysisConfig(inputPath, "", flags)
	return runCapture(cfg, func(engine *analyzer.Engine) error {
		if cfg.InputPath == "-" {
			return engine.RunPCAPStream(os.Stdin)
		}
		return engine.RunOffline(cfg.InputPath)
	})
}

func runLive(args []string) error {
	fs := flag.NewFlagSet("live", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	flags := bindCaptureFlags(fs, captureFlagDefaults{
		outPath:       "events.jsonl",
		iface:         "eth0",
		allowIface:    true,
		reportHelp:    "launch the local report viewer while capture is running",
		appendHelp:    "append to existing events/flows outputs instead of replacing them",
		flowsHelp:     "path to write flow summaries JSONL (default: sibling flows.jsonl)",
		inventoryHelp: "path to write device inventory snapshot JSON (default: sibling device_inventory.json, empty to disable with --inventory-out=-)",
	})

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse live flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("live does not accept positional arguments")
	}
	if strings.TrimSpace(*flags.iface) == "" {
		return fmt.Errorf("live requires --iface")
	}

	cfg := buildAnalysisConfig("", *flags.iface, flags)
	return runCapture(cfg, func(engine *analyzer.Engine) error {
		return engine.RunLive(cfg.Interface)
	})
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
	Interface         string
	EventsOut         string
	FlowsOut          string
	InventoryOut      string
	InventoryInterval time.Duration
	Debug             bool
	AppendOutput      bool
	Report            bool
	OpenViewer        bool
	ViewerAddr        string
	WebDist           string
	BlockOnViewer     bool
}

type captureRunner func(*analyzer.Engine) error

type captureFlags struct {
	outPath           *string
	flowsOutPath      *string
	inventoryOut      *string
	inventoryInterval *time.Duration
	debug             *bool
	appendOutput      *bool
	report            *bool
	openViewer        *bool
	addr              *string
	webDist           *string
	iface             *string
}

type captureFlagDefaults struct {
	outPath       string
	iface         string
	allowIface    bool
	appendHelp    string
	reportHelp    string
	flowsHelp     string
	inventoryHelp string
}

func bindCaptureFlags(fs *flag.FlagSet, defaults captureFlagDefaults) captureFlags {
	outDefault := defaults.outPath
	if strings.TrimSpace(outDefault) == "" {
		outDefault = "events.jsonl"
	}
	flags := captureFlags{
		outPath:           fs.String("out", outDefault, "path to write events JSONL"),
		flowsOutPath:      fs.String("flows-out", "", defaults.flowsHelp),
		inventoryOut:      fs.String("inventory-out", "", defaults.inventoryHelp),
		inventoryInterval: fs.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON"),
		debug:             fs.Bool("debug", false, "enable debug payload logging"),
		appendOutput:      fs.Bool("append", false, defaults.appendHelp),
		report:            fs.Bool("report", false, defaults.reportHelp),
		openViewer:        fs.Bool("open", false, "open the local report viewer in a browser"),
		addr:              fs.String("addr", "127.0.0.1:8080", "HTTP listen address for the report viewer"),
		webDist:           fs.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets"),
	}
	if defaults.allowIface {
		ifaceDefault := defaults.iface
		if strings.TrimSpace(ifaceDefault) == "" {
			ifaceDefault = "eth0"
		}
		flags.iface = fs.String("iface", ifaceDefault, "capture interface")
	}
	return flags
}

func buildAnalysisConfig(inputPath, iface string, flags captureFlags) analysisConfig {
	eventsDir := filepath.Dir(*flags.outPath)
	if eventsDir == "." {
		eventsDir = ""
	}
	flowsPath := defaultSibling(*flags.flowsOutPath, eventsDir, "flows.jsonl")
	inventoryPath := defaultSibling(*flags.inventoryOut, eventsDir, "device_inventory.json")
	if *flags.inventoryOut == "-" {
		inventoryPath = ""
	}
	return analysisConfig{
		InputPath:         inputPath,
		Interface:         iface,
		EventsOut:         *flags.outPath,
		FlowsOut:          flowsPath,
		InventoryOut:      inventoryPath,
		InventoryInterval: *flags.inventoryInterval,
		Debug:             *flags.debug,
		AppendOutput:      *flags.appendOutput,
		Report:            *flags.report,
		OpenViewer:        *flags.openViewer,
		ViewerAddr:        *flags.addr,
		WebDist:           *flags.webDist,
		BlockOnViewer:     inputPath != "",
	}
}

func runCapture(cfg analysisConfig, runner captureRunner) error {
	if runner == nil {
		return fmt.Errorf("capture runner is required")
	}

	runtime, err := newAnalysisRuntime(cfg)
	if err != nil {
		return err
	}
	defer runtime.close()

	if cfg.Report {
		runtime.startViewer()
	}
	if err := runner(runtime.engine); err != nil {
		return err
	}
	if cfg.Report && cfg.BlockOnViewer {
		return runtime.waitForViewer()
	}
	return nil
}

func analyzePCAP(cfg analysisConfig) error {
	return runCapture(cfg, func(engine *analyzer.Engine) error {
		if cfg.InputPath == "-" {
			return engine.RunPCAPStream(os.Stdin)
		}
		return engine.RunOffline(cfg.InputPath)
	})
}

type analysisRuntime struct {
	engine          *analyzer.Engine
	eventSink       *analyzer.JSONLSink
	flowSink        *analyzer.JSONLSink
	inventoryWriter *analyzer.DeviceInventoryWriter
	viewerOnce      sync.Once
	viewerErr       chan error
	cfg             analysisConfig
}

func newAnalysisRuntime(cfg analysisConfig) (*analysisRuntime, error) {
	if strings.TrimSpace(cfg.EventsOut) == "" {
		return nil, fmt.Errorf("events output path is required")
	}
	if strings.TrimSpace(cfg.FlowsOut) == "" {
		return nil, fmt.Errorf("flows output path is required")
	}
	if !cfg.AppendOutput {
		if err := resetOutputFile(cfg.EventsOut); err != nil {
			return nil, err
		}
		if err := resetOutputFile(cfg.FlowsOut); err != nil {
			return nil, err
		}
	}

	db, err := knowledge.LoadAll()
	if err != nil {
		return nil, fmt.Errorf("load knowledge db: %w", err)
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
		return nil, err
	}

	flowSink, err := analyzer.NewJSONSink(cfg.FlowsOut)
	if err != nil {
		_ = sink.Close()
		return nil, err
	}

	handler := analyzer.NewFlowHandler(sink, flowSink, cfg.Debug, db)
	var inventoryWriter *analyzer.DeviceInventoryWriter
	if cfg.InventoryOut != "" {
		inventoryWriter = analyzer.NewDeviceInventoryWriter(cfg.InventoryOut, cfg.InventoryInterval, handler.DeviceInventory)
		inventoryWriter.Start()
	}

	return &analysisRuntime{
		engine:          analyzer.NewEngine(handler),
		eventSink:       sink,
		flowSink:        flowSink,
		inventoryWriter: inventoryWriter,
		viewerErr:       make(chan error, 1),
		cfg:             cfg,
	}, nil
}

func (r *analysisRuntime) startViewer() {
	r.viewerOnce.Do(func() {
		go func() {
			r.viewerErr <- viewer.Serve(viewer.Options{
				EventsPath:    r.cfg.EventsOut,
				FlowsPath:     r.cfg.FlowsOut,
				InventoryPath: r.cfg.InventoryOut,
				Addr:          r.cfg.ViewerAddr,
				OpenBrowser:   r.cfg.OpenViewer,
				WebDist:       r.cfg.WebDist,
			})
		}()
	})
}

func (r *analysisRuntime) close() {
	if r == nil {
		return
	}
	if r.inventoryWriter != nil {
		r.inventoryWriter.Stop()
	}
	if r.flowSink != nil {
		_ = r.flowSink.Close()
	}
	if r.eventSink != nil {
		_ = r.eventSink.Close()
	}
}

func (r *analysisRuntime) waitForViewer() error {
	if r == nil || !r.cfg.Report {
		return nil
	}
	return <-r.viewerErr
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

	cfg := analysisConfig{
		InputPath:         *pcapPath,
		Interface:         *iface,
		EventsOut:         "events.jsonl",
		FlowsOut:          "flows.jsonl",
		InventoryOut:      *inventoryOut,
		InventoryInterval: *inventoryInterval,
		Debug:             *debug,
		AppendOutput:      true,
	}
	err := runCapture(cfg, func(engine *analyzer.Engine) error {
		switch {
		case cfg.InputPath == "-":
			return engine.RunPCAPStream(os.Stdin)
		case cfg.InputPath != "":
			return engine.RunOffline(cfg.InputPath)
		default:
			return engine.RunLive(cfg.Interface)
		}
	})
	if err != nil {
		log.Fatal(err)
	}
}
