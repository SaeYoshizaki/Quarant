package main

import (
	"flag"
	"log"
	"path/filepath"

	"quarant/internal/viewer"
)

func main() {
	inPath := flag.String("in", "events.jsonl", "input events.jsonl path")
	reportPath := flag.String("report-in", "", "input report JSON path (optional, used for /api/report when set)")
	flowsPath := flag.String("flows-in", "flows.jsonl", "input flows.jsonl path")
	inventoryPath := flag.String("inventory-in", "device_inventory.json", "input device inventory JSON path")
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	openBrowserFlag := flag.Bool("open", false, "open the local report viewer in a browser")
	webDist := flag.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets")
	flag.Parse()

	if err := viewer.Serve(viewer.Options{
		EventsPath:    *inPath,
		ReportPath:    *reportPath,
		FlowsPath:     *flowsPath,
		InventoryPath: *inventoryPath,
		Addr:          *addr,
		OpenBrowser:   *openBrowserFlag,
		WebDist:       *webDist,
	}); err != nil {
		log.Fatal(err)
	}
}
