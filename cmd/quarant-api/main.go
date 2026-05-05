package main

import (
	"flag"
	"log"
	"path/filepath"
	"strings"

	"quarant/internal/viewer"
)

func main() {
	inPath := flag.String("in", "", "input events.jsonl path")
	reportPath := flag.String("report-in", "", "input report JSON path (optional, used for /api/report when set)")
	flowsPath := flag.String("flows-in", "", "input flows.jsonl path")
	inventoryPath := flag.String("inventory-in", "", "input device inventory JSON path")
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	openBrowserFlag := flag.Bool("open", false, "open the local report viewer in a browser")
	webDist := flag.String("web-dist", filepath.Join("web", "out"), "path to exported web UI assets")
	flag.Parse()

	basePath := strings.TrimSpace(*inPath)
	if basePath == "" {
		basePath = strings.TrimSpace(*reportPath)
	}
	baseDir := filepath.Dir(basePath)
	if baseDir == "." {
		baseDir = ""
	}

	if err := viewer.Serve(viewer.Options{
		EventsPath:    defaultSibling(*inPath, baseDir, "events.jsonl"),
		ReportPath:    *reportPath,
		FlowsPath:     defaultSibling(*flowsPath, baseDir, "flows.jsonl"),
		InventoryPath: defaultSibling(*inventoryPath, baseDir, "device_inventory.json"),
		Addr:          *addr,
		OpenBrowser:   *openBrowserFlag,
		WebDist:       *webDist,
	}); err != nil {
		log.Fatal(err)
	}
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
