package main

import (
	"flag"
	"log"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/knowledge"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug payload logging")
	iface := flag.String("i", "eth1", "interface to capture on")
	inventoryOut := flag.String("inventory-out", "device_inventory.json", "path to write device inventory snapshot JSON (empty to disable)")
	inventoryInterval := flag.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON")
	flag.Parse()

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

	handler := analyzer.NewFlowHandler(sink, *debug, db)
	var inventoryWriter *analyzer.DeviceInventoryWriter
	if *inventoryOut != "" {
		inventoryWriter = analyzer.NewDeviceInventoryWriter(*inventoryOut, *inventoryInterval, handler.DeviceInventory)
		inventoryWriter.Start()
		defer inventoryWriter.Stop()
	}
	engine := analyzer.NewEngine(handler)

	if err := engine.Run(*iface); err != nil {
		log.Fatal(err)
	}
}
