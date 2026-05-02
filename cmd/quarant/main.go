package main

import (
	"flag"
	"log"
	"os"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/knowledge"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug payload logging")
	iface := flag.String("i", "eth1", "interface to capture on")
	pcapPath := flag.String("pcap", "", "pcap file to read, or - to read pcap stream from stdin")
	inventoryOut := flag.String("inventory-out", "device_inventory.json", "path to write device inventory snapshot JSON (empty to disable)")
	inventoryInterval := flag.Duration("inventory-interval", 10*time.Second, "interval to refresh device inventory snapshot JSON")
	flag.Parse()

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
	flowSink, err := analyzer.NewJSONSink("flows.jsonl")
	if err != nil {
		log.Fatal(err)
	}

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
