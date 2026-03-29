package main

import (
	"flag"
	"log"

	"quarant/analyzer"
	"quarant/analyzer/knowledge"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug payload logging")
	iface := flag.String("i", "eth1", "interface to capture on")
	flag.Parse()

	db, err := knowledge.LoadAll()
	if err != nil {
		log.Fatalf("load knowledge db: %v", err)
	}

	log.Printf(
		"knowledge db loaded: categories=%d communication_types=%d pii_types=%d policies=%d inference_categories=%d behavior_baselines=%d",
		len(db.DeviceCategories.Categories),
		len(db.CommunicationTypes.CommunicationTypes),
		len(db.PIITypes.PIITypes),
		len(db.CategoryPolicy),
		len(db.CategoryInference.Categories),
		len(db.BehaviorBaselines)-1,
	)

	sink, err := analyzer.NewJSONSink("events.jsonl")
	if err != nil {
		log.Fatal(err)
	}

	handler := analyzer.NewFlowHandler(sink, *debug, db)
	engine := analyzer.NewEngine(handler)

	if err := engine.Run(*iface); err != nil {
		log.Fatal(err)
	}
}
