package main

import (
	"flag"
	"log"

	"quarant/analyzer"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug payload logging")
	iface := flag.String("i", "eth1", "interface to capture on")
	flag.Parse()

	sink, err := analyzer.NewJSONSink("events.jsonl")
	if err != nil {
		log.Fatal(err)
	}

	handler := analyzer.NewFlowHandler(sink, *debug)
	engine := analyzer.NewEngine(handler)

	if err := engine.Run(*iface); err != nil {
		log.Fatal(err)
	}
}
