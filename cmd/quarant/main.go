package main

import (
	"log"
	"quarant/analyzer"
)

func main() {
	sink, err := analyzer.NewJSONSink("events.jsonl")
	if err != nil {
		log.Fatal(err)
	}
	handler := analyzer.NewFlowHandler(sink)
	engine := analyzer.NewEngine(handler)

	err = engine.Run("eth1")
	if err != nil {
		log.Fatal(err)
	}
}