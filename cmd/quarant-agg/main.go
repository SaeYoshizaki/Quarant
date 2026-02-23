package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"quarant/analyzer"
)

type Counter map[string]int

func (c Counter) Inc(key string) { c[key]++ }

type Pair struct {
	Key   string
	Count int
}

func topN(counter Counter, n int) []Pair {
	pairs := make([]Pair, 0, len(counter))
	for k, v := range counter {
		pairs = append(pairs, Pair{Key: k, Count: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Count == pairs[j].Count {
			return pairs[i].Key < pairs[j].Key
		}
		return pairs[i].Count > pairs[j].Count
	})
	if n > len(pairs) {
		n = len(pairs)
	}
	return pairs[:n]
}

func scoreDelta(evType string) int {
	switch evType {
	case "INSECURE_HTTP":
		return 30
	default:
		return 0
	}
}

func main() {
	path := flag.String("f", "events.jsonl", "path to events.jsonl")
	top := flag.Int("top", 10, "top N destinations/devices")
	flag.Parse()
	f, err := os.Open(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open %s: %v\n", *path, err)
		os.Exit(1)
	}
	defer f.Close()

	typeCount := Counter{}
	srcSeen := map[string]bool{}
	dstCount := Counter{}
	deviceScore := map[string]int{}
	deviceEventCount := Counter{}

	totalLines := 0
	badLines := 0

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		totalLines++
		line := sc.Bytes()

		var ev analyzer.Event
		if err := json.Unmarshal(line, &ev); err != nil {
			badLines++
			continue
		}

		typeCount.Inc(ev.Type)

		if ev.SrcIP != "" {
			srcSeen[ev.SrcIP] = true
			deviceEventCount.Inc(ev.SrcIP)
			deviceScore[ev.SrcIP] += scoreDelta(ev.Type)
		}

		if ev.DstIP != "" {
			key := fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort)
			dstCount.Inc(key)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scan error: %v\n", err)
		os.Exit(1)
	}

	devPairs := make([]Pair, 0, len(deviceScore))
	for ip, score := range deviceScore {
		devPairs = append(devPairs, Pair{Key: ip, Count: score})
	}
	sort.Slice(devPairs, func(i, j int) bool {
		if devPairs[i].Count == devPairs[j].Count {
			return devPairs[i].Key < devPairs[j].Key
		}
		return devPairs[i].Count > devPairs[j].Count
	})
	if *top > len(devPairs) {
		*top = len(devPairs)
	}

	fmt.Println("Quarant Aggregation")
	fmt.Printf("File: %s\n", *path)
	fmt.Printf("Lines: %d (bad json: %d)\n", totalLines, badLines)
	fmt.Printf("Impacted devices (unique src_ip): %d\n", len(srcSeen))
	fmt.Println()

	fmt.Println("-- Event counts (by type) --")
	for _, p := range topN(typeCount, 999) {
		fmt.Printf("%-20s %d\n", p.Key, p.Count)
	}
	fmt.Println()

	fmt.Printf("-- Top %d destinations (dst_ip:dst_port) --\n", *top)
	for _, p := range topN(dstCount, *top) {
		fmt.Printf("%-25s %d\n", p.Key, p.Count)
	}
	fmt.Println()

	fmt.Printf("-- Top %d devices by score (temporary) --\n", *top)
	for i := 0; i < *top; i++ {
		ip := devPairs[i].Key
		score := devPairs[i].Count
		fmt.Printf("%-15s score=%-3d events=%d\n", ip, score, deviceEventCount[ip])
	}
}
