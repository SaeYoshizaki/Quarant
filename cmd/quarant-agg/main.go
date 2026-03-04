package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`

	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	FlowKey  string `json:"flow_key"`

	SrcIP   string `json:"src_ip"`
	SrcPort int    `json:"src_port"`
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`

	Message  string `json:"message"`
	Evidence string `json:"evidence"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Report struct {
	Window struct {
		Start string `json:"start,omitempty"`
		End   string `json:"end,omitempty"`
	} `json:"window"`
	TotalEvents int `json:"total_events"`

	Severity []KV `json:"severity"`
	Rules    []KV `json:"rules"`
	SrcIP    []KV `json:"src_ip"`
	Flows    []KV `json:"flows"`
}

func main() {
	inPath := flag.String("in", "", "input events.jsonl path (default: stdin)")
	format := flag.String("format", "text", "output format: text|json")
	topN := flag.Int("top", 10, "show top N items per section (0 = all)")
	flag.Parse()

	r, closer, err := openInput(*inPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open input:", err)
		os.Exit(1)
	}
	if closer != nil {
		defer closer.Close()
	}

	rep, err := aggregate(r, *topN)
	if err != nil {
		fmt.Fprintln(os.Stderr, "aggregate:", err)
		os.Exit(1)
	}

	switch *format {
	case "text":
		printText(rep, *topN)
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "json encode:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown -format:", *format, "(use text|json)")
		os.Exit(1)
	}
}

func openInput(path string) (io.Reader, *os.File, error) {
	if path == "" || path == "-" {
		return os.Stdin, nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

func aggregate(r io.Reader, topN int) (Report, error) {
	sc := bufio.NewScanner(r)

	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 8*1024*1024)

	total := 0
	ruleCount := map[string]int{}
	srcCount := map[string]int{}
	severityCount := map[string]int{}
	flowCount := map[string]int{}

	var first time.Time
	var last time.Time

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}

		total++
		if first.IsZero() {
			first = e.Timestamp
		}
		last = e.Timestamp

		if e.RuleID != "" {
			ruleCount[e.RuleID]++
		} else if e.Type != "" {
			ruleCount[e.Type]++
		}

		if e.SrcIP != "" {
			srcCount[e.SrcIP]++
		}
		if e.Severity != "" {
			severityCount[e.Severity]++
		}
		if e.FlowKey != "" {
			flowCount[e.FlowKey]++
		}
	}

	if err := sc.Err(); err != nil {
		return Report{}, err
	}

	var rep Report
	rep.TotalEvents = total
	if !first.IsZero() {
		rep.Window.Start = first.UTC().Format(time.RFC3339Nano)
	}
	if !last.IsZero() {
		rep.Window.End = last.UTC().Format(time.RFC3339Nano)
	}

	rep.Severity = toSortedKV(severityCount, topN)
	rep.Rules = toSortedKV(ruleCount, topN)
	rep.SrcIP = toSortedKV(srcCount, topN)
	rep.Flows = toSortedKV(flowCount, topN)

	return rep, nil
}

func toSortedKV(m map[string]int, topN int) []KV {
	list := make([]KV, 0, len(m))
	for k, v := range m {
		list = append(list, KV{Key: k, Count: v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Count == list[j].Count {
			return list[i].Key < list[j].Key
		}
		return list[i].Count > list[j].Count
	})
	if topN > 0 && len(list) > topN {
		list = list[:topN]
	}
	return list
}

func printText(rep Report, topN int) {
	fmt.Println("=== Quarant Report ===")
	fmt.Println()

	fmt.Println("Window")
	fmt.Println(" Start:", rep.Window.Start)
	fmt.Println(" End  :", rep.Window.End)
	fmt.Println()

	fmt.Println("Total Events:", rep.TotalEvents)
	fmt.Println()

	printSection("Severity", rep.Severity, topN)
	printSection("Rules", rep.Rules, topN)
	printSection("Source IP", rep.SrcIP, topN)
	printSection("Flows", rep.Flows, topN)
}

func printSection(title string, items []KV, topN int) {
	fmt.Println(title)
	if len(items) == 0 {
		fmt.Println("  (none)")
		fmt.Println()
		return
	}
	for _, kv := range items {
		fmt.Printf("  %-40s %d\n", kv.Key, kv.Count)
	}
	fmt.Println()
}
