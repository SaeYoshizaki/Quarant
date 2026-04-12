package reportapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`

	RuleID   string `json:"rule_id,omitempty"`
	Category string `json:"category,omitempty"`
	FlowKey  string `json:"flow_key,omitempty"`
	Evidence string `json:"evidence,omitempty"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	Message string `json:"message,omitempty"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Report struct {
	GeneratedAt string  `json:"generated_at"`
	Source      string  `json:"source"`
	TotalEvents int     `json:"total_events"`
	Window      Window  `json:"window"`
	Severity    []KV    `json:"severity"`
	Rules       []KV    `json:"rules"`
	Categories  []KV    `json:"categories"`
	Sources     []KV    `json:"sources"`
	Events      []Event `json:"events"`
}

type Window struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

func LoadReport(path string) (Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return Report{}, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)

	var events []Event
	severityCount := map[string]int{}
	ruleCount := map[string]int{}
	categoryCount := map[string]int{}
	sourceCount := map[string]int{}

	var first time.Time
	var last time.Time

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}

		events = append(events, e)
		if e.Severity != "" {
			severityCount[e.Severity]++
		}

		switch {
		case e.RuleID != "":
			ruleCount[e.RuleID]++
		case e.Type != "":
			ruleCount[e.Type]++
		}
		if e.Category != "" {
			categoryCount[e.Category]++
		}
		if e.SrcIP != "" {
			sourceCount[e.SrcIP]++
		}

		if first.IsZero() || e.Timestamp.Before(first) {
			first = e.Timestamp
		}
		if e.Timestamp.After(last) {
			last = e.Timestamp
		}
	}
	if err := sc.Err(); err != nil {
		return Report{}, fmt.Errorf("scan %s: %w", path, err)
	}

	sort.Slice(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return severityRank(events[i].Severity) > severityRank(events[j].Severity)
		}
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	rep := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      path,
		TotalEvents: len(events),
		Severity:    toSortedKV(severityCount),
		Rules:       toSortedKV(ruleCount),
		Categories:  toSortedKV(categoryCount),
		Sources:     toSortedKV(sourceCount),
		Events:      events,
	}
	if !first.IsZero() {
		rep.Window.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		rep.Window.End = last.UTC().Format(time.RFC3339)
	}

	return rep, nil
}

func toSortedKV(m map[string]int) []KV {
	items := make([]KV, 0, len(m))
	for k, v := range m {
		if k == "" {
			continue
		}
		items = append(items, KV{Key: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	return items
}

func severityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 3
	case "WARNING":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}
