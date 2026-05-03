package reportapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`

	RuleID                  string       `json:"rule_id,omitempty"`
	Category                string       `json:"category,omitempty"`
	FlowKey                 string       `json:"flow_key,omitempty"`
	OWASPTags               []string     `json:"owasp_tags,omitempty"`
	Confidence              string       `json:"confidence,omitempty"`
	Evidence                string       `json:"evidence,omitempty"`
	ObservedFact            string       `json:"observed_fact,omitempty"`
	Inference               string       `json:"inference,omitempty"`
	Limitation              string       `json:"limitation,omitempty"`
	Recommendation          string       `json:"recommendation,omitempty"`
	UserTitle               string       `json:"user_title,omitempty"`
	UserMessage             string       `json:"user_message,omitempty"`
	UserImpact              string       `json:"user_impact,omitempty"`
	ActionIDs               []string     `json:"action_ids,omitempty"`
	UserActions             []UserAction `json:"user_actions,omitempty"`
	RecommendedAction       string       `json:"recommended_action,omitempty"`
	DryRun                  bool         `json:"dry_run,omitempty"`
	Debug                   bool         `json:"debug,omitempty"`
	SuggestedFirewallAction string       `json:"suggested_firewall_action,omitempty"`
	DeviceKey               string       `json:"device_key,omitempty"`
	DeviceLabel             string       `json:"device_label,omitempty"`
	DeviceStatus            string       `json:"device_status,omitempty"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	Message string `json:"message,omitempty"`
}

type UserAction struct {
	ID          string `json:"id,omitempty"`
	Label       string `json:"label,omitempty"`
	Description string `json:"description,omitempty"`
	Difficulty  string `json:"difficulty,omitempty"`
	Priority    int    `json:"priority,omitempty"`
	Fallback    string `json:"fallback,omitempty"`
}

type KV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type Report struct {
	GeneratedAt          string  `json:"generated_at"`
	Source               string  `json:"source"`
	TotalEvents          int     `json:"total_events"`
	UserNotifications    int     `json:"user_notifications"`
	QuarantineCandidates int     `json:"quarantine_candidates"`
	UnknownDevices       int     `json:"unknown_devices"`
	Window               Window  `json:"window"`
	Severity             []KV    `json:"severity"`
	Rules                []KV    `json:"rules"`
	Categories           []KV    `json:"categories"`
	Sources              []KV    `json:"sources"`
	Events               []Event `json:"events"`
}

type Window struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

func LoadReport(path string) (Report, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return loadReportJSON(path)
	default:
		return loadEventsJSONLReport(path)
	}
}

func loadEventsJSONLReport(path string) (Report, error) {
	if strings.TrimSpace(path) == "" {
		return emptyReport(path), nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyReport(path), nil
		}
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
	unknownDevices := map[string]bool{}
	userNotifications := 0
	quarantineCandidates := 0

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
		if e.UserTitle != "" {
			userNotifications++
		}
		if e.RuleID == "R1_QUARANTINE_RECOMMENDATION" || e.Type == "R1_QUARANTINE_RECOMMENDATION" {
			quarantineCandidates++
		}
		if e.RuleID == "I8_UNREGISTERED_DEVICE_ACTIVE" || e.Type == "I8_UNREGISTERED_DEVICE_ACTIVE" {
			key := strings.TrimSpace(e.DeviceKey)
			if key == "" {
				key = strings.TrimSpace(e.SrcIP)
			}
			if key != "" {
				unknownDevices[key] = true
			}
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
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		Source:               path,
		TotalEvents:          len(events),
		UserNotifications:    userNotifications,
		QuarantineCandidates: quarantineCandidates,
		UnknownDevices:       len(unknownDevices),
		Severity:             toSortedKV(severityCount),
		Rules:                toSortedKV(ruleCount),
		Categories:           toSortedKV(categoryCount),
		Sources:              toSortedKV(sourceCount),
		Events:               events,
	}
	if !first.IsZero() {
		rep.Window.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		rep.Window.End = last.UTC().Format(time.RFC3339)
	}

	return rep, nil
}

func emptyReport(source string) Report {
	return Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Source:      source,
		Severity:    []KV{},
		Rules:       []KV{},
		Categories:  []KV{},
		Sources:     []KV{},
		Events:      []Event{},
	}
}

type rawReport struct {
	GeneratedAt          string  `json:"generated_at"`
	Source               string  `json:"source"`
	TotalEvents          int     `json:"total_events"`
	UserNotifications    int     `json:"user_notifications"`
	QuarantineCandidates int     `json:"quarantine_candidates"`
	UnknownDevices       int     `json:"unknown_devices"`
	Window               Window  `json:"window"`
	Severity             []KV    `json:"severity"`
	Rules                []KV    `json:"rules"`
	Categories           []KV    `json:"categories"`
	Sources              []KV    `json:"sources"`
	SrcIP                []KV    `json:"src_ip"`
	Flows                []KV    `json:"flows"`
	Events               []Event `json:"events"`
}

func loadReportJSON(path string) (Report, error) {
	if strings.TrimSpace(path) == "" {
		return emptyReport(path), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return emptyReport(path), nil
		}
		return Report{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return emptyReport(path), nil
	}

	var rep rawReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return emptyReport(path), nil
	}

	normalized := Report{
		GeneratedAt:          rep.GeneratedAt,
		Source:               rep.Source,
		TotalEvents:          rep.TotalEvents,
		UserNotifications:    rep.UserNotifications,
		QuarantineCandidates: rep.QuarantineCandidates,
		UnknownDevices:       rep.UnknownDevices,
		Window:               rep.Window,
		Severity:             rep.Severity,
		Rules:                rep.Rules,
		Categories:           rep.Categories,
		Sources:              rep.Sources,
		Events:               rep.Events,
	}
	if normalized.GeneratedAt == "" {
		normalized.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if normalized.Source == "" {
		normalized.Source = path
	}
	if normalized.TotalEvents == 0 && len(normalized.Events) > 0 {
		normalized.TotalEvents = len(normalized.Events)
	}
	if len(normalized.Sources) == 0 && len(rep.SrcIP) > 0 {
		normalized.Sources = rep.SrcIP
	}
	if len(normalized.Categories) == 0 && len(normalized.Events) > 0 {
		categoryCount := map[string]int{}
		for _, event := range normalized.Events {
			if event.Category != "" {
				categoryCount[event.Category]++
			}
		}
		normalized.Categories = toSortedKV(categoryCount)
	}
	if normalized.Window.Start == "" || normalized.Window.End == "" {
		first, last := eventWindow(normalized.Events)
		if normalized.Window.Start == "" && !first.IsZero() {
			normalized.Window.Start = first.UTC().Format(time.RFC3339)
		}
		if normalized.Window.End == "" && !last.IsZero() {
			normalized.Window.End = last.UTC().Format(time.RFC3339)
		}
	}
	sort.Slice(normalized.Events, func(i, j int) bool {
		if normalized.Events[i].Timestamp.Equal(normalized.Events[j].Timestamp) {
			return severityRank(normalized.Events[i].Severity) > severityRank(normalized.Events[j].Severity)
		}
		return normalized.Events[i].Timestamp.After(normalized.Events[j].Timestamp)
	})
	return normalized, nil
}

func eventWindow(events []Event) (time.Time, time.Time) {
	var first time.Time
	var last time.Time
	for _, event := range events {
		if event.Timestamp.IsZero() {
			continue
		}
		if first.IsZero() || event.Timestamp.Before(first) {
			first = event.Timestamp
		}
		if event.Timestamp.After(last) {
			last = event.Timestamp
		}
	}
	return first, last
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
		return 4
	case "HIGH":
		return 3
	case "WARNING":
		return 2
	case "INFO":
		return 1
	default:
		return 0
	}
}
