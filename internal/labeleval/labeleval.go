// Package labeleval compares Quarant events against ground-truth labels
// (such as those produced by `quarant synth`) and reports which labelled
// conditions were detected, which were missed, and which reported findings
// have no label. It is the measurement tool for detection research: it does
// not judge unlabelled findings as false positives automatically, because
// several rules legitimately describe one condition from different angles.
package labeleval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"quarant/internal/synth"
)

// Event is the subset of an events.jsonl record used for evaluation.
type Event struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	DeviceKey string `json:"device_key"`
	SrcIP     string `json:"src_ip"`
	Basis     string `json:"basis"`
	Debug     bool   `json:"debug"`
}

// KindEventTypes maps a label kind to the event types that count as detecting
// it. Keep this table in sync with docs/EVALUATION.md.
var KindEventTypes = map[string][]string{
	"weak_tls_version":           {"I7_TLS_WEAK_VERSION_OBSERVED"},
	"cleartext_credentials_http": {"INSECURE_HTTP_AUTH"},
	"cleartext_firmware_update":  {"I4_INSECURE_FIRMWARE_UPDATE_HTTP"},
	"telnet_service_exposed":     {"I2_TELNET_SERVICE_OBSERVED", "I2_TELNET_PROTOCOL_EVIDENCE"},
	"http_admin_interface":       {"I2_HTTP_ADMIN_INTERFACE_SUSPECTED"},
	"cleartext_credentials_mqtt": {"INSECURE_MQTT_CREDENTIALS"},
	"periodic_beacon":            {"PERIODIC_COMMUNICATION_OBSERVED"},
	"outbound_telnet_scan":       {"OUTBOUND_SCAN_SUSPECTED"},
	"known_vulnerable_firmware":  {"I5_KNOWN_VULNERABLE_COMPONENT"},
}

// NegativeKindForbidden lists event-type prefixes that must not appear on a
// device carrying a negative-control label.
var NegativeKindForbidden = map[string][]string{
	"benign_modern_tls": {"I7_TLS_", "INSECURE_"},
}

// contextTypes are informational or aggregate events that are not findings
// about a specific condition.
var contextTypes = map[string]bool{
	"TLS_CLIENT_HELLO":              true,
	"I8_NEW_DEVICE_OBSERVED":        true,
	"I8_UNREGISTERED_DEVICE_ACTIVE": true,
	"R1_COMPOSITE_RISK":             true,
	"R1_QUARANTINE_RECOMMENDATION":  true,
}

type LabelResult struct {
	synth.Label
	// Outcome: detected | missed | not_observable_as_expected |
	// detected_by_reference (a "hidden" condition reported from a
	// reference DB match) | negative_ok | negative_violated.
	Outcome       string   `json:"outcome"`
	MatchedEvents []string `json:"matched_event_types,omitempty"`
}

type UnlabelledFinding struct {
	DeviceIP string `json:"device_ip"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Basis    string `json:"basis"`
	Count    int    `json:"count"`
}

type Report struct {
	Scenario string        `json:"scenario"`
	Labels   []LabelResult `json:"labels"`
	Metrics  Metrics       `json:"metrics"`
	// Unlabelled lists WARNING+ findings that match no label. They need
	// human review: each is either a redundant view of a labelled
	// condition, an unlabelled true condition, or a false positive.
	Unlabelled []UnlabelledFinding `json:"unlabelled_findings"`
	Notes      []string            `json:"notes"`
}

type Metrics struct {
	ObservableLabels   int     `json:"observable_labels"`
	Detected           int     `json:"detected"`
	Missed             int     `json:"missed"`
	Recall             float64 `json:"recall"`
	HiddenLabels       int     `json:"hidden_labels"`
	HiddenReported     int     `json:"hidden_reported_by_reference"`
	NegativeControls   int     `json:"negative_controls"`
	NegativeViolations int     `json:"negative_violations"`
	FindingEvents      int     `json:"finding_events"`
	UnlabelledTypes    int     `json:"unlabelled_finding_types"`
}

// LoadEvents reads events.jsonl, skipping debug events and malformed lines.
func LoadEvents(r io.Reader) ([]Event, int, error) {
	var out []Event
	bad := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			bad++
			continue
		}
		if e.Debug {
			continue
		}
		if e.DeviceKey == "" {
			e.DeviceKey = e.SrcIP
		}
		out = append(out, e)
	}
	return out, bad, sc.Err()
}

func LoadScenario(path string) (synth.Scenario, error) {
	var s synth.Scenario
	data, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("parse labels %s: %w", path, err)
	}
	return s, nil
}

func severityAtLeastWarning(s string) bool {
	switch strings.ToUpper(s) {
	case "WARNING", "MEDIUM", "HIGH", "CRITICAL":
		return true
	}
	return false
}

// Evaluate matches events to labels.
func Evaluate(scenario synth.Scenario, events []Event) Report {
	type key struct{ ip, typ string }
	byKey := map[key][]Event{}
	for _, e := range events {
		byKey[key{e.DeviceKey, e.Type}] = append(byKey[key{e.DeviceKey, e.Type}], e)
	}
	explained := map[key]bool{}

	rep := Report{Scenario: scenario.Name}
	for _, l := range scenario.Labels {
		res := LabelResult{Label: l}
		if forbidden, ok := NegativeKindForbidden[l.Kind]; ok {
			rep.Metrics.NegativeControls++
			for k := range byKey {
				if k.ip != l.DeviceIP {
					continue
				}
				for _, p := range forbidden {
					if strings.HasPrefix(k.typ, p) {
						res.MatchedEvents = append(res.MatchedEvents, k.typ)
					}
				}
			}
			sort.Strings(res.MatchedEvents)
			res.Outcome = "negative_ok"
			if len(res.MatchedEvents) > 0 {
				res.Outcome = "negative_violated"
				rep.Metrics.NegativeViolations++
			}
			rep.Labels = append(rep.Labels, res)
			continue
		}
		for _, typ := range KindEventTypes[l.Kind] {
			if len(byKey[key{l.DeviceIP, typ}]) > 0 {
				res.MatchedEvents = append(res.MatchedEvents, typ)
				explained[key{l.DeviceIP, typ}] = true
			}
		}
		detected := len(res.MatchedEvents) > 0
		switch {
		case l.Visibility == "hidden" && detected:
			res.Outcome = "detected_by_reference"
			rep.Metrics.HiddenLabels++
			rep.Metrics.HiddenReported++
		case l.Visibility == "hidden":
			res.Outcome = "not_observable_as_expected"
			rep.Metrics.HiddenLabels++
		case detected:
			res.Outcome = "detected"
			rep.Metrics.ObservableLabels++
			rep.Metrics.Detected++
		default:
			res.Outcome = "missed"
			rep.Metrics.ObservableLabels++
			rep.Metrics.Missed++
		}
		rep.Labels = append(rep.Labels, res)
	}
	if rep.Metrics.ObservableLabels > 0 {
		rep.Metrics.Recall = float64(rep.Metrics.Detected) / float64(rep.Metrics.ObservableLabels)
	}

	keys := make([]key, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ip != keys[j].ip {
			return keys[i].ip < keys[j].ip
		}
		return keys[i].typ < keys[j].typ
	})
	for _, k := range keys {
		evs := byKey[k]
		if contextTypes[k.typ] || !severityAtLeastWarning(evs[0].Severity) {
			continue
		}
		rep.Metrics.FindingEvents += len(evs)
		if explained[k] {
			continue
		}
		rep.Unlabelled = append(rep.Unlabelled, UnlabelledFinding{DeviceIP: k.ip, Type: k.typ, Severity: evs[0].Severity, Basis: evs[0].Basis, Count: len(evs)})
	}
	rep.Metrics.UnlabelledTypes = len(rep.Unlabelled)
	rep.Notes = []string{
		"recall counts only labels whose condition is observable on the wire.",
		"hidden labels document limits of passive monitoring; a hidden condition reported via reference_match is a claim about the device model, not a verified vulnerability.",
		"unlabelled findings are not automatically false positives: review each as redundant view, unlabelled true condition, or false positive.",
		"a synthetic scenario written with knowledge of the detectors measures regressions, not real-world detection performance.",
	}
	return rep
}

// WriteMarkdown renders the report as a table for humans.
func WriteMarkdown(w io.Writer, rep Report) {
	fmt.Fprintf(w, "# Label evaluation: %s\n\n", rep.Scenario)
	m := rep.Metrics
	fmt.Fprintf(w, "- Observable labels: %d, detected: %d, missed: %d, recall: %.2f\n", m.ObservableLabels, m.Detected, m.Missed, m.Recall)
	fmt.Fprintf(w, "- Hidden (not observable) labels: %d, reported via reference match: %d\n", m.HiddenLabels, m.HiddenReported)
	fmt.Fprintf(w, "- Negative controls: %d, violated: %d\n", m.NegativeControls, m.NegativeViolations)
	fmt.Fprintf(w, "- WARNING+ finding events: %d, unlabelled finding types: %d\n\n", m.FindingEvents, m.UnlabelledTypes)
	fmt.Fprintln(w, "| Label | Device | Kind | Outcome | Matched event types |")
	fmt.Fprintln(w, "|---|---|---|---|---|")
	for _, l := range rep.Labels {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s |\n", l.ID, l.DeviceIP, l.Kind, l.Outcome, strings.Join(l.MatchedEvents, ", "))
	}
	if len(rep.Unlabelled) > 0 {
		fmt.Fprintln(w, "\n## Unlabelled findings (need review)")
		fmt.Fprintln(w, "\n| Device | Type | Severity | Basis | Count |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, u := range rep.Unlabelled {
			fmt.Fprintf(w, "| %s | %s | %s | %s | %d |\n", u.DeviceIP, u.Type, u.Severity, u.Basis, u.Count)
		}
	}
	fmt.Fprintln(w, "\n## Notes")
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "- %s\n", n)
	}
}
