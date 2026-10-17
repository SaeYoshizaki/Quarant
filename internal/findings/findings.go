// Package findings condenses the event stream into one record per device and
// condition. Rules report per flow, so one device with one cleartext service
// produced hundreds of identical events a day (1,579-4,726 WARNING+ events
// per UNSW day against 14-149 alerts from Suricata and Zeek, EXPERIMENTS S2).
// The events stay the raw record; this package adds two summary levels:
//
//   - Finding: device x event type (how often, when, towards how many
//     destinations, with which basis).
//   - Condition: device x condition, where event types that restate the same
//     observed fact with a different inference (see conditionOf) are merged.
//
// Nothing here creates a new judgement: counts, times and the strongest
// severity/basis are taken from the events themselves.
package findings

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Event is the subset of an analyzer event used here.
type Event struct {
	TS           time.Time `json:"ts"`
	Type         string    `json:"type"`
	Severity     string    `json:"severity"`
	RuleID       string    `json:"rule_id"`
	FlowKey      string    `json:"flow_key"`
	Evidence     string    `json:"evidence"`
	Confidence   string    `json:"confidence"`
	Basis        string    `json:"basis"`
	ObservedFact string    `json:"observed_fact"`
	Inference    string    `json:"inference"`
	Limitation   string    `json:"limitation"`
	DeviceKey    string    `json:"device_key"`
	Debug        bool      `json:"debug"`
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	DstPort      uint16    `json:"dst_port"`
}

// Finding is one device x event type.
type Finding struct {
	Device            string    `json:"device"`
	MAC               string    `json:"mac,omitempty"`
	Type              string    `json:"type"`
	Condition         string    `json:"condition"`
	Severity          string    `json:"severity"`
	Basis             []string  `json:"basis"`
	Confidence        string    `json:"confidence,omitempty"`
	Events            int       `json:"events"`
	Flows             int       `json:"flows"`
	Destinations      int       `json:"destinations"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	ExampleDests      []string  `json:"example_destinations,omitempty"`
	ExampleEvidence   []string  `json:"example_evidence,omitempty"`
	ObservedFact      string    `json:"observed_fact,omitempty"`
	Inference         string    `json:"inference,omitempty"`
	Limitation        string    `json:"limitation,omitempty"`
	DerivedFromOthers bool      `json:"derived,omitempty"`
}

// Condition is one device x condition: the findings that report it.
type Condition struct {
	Device       string    `json:"device"`
	MAC          string    `json:"mac,omitempty"`
	Condition    string    `json:"condition"`
	Severity     string    `json:"severity"`
	Basis        []string  `json:"basis"`
	Types        []string  `json:"types"`
	Events       int       `json:"events"`
	Destinations int       `json:"destinations"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Derived      bool      `json:"derived,omitempty"`
}

// Report is what findings.json holds.
type Report struct {
	// MinSeverity is the lowest severity included.
	MinSeverity string `json:"min_severity"`
	Counts      struct {
		Events     int `json:"events"`
		Findings   int `json:"findings"`
		Conditions int `json:"conditions"`
		Devices    int `json:"devices"`
	} `json:"counts"`
	Conditions []Condition `json:"conditions"`
	Findings   []Finding   `json:"findings"`
	Note       string      `json:"note"`
}

// conditionGroups merges event types that restate one observed fact. A type
// joins a group only when its observed_fact describes the same observation;
// types with distinct observations (each credential exposure, a weak TLS
// version, a certificate anomaly) remain their own condition.
var conditionGroups = map[string][]string{
	// "HTTP without transport encryption was observed", read as an API,
	// as cloud/backend traffic, or against the category baseline.
	"cleartext_http": {"INSECURE_HTTP", "I3_API_OVER_PLAINTEXT", "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL", "I6_HTTP_BASELINE_PLAINTEXT"},
	// The ClientHello's cipher list.
	"weak_tls_offered": {"I7_TLS_WEAK_CIPHER_OFFERED", "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED"},
	// The ServerHello's selected suite, reported by two rules.
	"weak_cipher_selected": {"I7_TLS_WEAK_CIPHER_SELECTED", "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED"},
	// A destination or protocol outside the learned category baseline.
	"baseline_deviation": {"I6_HTTP_BASELINE_UNEXPECTED_DOMAIN", "I6_TLS_UNEXPECTED_SNI_OBSERVED", "I3_UNEXPECTED_CLOUD_ENDPOINT",
		"I6_HTTP_UNEXPECTED_COMMUNICATION", "I6_HTTP_BASELINE_PROTOCOL_MISMATCH"},
	// Management-style HTTP paths.
	"management_interface": {"I2_HTTP_ADMIN_INTERFACE_SUSPECTED", "I3_MANAGEMENT_API_EXPOSED", "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED"},
	// The same cleartext service seen by port and by protocol content.
	"telnet_service":  {"INSECURE_TELNET", "I2_TELNET_SERVICE_OBSERVED", "I2_TELNET_PROTOCOL_EVIDENCE"},
	"mqtt_plaintext":  {"INSECURE_MQTT", "I2_MQTT_PROTOCOL_EVIDENCE"},
	"ftp_service":     {"I2_FTP_SERVICE_OBSERVED"},
	"composite_risks": {"R1_COMPOSITE_RISK", "R1_QUARANTINE_RECOMMENDATION", "I4_I5_COMBINED_RISK"},
}

// derivedTypes are computed from other findings, not from traffic directly.
var derivedTypes = map[string]bool{"R1_COMPOSITE_RISK": true, "R1_QUARANTINE_RECOMMENDATION": true, "I4_I5_COMBINED_RISK": true}

var typeCondition = func() map[string]string {
	m := map[string]string{}
	for c, types := range conditionGroups {
		for _, t := range types {
			m[t] = c
		}
	}
	return m
}()

// ConditionOf names the condition an event type belongs to (the type itself,
// lower-cased, when it is not merged with others).
func ConditionOf(eventType string) string {
	if c, ok := typeCondition[eventType]; ok {
		return c
	}
	return strings.ToLower(eventType)
}

var severityRank = map[string]int{"INFO": 0, "WARNING": 1, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
var basisRank = map[string]int{"observed": 0, "inferred": 1, "reference_match": 2}
var confidenceRank = map[string]int{"low": 0, "medium": 1, "high": 2, "strong": 3}

const (
	maxExamples = 3
	maxEvidence = 160
)

// Build condenses events at or above minSeverity. macs maps device IPs to
// MAC addresses (from device_inventory.json) so that a device seen under
// several IPs is still one device; it may be nil.
func Build(events []Event, macs map[string]string, minSeverity string) Report {
	minRank := severityRank[strings.ToUpper(minSeverity)]
	type acc struct {
		f      Finding
		flows  map[string]bool
		dests  map[string]bool
		basis  map[string]bool
		evSeen map[string]bool
	}
	accs := map[[2]string]*acc{}
	rep := Report{MinSeverity: strings.ToUpper(minSeverity)}
	for _, e := range events {
		if e.Debug || severityRank[strings.ToUpper(e.Severity)] < minRank {
			continue
		}
		rep.Counts.Events++
		dev := e.DeviceKey
		if dev == "" {
			dev = e.SrcIP
		}
		id := dev
		if m := macs[dev]; m != "" {
			id = m
		}
		k := [2]string{id, e.Type}
		a := accs[k]
		if a == nil {
			a = &acc{f: Finding{Device: dev, MAC: macs[dev], Type: e.Type, Condition: ConditionOf(e.Type), Severity: strings.ToUpper(e.Severity),
				Confidence: e.Confidence, FirstSeen: e.TS, LastSeen: e.TS, ObservedFact: e.ObservedFact, Inference: e.Inference,
				Limitation: e.Limitation, DerivedFromOthers: derivedTypes[e.Type]},
				flows: map[string]bool{}, dests: map[string]bool{}, basis: map[string]bool{}, evSeen: map[string]bool{}}
			accs[k] = a
		}
		f := &a.f
		f.Events++
		if severityRank[strings.ToUpper(e.Severity)] > severityRank[f.Severity] {
			f.Severity = strings.ToUpper(e.Severity)
		}
		if confidenceRank[strings.ToLower(e.Confidence)] > confidenceRank[strings.ToLower(f.Confidence)] {
			f.Confidence = e.Confidence
		}
		if e.TS.Before(f.FirstSeen) {
			f.FirstSeen = e.TS
		}
		if e.TS.After(f.LastSeen) {
			f.LastSeen = e.TS
		}
		if e.Basis != "" {
			a.basis[e.Basis] = true
		}
		if e.FlowKey != "" {
			a.flows[e.FlowKey] = true
		}
		if e.DstIP != "" {
			d := fmt.Sprintf("%s:%d", e.DstIP, e.DstPort)
			if !a.dests[d] && len(f.ExampleDests) < maxExamples {
				f.ExampleDests = append(f.ExampleDests, d)
			}
			a.dests[d] = true
		}
		// Evidence strings are already masked by the rules; they are cut
		// short and deduplicated, never extended.
		if ev := truncate(e.Evidence, maxEvidence); ev != "" && !a.evSeen[ev] && len(f.ExampleEvidence) < maxExamples {
			a.evSeen[ev] = true
			f.ExampleEvidence = append(f.ExampleEvidence, ev)
		}
	}

	conds := map[[2]string]*Condition{}
	condDests := map[[2]string]map[string]bool{}
	devices := map[string]bool{}
	for k, a := range accs {
		f := a.f
		f.Flows, f.Destinations = len(a.flows), len(a.dests)
		f.Basis = sortedBasis(a.basis)
		rep.Findings = append(rep.Findings, f)
		devices[k[0]] = true

		ck := [2]string{k[0], f.Condition}
		c := conds[ck]
		if c == nil {
			c = &Condition{Device: f.Device, MAC: f.MAC, Condition: f.Condition, Severity: f.Severity, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen, Derived: true}
			conds[ck] = c
			condDests[ck] = map[string]bool{}
		}
		c.Types = append(c.Types, f.Type)
		c.Events += f.Events
		c.Derived = c.Derived && f.DerivedFromOthers
		if severityRank[f.Severity] > severityRank[c.Severity] {
			c.Severity = f.Severity
		}
		if f.FirstSeen.Before(c.FirstSeen) {
			c.FirstSeen = f.FirstSeen
		}
		if f.LastSeen.After(c.LastSeen) {
			c.LastSeen = f.LastSeen
		}
		merged := map[string]bool{}
		for _, b := range c.Basis {
			merged[b] = true
		}
		for b := range a.basis {
			merged[b] = true
		}
		c.Basis = sortedBasis(merged)
		for d := range a.dests {
			condDests[ck][d] = true
		}
	}
	for ck, c := range conds {
		sort.Strings(c.Types)
		c.Destinations = len(condDests[ck])
		rep.Conditions = append(rep.Conditions, *c)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		return a.Type < b.Type
	})
	sort.Slice(rep.Conditions, func(i, j int) bool {
		a, b := rep.Conditions[i], rep.Conditions[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		return a.Condition < b.Condition
	})
	rep.Counts.Findings = len(rep.Findings)
	rep.Counts.Conditions = len(rep.Conditions)
	rep.Counts.Devices = len(devices)
	rep.Note = "Summary of events.jsonl. A finding is one device x event type; a condition merges event types that restate the same observed fact. " +
		"Counts and times come from the events; severity and basis are the strongest seen. Absence of a condition is not evidence that it does not hold."
	return rep
}

func sortedBasis(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for b := range m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return basisRank[out[i]] < basisRank[out[j]] })
	return out
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n-- // do not cut a multi-byte character
	}
	return s[:n] + "…"
}

// ReadEvents reads events.jsonl, skipping malformed lines.
func ReadEvents(r io.Reader) ([]Event, int, error) {
	var out []Event
	bad := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			bad++
			continue
		}
		out = append(out, e)
	}
	return out, bad, sc.Err()
}

// ReadMACs maps device IPs to MAC addresses from device_inventory.json. A
// missing file gives an empty map.
func ReadMACs(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var inv struct {
		Devices []struct {
			IP  string `json:"ip"`
			MAC string `json:"mac_address"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := map[string]string{}
	for _, d := range inv.Devices {
		if d.MAC != "" {
			out[d.IP] = strings.ToLower(d.MAC)
		}
	}
	return out, nil
}

// FromRun builds the report for an analysis output (events.jsonl and,
// optionally, device_inventory.json).
func FromRun(eventsPath, inventoryPath, minSeverity string) (Report, error) {
	f, err := os.Open(eventsPath)
	if err != nil {
		return Report{}, err
	}
	defer f.Close()
	events, _, err := ReadEvents(f)
	if err != nil {
		return Report{}, err
	}
	macs := map[string]string{}
	if inventoryPath != "" {
		if macs, err = ReadMACs(inventoryPath); err != nil {
			return Report{}, err
		}
	}
	return Build(events, macs, minSeverity), nil
}

// Write stores the report as indented JSON.
func Write(rep Report, outPath string) error {
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// WriteFromRun is FromRun followed by Write.
func WriteFromRun(eventsPath, inventoryPath, outPath, minSeverity string) (Report, error) {
	rep, err := FromRun(eventsPath, inventoryPath, minSeverity)
	if err != nil {
		return rep, err
	}
	return rep, Write(rep, outPath)
}
