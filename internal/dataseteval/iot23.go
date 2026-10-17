// Package dataseteval evaluates Quarant output against the ground truth of
// public datasets (see docs/DATASETS.md). Each evaluator reports, per
// labelled condition, whether Quarant detected it, missed it, or has no
// detector for it, so results separate detector quality from coverage gaps.
package dataseteval

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IoT23Flow is one row of an IoT-23 conn.log.labeled file.
type IoT23Flow struct {
	TS       time.Time
	OrigH    string
	OrigP    uint16
	RespH    string
	RespP    uint16
	Proto    string
	State    string
	Label    string // Benign | Malicious
	DetLabel string // e.g. PartOfAHorizontalPortScan, C&C-HeartBeat, "-"
}

// ParseIoT23Labels reads a Zeek conn.log with IoT-23's label columns. Older
// releases put "tunnel_parents label detailed-label" into one tab field
// separated by spaces; both layouts are accepted.
func ParseIoT23Labels(r io.Reader) ([]IoT23Flow, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	var fields []string
	idx := map[string]int{}
	var out []IoT23Flow
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#fields") {
			// Older releases name the last column "tunnel_parents   label
			// detailed-label" (space separated); split such names.
			fields = nil
			for _, name := range strings.Split(line, "\t")[1:] {
				fields = append(fields, strings.Fields(name)...)
			}
			for i, f := range fields {
				if f == "detailed-label" {
					f = "det_label"
				}
				idx[f] = i
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || fields == nil {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) < len(fields) {
			// Merged trailing field: split it on whitespace.
			last := strings.Fields(cols[len(cols)-1])
			cols = append(cols[:len(cols)-1], last...)
		}
		get := func(name string) string {
			if i, ok := idx[name]; ok && i < len(cols) {
				return cols[i]
			}
			return ""
		}
		label, det := get("label"), get("det_label")
		sec, err := strconv.ParseFloat(get("ts"), 64)
		if err != nil {
			continue
		}
		op, _ := strconv.Atoi(get("id.orig_p"))
		rp, _ := strconv.Atoi(get("id.resp_p"))
		out = append(out, IoT23Flow{
			TS:    time.Unix(0, int64(sec*1e9)).UTC(),
			OrigH: get("id.orig_h"), OrigP: uint16(op),
			RespH: get("id.resp_h"), RespP: uint16(rp),
			Proto: get("proto"), State: get("conn_state"),
			Label: label, DetLabel: det,
		})
	}
	return out, sc.Err()
}

// Event is the subset of a Quarant event used by the dataset evaluators.
type Event struct {
	TS        time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  string    `json:"severity"`
	Basis     string    `json:"basis"`
	DeviceKey string    `json:"device_key"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	DstPort   uint16    `json:"dst_port"`
	Evidence  string    `json:"evidence"`
	Debug     bool      `json:"debug"`
}

// labelDetectors maps IoT-23 detailed labels to Quarant event types and how
// to match them. An empty list means Quarant has no detector for the class.
var labelDetectors = map[string]struct {
	types []string
	byDst bool // the event's dst_ip must be one of the labelled destinations
}{
	"PartOfAHorizontalPortScan": {types: []string{"OUTBOUND_SCAN_SUSPECTED", "LATERAL_SCAN_SUSPECTED"}},
	// IoT-23 "Attack" flows are mostly outbound brute force (e.g. SSH); there
	// is no brute-force detector, but repeated attempts per target surface them.
	"Attack":                     {types: []string{"PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C":                        {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C-HeartBeat":              {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C-Torii":                  {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C-Mirai":                  {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C-FileDownload":           {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
	"C&C-HeartBeat-FileDownload": {types: []string{"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS"}, byDst: true},
}

type IoT23Class struct {
	Label        string         `json:"detailed_label"`
	Flows        int            `json:"flows"`
	TCPFlows     int            `json:"tcp_flows"`
	Destinations int            `json:"distinct_destinations"`
	TopPorts     []string       `json:"top_dst_ports"`
	Outcome      string         `json:"outcome"` // detected | missed | no_detector
	Matched      map[string]int `json:"matched_event_types,omitempty"`
	Note         string         `json:"note,omitempty"`
}

type IoT23Report struct {
	Scenario       string       `json:"scenario"`
	Host           string       `json:"host"`
	CaptureStart   string       `json:"capture_start"`
	CaptureEnd     string       `json:"capture_end"`
	TotalFlows     int          `json:"labelled_flows"`
	MaliciousFlows int          `json:"malicious_flows"`
	Classes        []IoT23Class `json:"classes"`
	// FindingsOnHost counts WARNING+ Quarant findings for the host by type.
	FindingsOnHost map[string]int `json:"findings_on_host"`
	// BehaviourOutsideLabels lists behaviour findings whose destination is
	// not part of any malicious labelled flow (candidate false positives).
	BehaviourOutsideLabels []string `json:"behaviour_outside_labels,omitempty"`
}

// EvaluateIoT23 compares Quarant events with IoT-23 flow labels. host is the
// infected (or benign) device; if empty, the most frequent originator wins.
func EvaluateIoT23(scenario string, flows []IoT23Flow, events []Event, host string) IoT23Report {
	if host == "" {
		count := map[string]int{}
		for _, f := range flows {
			count[f.OrigH]++
		}
		best := 0
		for ip, n := range count {
			if n > best || (n == best && ip < host) {
				host, best = ip, n
			}
		}
	}
	rep := IoT23Report{Scenario: scenario, Host: host, FindingsOnHost: map[string]int{}}

	type agg struct {
		flows, tcp int
		dsts       map[string]bool
		ports      map[string]int
	}
	classes := map[string]*agg{}
	maliciousDst := map[string]bool{}
	var start, end time.Time
	for _, f := range flows {
		if f.OrigH != host {
			continue
		}
		rep.TotalFlows++
		if start.IsZero() || f.TS.Before(start) {
			start = f.TS
		}
		if f.TS.After(end) {
			end = f.TS
		}
		if !strings.EqualFold(f.Label, "Malicious") {
			continue
		}
		rep.MaliciousFlows++
		maliciousDst[f.RespH] = true
		name := f.DetLabel
		if name == "" || name == "-" {
			name = "Malicious(unspecified)"
		}
		a := classes[name]
		if a == nil {
			a = &agg{dsts: map[string]bool{}, ports: map[string]int{}}
			classes[name] = a
		}
		a.flows++
		if f.Proto == "tcp" {
			a.tcp++
		}
		a.dsts[f.RespH] = true
		a.ports[fmt.Sprintf("%s/%d", f.Proto, f.RespP)]++
	}
	if !start.IsZero() {
		rep.CaptureStart, rep.CaptureEnd = start.Format(time.RFC3339), end.Format(time.RFC3339)
	}

	hostEvents := []Event{}
	for _, e := range events {
		if e.Debug {
			continue
		}
		dev := e.DeviceKey
		if dev == "" {
			dev = e.SrcIP
		}
		if dev != host {
			continue
		}
		hostEvents = append(hostEvents, e)
		if isWarningOrAbove(e.Severity) || strings.HasSuffix(e.Type, "_SUSPECTED") || e.Type == "PERIODIC_COMMUNICATION_OBSERVED" || e.Type == "PERSISTENT_CONNECTION_ATTEMPTS" {
			rep.FindingsOnHost[e.Type]++
		}
		if (strings.HasSuffix(e.Type, "SCAN_SUSPECTED") || e.Type == "PERIODIC_COMMUNICATION_OBSERVED" || e.Type == "PERSISTENT_CONNECTION_ATTEMPTS") && e.DstIP != "" && !maliciousDst[e.DstIP] {
			rep.BehaviourOutsideLabels = append(rep.BehaviourOutsideLabels, fmt.Sprintf("%s dst=%s:%d", e.Type, e.DstIP, e.DstPort))
		}
	}
	sort.Strings(rep.BehaviourOutsideLabels)

	names := make([]string, 0, len(classes))
	for n := range classes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := classes[n]
		c := IoT23Class{Label: n, Flows: a.flows, TCPFlows: a.tcp, Destinations: len(a.dsts), TopPorts: topKeys(a.ports, 3)}
		det, ok := labelDetectors[n]
		if !ok || len(det.types) == 0 {
			c.Outcome = "no_detector"
			c.Note = "Quarant has no detector for this class yet"
		} else {
			c.Matched = map[string]int{}
			for _, e := range hostEvents {
				for _, t := range det.types {
					if e.Type == t && (!det.byDst || a.dsts[e.DstIP]) {
						c.Matched[t]++
					}
				}
			}
			c.Outcome = "missed"
			if len(c.Matched) > 0 {
				c.Outcome = "detected"
			} else if a.tcp == 0 {
				c.Note = "all labelled flows are non-TCP; Quarant's behaviour analysis is TCP-only"
			}
		}
		rep.Classes = append(rep.Classes, c)
	}
	return rep
}

func isWarningOrAbove(s string) bool {
	switch strings.ToUpper(s) {
	case "WARNING", "MEDIUM", "HIGH", "CRITICAL":
		return true
	}
	return false
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	list := make([]kv, 0, len(m))
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].v != list[j].v {
			return list[i].v > list[j].v
		}
		return list[i].k < list[j].k
	})
	out := []string{}
	for i := 0; i < len(list) && i < n; i++ {
		out = append(out, fmt.Sprintf("%s(%d)", list[i].k, list[i].v))
	}
	return out
}
