package dataseteval

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"quarant/analyzer"
	"quarant/analyzer/device"
)

// LoadRun reads events.jsonl and device_inventory.json from an analysis
// output directory. Malformed event lines are counted and skipped.
func LoadRun(dir string) ([]Event, []device.InventorySnapshot, int, error) {
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, nil, 0, err
	}
	defer f.Close()
	var events []Event
	bad := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			bad++
			continue
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, bad, err
	}
	var inv analyzer.DeviceInventoryReport
	data, err := os.ReadFile(filepath.Join(dir, "device_inventory.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, bad, err
	}
	if err == nil {
		if err := json.Unmarshal(data, &inv); err != nil {
			return nil, nil, bad, fmt.Errorf("parse device_inventory.json: %w", err)
		}
	}
	return events, inv.Devices, bad, nil
}

// WriteIoT23Markdown renders an IoT-23 evaluation.
func WriteIoT23Markdown(w io.Writer, rep IoT23Report) {
	fmt.Fprintf(w, "### %s (host %s)\n\n", rep.Scenario, rep.Host)
	fmt.Fprintf(w, "Capture %s – %s; labelled flows from host %d, malicious %d\n\n", rep.CaptureStart, rep.CaptureEnd, rep.TotalFlows, rep.MaliciousFlows)
	if len(rep.Classes) > 0 {
		fmt.Fprintln(w, "| Label | Flows (TCP) | Destinations | Top ports | Outcome | Matched | Note |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|---|")
		for _, c := range rep.Classes {
			fmt.Fprintf(w, "| %s | %d (%d) | %d | %s | %s | %s | %s |\n", c.Label, c.Flows, c.TCPFlows, c.Destinations, strings.Join(c.TopPorts, " "), c.Outcome, fmtCounts(c.Matched), c.Note)
		}
	}
	fmt.Fprintf(w, "\nQuarant findings on host: %s\n", fmtCounts(rep.FindingsOnHost))
	if len(rep.BehaviourOutsideLabels) > 0 {
		fmt.Fprintf(w, "\nBehaviour findings toward destinations without malicious labels (review): %s\n", strings.Join(rep.BehaviourOutsideLabels, "; "))
	}
	fmt.Fprintln(w)
}

// WriteUNSWMarkdown renders a UNSW identity/benign evaluation.
func WriteUNSWMarkdown(w io.Writer, rep UNSWReport) {
	s := rep.Summary
	fmt.Fprintln(w, "### UNSW IoT traces: identity and benign findings")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "- Listed devices seen: %d / %d\n", s.Seen, s.ListedDevices)
	fmt.Fprintf(w, "- With OUI vendor: %d, hostname: %d, DHCP: %d, mDNS: %d, SSDP: %d, category candidate: %d\n", s.WithOUIVendor, s.WithHostname, s.WithDHCP, s.WithMDNS, s.WithSSDP, s.WithCategory)
	fmt.Fprintf(w, "- Devices with WARNING+ findings: %d; behaviour findings (benign dataset, review as candidate false positives): %d\n\n", s.WithWarningFindings, s.BehaviourFindings)
	fmt.Fprintln(w, "| Device (truth) | MAC | Seen | OUI vendor | Hostname | Identity sources | Category | WARNING+ findings |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for _, d := range rep.Devices {
		fmt.Fprintf(w, "| %s | %s | %v | %s | %s | %s | %s (%s) | %s |\n", d.Name, d.MAC, d.Seen, d.MACVendor, d.Hostname, strings.Join(d.IdentitySrc, ","), d.Category, d.CategoryConf, fmtCounts(d.Findings))
	}
	if len(s.FindingTypeCounts) > 0 {
		fmt.Fprintf(w, "\nDevices per WARNING+ finding type: %s\n", fmtCounts(s.FindingTypeCounts))
	}
	if len(rep.UnlistedLocalDevices) > 0 {
		fmt.Fprintf(w, "\nUnlisted local hosts (%d): %s\n", len(rep.UnlistedLocalDevices), strings.Join(rep.UnlistedLocalDevices, "; "))
	}
}

func fmtCounts(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
