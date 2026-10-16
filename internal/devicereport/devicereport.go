// Package devicereport builds a per-device view of an analysis run: who the
// device appears to be (and on what basis), what it talked to, what was
// found, and what passive monitoring could not see for it.
//
// The report intentionally has no numeric risk score. Findings are counted by
// severity and by evidence basis, so a reader can see at a glance whether a
// device's most severe finding rests on an observed fact, an inference, or a
// reference-database match.
package devicereport

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/device"
)

// Inputs are the analysis outputs the report is built from.
type Inputs struct {
	Events    []analyzer.Event
	Flows     []analyzer.FlowRecord
	Inventory []device.InventorySnapshot
}

type Report struct {
	GeneratedAt string   `json:"generated_at"`
	Window      Window   `json:"capture_window"`
	Devices     []Device `json:"devices"`
	Notes       []string `json:"notes"`
}

type Window struct {
	Start string `json:"start,omitempty"`
	End   string `json:"end,omitempty"`
}

type Device struct {
	IP       string   `json:"ip"`
	Identity Identity `json:"identity"`
	Activity Activity `json:"activity"`
	// FindingCounts[severity][basis] = number of distinct finding types.
	FindingCounts map[string]map[string]int `json:"finding_counts"`
	Findings      []Finding                 `json:"findings"`
	Visibility    []string                  `json:"visibility_limits"`
}

type Identity struct {
	MAC                string                    `json:"mac,omitempty"`
	MACVendor          string                    `json:"mac_vendor,omitempty"`
	MACRandomized      bool                      `json:"mac_locally_administered,omitempty"`
	Hostname           string                    `json:"hostname,omitempty"`
	CategoryCandidate  string                    `json:"category_candidate,omitempty"`
	CategoryConfidence string                    `json:"category_confidence,omitempty"`
	VendorCandidate    string                    `json:"vendor_candidate,omitempty"`
	VendorConfidence   string                    `json:"vendor_confidence,omitempty"`
	Evidence           []device.IdentityEvidence `json:"evidence,omitempty"`
}

type Activity struct {
	FirstSeen       string        `json:"first_seen,omitempty"`
	LastSeen        string        `json:"last_seen,omitempty"`
	Protocols       []string      `json:"protocols,omitempty"`
	Ports           []uint16      `json:"ports,omitempty"`
	Flows           int           `json:"tcp_flows"`
	EncryptedFlows  int           `json:"encrypted_tcp_flows"`
	PlaintextFlows  int           `json:"plaintext_tcp_flows"`
	DNSQueries      int           `json:"dns_queries"`
	TopDestinations []Destination `json:"top_destinations,omitempty"`
}

type Destination struct {
	Name     string `json:"name"`
	Flows    int    `json:"flows"`
	BytesOut int64  `json:"bytes_out"`
	BytesIn  int64  `json:"bytes_in"`
}

type Finding struct {
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Basis        string `json:"basis"`
	Confidence   string `json:"confidence,omitempty"`
	Count        int    `json:"count"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	ObservedFact string `json:"observed_fact,omitempty"`
	Inference    string `json:"inference,omitempty"`
	Limitation   string `json:"limitation,omitempty"`
	Evidence     string `json:"example_evidence,omitempty"`
}

// contextOnly are events that describe the device rather than a risk.
var contextOnly = map[string]bool{"TLS_CLIENT_HELLO": true}

// Build assembles the report.
func Build(in Inputs, generatedAt time.Time) Report {
	rep := Report{GeneratedAt: generatedAt.UTC().Format(time.RFC3339)}
	devices := map[string]*Device{}
	get := func(ip string) *Device {
		d, ok := devices[ip]
		if !ok {
			d = &Device{IP: ip, FindingCounts: map[string]map[string]int{}}
			devices[ip] = d
		}
		return d
	}

	var start, end time.Time
	widen := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if start.IsZero() || t.Before(start) {
			start = t
		}
		if t.After(end) {
			end = t
		}
	}

	snapshots := map[string]device.InventorySnapshot{}
	for _, s := range in.Inventory {
		snapshots[s.IP] = s
		d := get(s.IP)
		d.Identity = Identity{
			MAC: s.MACAddress, MACVendor: s.MACVendor, MACRandomized: s.MACRandomized, Hostname: s.Hostname,
			CategoryCandidate: s.CategoryCandidate, CategoryConfidence: s.CategoryConfidence,
			VendorCandidate: s.VendorCandidate, VendorConfidence: s.VendorConfidence,
			Evidence: s.IdentityEvidence,
		}
		d.Activity.FirstSeen, d.Activity.LastSeen = s.FirstSeen, s.LastSeen
		for _, ts := range []string{s.FirstSeen, s.LastSeen} {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				widen(t)
			}
		}
		d.Activity.Protocols, d.Activity.Ports = s.ObservedProtocols, s.ObservedPorts
		d.Activity.DNSQueries = len(s.DNSQueries)
	}

	// Flow records are snapshots; the last one per flow key is final.
	final := map[string]analyzer.FlowRecord{}
	order := []string{}
	for _, f := range in.Flows {
		if _, ok := final[f.FlowKey]; !ok {
			order = append(order, f.FlowKey)
		}
		final[f.FlowKey] = f
		widen(f.Timestamp)
	}
	dests := map[string]map[string]*Destination{}
	tls13 := map[string]bool{}
	for _, k := range order {
		f := final[k]
		// A flow counts for each monitored endpoint: outbound for the
		// client, inbound for a local server.
		for _, ip := range []string{f.SrcIP, f.DstIP} {
			if _, ok := snapshots[ip]; !ok {
				continue
			}
			addFlow(get(ip), dests, ip, f)
		}
	}
	for ip, m := range dests {

		list := make([]Destination, 0, len(m))
		for _, ds := range m {
			list = append(list, *ds)
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Flows != list[j].Flows {
				return list[i].Flows > list[j].Flows
			}
			return list[i].Name < list[j].Name
		})
		if len(list) > 10 {
			list = list[:10]
		}
		get(ip).Activity.TopDestinations = list
	}

	type fkey struct{ ip, typ string }
	findings := map[fkey]*Finding{}
	for _, e := range in.Events {
		widen(e.Timestamp)
		if e.Debug || contextOnly[e.Type] {
			continue
		}
		if strings.Contains(e.Evidence, "TLS1.3") {
			tls13[e.DeviceKey] = true
		}
		ip := e.DeviceKey
		if ip == "" {
			ip = e.SrcIP
		}
		if _, ok := snapshots[ip]; !ok && len(in.Inventory) > 0 {
			continue
		}
		k := fkey{ip, e.Type}
		f := findings[k]
		ts := e.Timestamp.UTC().Format(time.RFC3339)
		if f == nil {
			f = &Finding{
				Type: e.Type, Severity: string(e.Severity), Basis: e.Basis, Confidence: e.Confidence,
				FirstSeen: ts, LastSeen: ts, ObservedFact: e.ObservedFact, Inference: e.Inference,
				Limitation: e.Limitation, Evidence: e.Evidence,
			}
			findings[k] = f
		}
		f.Count++
		if severityRank(string(e.Severity)) > severityRank(f.Severity) {
			f.Severity = string(e.Severity)
		}
		if ts < f.FirstSeen {
			f.FirstSeen = ts
		}
		if ts > f.LastSeen {
			f.LastSeen = ts
		}
	}
	for k, f := range findings {
		d := get(k.ip)
		d.Findings = append(d.Findings, *f)
		basis := f.Basis
		if basis == "" {
			basis = "unspecified"
		}
		if d.FindingCounts[f.Severity] == nil {
			d.FindingCounts[f.Severity] = map[string]int{}
		}
		d.FindingCounts[f.Severity][basis]++
	}

	for _, d := range devices {
		sort.Slice(d.Findings, func(i, j int) bool {
			a, b := d.Findings[i], d.Findings[j]
			if severityRank(a.Severity) != severityRank(b.Severity) {
				return severityRank(a.Severity) > severityRank(b.Severity)
			}
			if basisRank(a.Basis) != basisRank(b.Basis) {
				return basisRank(a.Basis) < basisRank(b.Basis)
			}
			return a.Type < b.Type
		})
		d.Visibility = visibilityLimits(d, tls13[d.IP])
		rep.Devices = append(rep.Devices, *d)
	}
	sort.Slice(rep.Devices, func(i, j int) bool { return ipLess(rep.Devices[i].IP, rep.Devices[j].IP) })

	if !start.IsZero() {
		rep.Window = Window{Start: start.UTC().Format(time.RFC3339), End: end.UTC().Format(time.RFC3339)}
	}
	rep.Notes = []string{
		"No finding does not mean no risk: encrypted payloads, traffic that did not cross the capture point, and device internals (firmware, SBOM) are not visible to passive monitoring.",
		"basis=observed: the trigger was seen in traffic; basis=inferred: derived by heuristics or statistics; basis=reference_match: matched against a curated or external reference whose accuracy and applicability to this device are not confirmed.",
		"finding_counts counts distinct finding types, not events; repeated events of one type are summarised in each finding's count.",
	}
	return rep
}

func visibilityLimits(d *Device, sawTLS13 bool) []string {
	var out []string
	if d.Identity.MACRandomized {
		out = append(out, "MAC address is locally administered (randomized or virtual); vendor cannot be derived from it.")
	}
	if d.Identity.MAC == "" {
		out = append(out, "No link-layer address was observed (capture point is likely routed/WAN side); MAC-based identity is unavailable.")
	}
	hasDHCP := false
	for _, e := range d.Identity.Evidence {
		if e.Source == "dhcp" {
			hasDHCP = true
		}
	}
	if !hasDHCP {
		out = append(out, "No DHCP exchange was observed for this device during the capture; hostname and DHCP fingerprint are unknown.")
	}
	if d.Activity.Flows > 0 && d.Activity.EncryptedFlows > 0 {
		out = append(out, fmt.Sprintf("%d of %d TCP flows were TLS-encrypted; their content (credentials, commands, data) cannot be inspected.", d.Activity.EncryptedFlows, d.Activity.Flows))
	}
	if sawTLS13 {
		out = append(out, "TLS 1.3 was used; server certificates are encrypted and certificate checks (self-signed, expiry) are not possible for those connections.")
	}
	if d.Activity.DNSQueries == 0 && d.Activity.Flows > 0 {
		out = append(out, "No DNS queries were observed; destinations are known by IP only (DNS over HTTPS/TLS, cached names, or capture placement).")
	}
	out = append(out, "Firmware version, installed software components and local (Bluetooth/Zigbee/same-switch) traffic are not observable from this capture.")
	return out
}

func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "WARNING", "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

func basisRank(b string) int {
	switch b {
	case "observed":
		return 0
	case "inferred":
		return 1
	case "reference_match":
		return 2
	}
	return 3
}

func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) == 4 && len(pb) == 4 {
		for i := 0; i < 4; i++ {
			var x, y int
			fmt.Sscanf(pa[i], "%d", &x)
			fmt.Sscanf(pb[i], "%d", &y)
			if x != y {
				return x < y
			}
		}
	}
	return a < b
}

// ---- loading -------------------------------------------------------------------

// LoadDir reads events.jsonl, flows.jsonl and device_inventory.json from an
// analysis output directory. Missing flows or inventory files are allowed.
func LoadDir(dir string) (Inputs, error) {
	var in Inputs
	if err := readJSONL(dir+"/events.jsonl", func(b []byte) error {
		var e analyzer.Event
		if json.Unmarshal(b, &e) == nil {
			in.Events = append(in.Events, e)
		}
		return nil
	}); err != nil {
		return in, err
	}
	if err := readJSONL(dir+"/flows.jsonl", func(b []byte) error {
		var f analyzer.FlowRecord
		if json.Unmarshal(b, &f) == nil {
			in.Flows = append(in.Flows, f)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return in, err
	}
	data, err := os.ReadFile(dir + "/device_inventory.json")
	if err == nil {
		var inv analyzer.DeviceInventoryReport
		if err := json.Unmarshal(data, &inv); err != nil {
			return in, fmt.Errorf("parse device_inventory.json: %w", err)
		}
		in.Inventory = inv.Devices
	} else if !os.IsNotExist(err) {
		return in, err
	}
	return in, nil
}

func readJSONL(path string, fn func([]byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		if err := fn(sc.Bytes()); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ---- markdown -------------------------------------------------------------------

func WriteMarkdown(w io.Writer, rep Report) {
	fmt.Fprintln(w, "# Quarant device report")
	fmt.Fprintln(w)
	if rep.Window.Start != "" {
		fmt.Fprintf(w, "Capture window: %s – %s\n\n", rep.Window.Start, rep.Window.End)
	}
	for _, d := range rep.Devices {
		title := d.IP
		if d.Identity.Hostname != "" {
			title += " (" + d.Identity.Hostname + ")"
		}
		fmt.Fprintf(w, "## %s\n\n", title)
		id := d.Identity
		fmt.Fprintln(w, "**Identity**")
		fmt.Fprintln(w)
		if id.MAC != "" {
			vendor := id.MACVendor
			switch {
			case id.MACRandomized:
				vendor = "n/a (locally administered MAC)"
			case vendor == "":
				vendor = "not in registry"
			}
			fmt.Fprintf(w, "- MAC: `%s` (observed) — vendor: %s (reference_match: IEEE OUI)\n", id.MAC, vendor)
		}
		for _, e := range id.Evidence {
			if e.Attribute == "mac" || e.Attribute == "mac_vendor" || e.Attribute == "mac_locally_administered" {
				continue
			}
			fmt.Fprintf(w, "- %s: `%s` (%s via %s)\n", e.Attribute, e.Value, e.Basis, e.Source)
		}
		if id.CategoryCandidate != "" {
			fmt.Fprintf(w, "- category candidate: %s (inferred, confidence %s)\n", id.CategoryCandidate, id.CategoryConfidence)
		}
		if id.VendorCandidate != "" {
			fmt.Fprintf(w, "- vendor candidate: %s (inferred, confidence %s)\n", id.VendorCandidate, id.VendorConfidence)
		}
		a := d.Activity
		fmt.Fprintf(w, "\n**Activity**: %s – %s; TCP flows %d (TLS %d, plaintext %d); DNS names %d; protocols %s\n\n",
			a.FirstSeen, a.LastSeen, a.Flows, a.EncryptedFlows, a.PlaintextFlows, a.DNSQueries, strings.Join(a.Protocols, ", "))
		if len(a.TopDestinations) > 0 {
			fmt.Fprintln(w, "| Destination | Flows | Bytes out | Bytes in |")
			fmt.Fprintln(w, "|---|---|---|---|")
			for _, ds := range a.TopDestinations {
				fmt.Fprintf(w, "| %s | %d | %d | %d |\n", ds.Name, ds.Flows, ds.BytesOut, ds.BytesIn)
			}
			fmt.Fprintln(w)
		}
		if len(d.Findings) == 0 {
			fmt.Fprintln(w, "**Findings**: none (see visibility limits)")
		} else {
			fmt.Fprintln(w, "**Findings**")
			fmt.Fprintln(w)
			fmt.Fprintln(w, "| Severity | Basis | Confidence | Type | Count | Observed fact |")
			fmt.Fprintln(w, "|---|---|---|---|---|---|")
			for _, f := range d.Findings {
				fmt.Fprintf(w, "| %s | %s | %s | %s | %d | %s |\n", f.Severity, f.Basis, f.Confidence, f.Type, f.Count, mdEscape(f.ObservedFact))
			}
		}
		fmt.Fprintln(w, "\n**Visibility limits**")
		fmt.Fprintln(w)
		for _, v := range d.Visibility {
			fmt.Fprintf(w, "- %s\n", v)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "## Notes")
	fmt.Fprintln(w)
	for _, n := range rep.Notes {
		fmt.Fprintf(w, "- %s\n", n)
	}
}

func mdEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func addFlow(d *Device, dests map[string]map[string]*Destination, ip string, f analyzer.FlowRecord) {
	d.Activity.Flows++
	switch f.Protocol {
	case "tls":
		d.Activity.EncryptedFlows++
	case "http", "mqtt", "telnet":
		d.Activity.PlaintextFlows++
	}
	if dests[ip] == nil {
		dests[ip] = map[string]*Destination{}
	}
	name := f.ObservedDestination
	if name == "" {
		name = f.DstIP
	}
	if ip == f.DstIP {
		name = "inbound from " + f.SrcIP
	}
	ds := dests[ip][name]
	if ds == nil {
		ds = &Destination{Name: name}
		dests[ip][name] = ds
	}
	ds.Flows++
	ds.BytesOut += f.BytesOut
	ds.BytesIn += f.BytesIn
}
