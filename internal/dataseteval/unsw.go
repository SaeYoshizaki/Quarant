package dataseteval

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"

	"quarant/analyzer/device"
)

// UNSWDevice is one entry of the UNSW IoT traces List_Of_Devices.txt.
type UNSWDevice struct {
	Name       string `json:"name"`
	MAC        string `json:"mac"`
	Connection string `json:"connection,omitempty"`
}

var macRe = regexp.MustCompile(`(?i)\b([0-9a-f]{1,2}(?::[0-9a-f]{1,2}){5})\b`)

// ParseUNSWDevices reads List_Of_Devices.txt ("name  MAC  Wired|Wireless").
// MACs are normalised to two-digit lower-case octets.
func ParseUNSWDevices(r io.Reader) ([]UNSWDevice, error) {
	var out []UNSWDevice
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		loc := macRe.FindStringSubmatchIndex(line)
		if loc == nil {
			continue
		}
		hw, err := net.ParseMAC(normalizeMAC(line[loc[2]:loc[3]]))
		if err != nil {
			continue
		}
		out = append(out, UNSWDevice{
			Name:       strings.TrimSpace(line[:loc[0]]),
			MAC:        strings.ToLower(hw.String()),
			Connection: strings.TrimSpace(line[loc[1]:]),
		})
	}
	return out, sc.Err()
}

func normalizeMAC(s string) string {
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

type UNSWDeviceResult struct {
	UNSWDevice
	Seen          bool           `json:"seen"`
	IPs           []string       `json:"ips,omitempty"`
	MACVendor     string         `json:"mac_vendor,omitempty"`
	Hostname      string         `json:"hostname,omitempty"`
	IdentitySrc   []string       `json:"identity_sources,omitempty"` // dhcp, mdns, ssdp, oui_registry...
	Category      string         `json:"category_candidate,omitempty"`
	CategoryConf  string         `json:"category_confidence,omitempty"`
	Findings      map[string]int `json:"warning_or_above_findings,omitempty"`
	Informational map[string]int `json:"other_findings,omitempty"`
}

type UNSWReport struct {
	Devices []UNSWDeviceResult `json:"devices"`
	Summary UNSWSummary        `json:"summary"`
	// UnlistedLocalDevices are monitored hosts whose MAC is not in the
	// ground-truth list (e.g. IPv6 addresses of listed devices, or
	// devices outside the published list).
	UnlistedLocalDevices []string `json:"unlisted_local_devices,omitempty"`
}

type UNSWSummary struct {
	ListedDevices       int            `json:"listed_devices"`
	Seen                int            `json:"seen"`
	WithOUIVendor       int            `json:"with_oui_vendor"`
	WithHostname        int            `json:"with_hostname"`
	WithDHCP            int            `json:"with_dhcp_evidence"`
	WithMDNS            int            `json:"with_mdns_evidence"`
	WithSSDP            int            `json:"with_ssdp_evidence"`
	WithCategory        int            `json:"with_category_candidate"`
	WithWarningFindings int            `json:"with_warning_or_above_findings"`
	FindingTypeCounts   map[string]int `json:"warning_or_above_finding_types"`
	BehaviourFindings   int            `json:"behaviour_findings"`
}

// EvaluateUNSW maps inventory entries to the ground-truth MAC list. The
// dataset is benign, so any finding is either a true weakness of the 2016-era
// devices (plaintext, old TLS) or a false positive; behaviour findings in
// particular are candidate false positives and are counted separately.
func EvaluateUNSW(truth []UNSWDevice, inventory []device.InventorySnapshot, events []Event) UNSWReport {
	byMAC := map[string][]device.InventorySnapshot{}
	for _, s := range inventory {
		macs := append([]string{s.MACAddress}, s.MACAddresses...)
		seen := map[string]bool{}
		for _, m := range macs {
			m = strings.ToLower(m)
			if m != "" && !seen[m] {
				seen[m] = true
				byMAC[m] = append(byMAC[m], s)
			}
		}
	}
	findings := map[string]map[string]int{}
	info := map[string]map[string]int{}
	for _, e := range events {
		if e.Debug {
			continue
		}
		dev := e.DeviceKey
		if dev == "" {
			dev = e.SrcIP
		}
		target := info
		if isWarningOrAbove(e.Severity) {
			target = findings
		}
		if target[dev] == nil {
			target[dev] = map[string]int{}
		}
		target[dev][e.Type]++
	}

	rep := UNSWReport{Summary: UNSWSummary{ListedDevices: len(truth), FindingTypeCounts: map[string]int{}}}
	listed := map[string]bool{}
	for _, t := range truth {
		listed[t.MAC] = true
		r := UNSWDeviceResult{UNSWDevice: t}
		snaps := byMAC[t.MAC]
		sources := map[string]bool{}
		for _, s := range snaps {
			r.Seen = true
			r.IPs = append(r.IPs, s.IP)
			if r.MACVendor == "" {
				r.MACVendor = s.MACVendor
			}
			if r.Hostname == "" {
				r.Hostname = s.Hostname
			}
			if r.Category == "" || r.Category == "GenericIoT" {
				r.Category, r.CategoryConf = s.CategoryCandidate, s.CategoryConfidence
			}
			for _, ev := range s.IdentityEvidence {
				sources[ev.Source] = true
			}
			for typ, n := range findings[s.IP] {
				if r.Findings == nil {
					r.Findings = map[string]int{}
				}
				r.Findings[typ] += n
			}
			for typ, n := range info[s.IP] {
				if r.Informational == nil {
					r.Informational = map[string]int{}
				}
				r.Informational[typ] += n
			}
		}
		for s := range sources {
			r.IdentitySrc = append(r.IdentitySrc, s)
		}
		sort.Strings(r.IdentitySrc)
		sort.Strings(r.IPs)

		sum := &rep.Summary
		if r.Seen {
			sum.Seen++
		}
		if r.MACVendor != "" {
			sum.WithOUIVendor++
		}
		if r.Hostname != "" {
			sum.WithHostname++
		}
		if sources["dhcp"] {
			sum.WithDHCP++
		}
		if sources["mdns"] {
			sum.WithMDNS++
		}
		if sources["ssdp"] {
			sum.WithSSDP++
		}
		if r.Category != "" && r.Category != "GenericIoT" {
			sum.WithCategory++
		}
		if len(r.Findings) > 0 {
			sum.WithWarningFindings++
		}
		for typ := range r.Findings {
			sum.FindingTypeCounts[typ]++
		}
		for _, m := range []map[string]int{r.Findings, r.Informational} {
			for typ, n := range m {
				if isBehaviourType(typ) {
					sum.BehaviourFindings += n
				}
			}
		}
		rep.Devices = append(rep.Devices, r)
	}
	for _, s := range inventory {
		if s.MACAddress == "" || !listed[strings.ToLower(s.MACAddress)] {
			rep.UnlistedLocalDevices = append(rep.UnlistedLocalDevices, s.IP+" "+s.MACAddress)
		}
	}
	sort.Strings(rep.UnlistedLocalDevices)
	return rep
}

func isBehaviourType(t string) bool {
	switch t {
	case "OUTBOUND_SCAN_SUSPECTED", "PORT_SCAN_SUSPECTED", "LATERAL_SCAN_SUSPECTED",
		"PERIODIC_COMMUNICATION_OBSERVED", "PERSISTENT_CONNECTION_ATTEMPTS", "IP_MAC_BINDING_CHANGED":
		return true
	}
	return false
}
