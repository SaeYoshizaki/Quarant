// Package discovery extracts device-identity hints from link-layer and local
// discovery traffic: Ethernet/ARP addresses, DHCP client options, mDNS
// announcements and SSDP headers, plus MAC-vendor lookup against the IEEE
// registry.
//
// Every hint carries a Basis so that consumers can tell an observed value
// (the device itself put it on the wire) from a reference lookup (a registry
// told us what the value usually means) or an inference.
package discovery

import (
	"bufio"
	"bytes"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/gopacket/layers"

	"quarant/analyzer/knowledge"
)

// Basis classifies where a piece of information came from.
type Basis string

const (
	// BasisObserved: the value was seen verbatim in traffic.
	BasisObserved Basis = "observed"
	// BasisReference: the value comes from matching an observed value
	// against an external reference (registry, threat feed, CVE database).
	BasisReference Basis = "reference_match"
	// BasisInferred: the value is a judgement derived from observations
	// (heuristics, statistics, classifiers).
	BasisInferred Basis = "inferred"
)

// ---- MAC / OUI ---------------------------------------------------------------

// MACInfo describes a MAC address and what the registry says about it.
type MACInfo struct {
	MAC                 string `json:"mac"`
	Vendor              string `json:"vendor,omitempty"`
	LocallyAdministered bool   `json:"locally_administered,omitempty"`
	Multicast           bool   `json:"multicast,omitempty"`
}

var (
	ouiOnce  sync.Once
	ouiTable map[string]string
	ouiMeta  string
)

func loadOUI() {
	ouiTable = map[string]string{}
	data, err := knowledge.ReadFile("oui_ma_l.tsv")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") {
			if ouiMeta == "" {
				ouiMeta = strings.TrimSpace(strings.TrimPrefix(line, "#"))
			}
			continue
		}
		prefix, name, ok := strings.Cut(line, "\t")
		if ok && len(prefix) == 6 {
			ouiTable[prefix] = name
		}
	}
}

// OUISource returns the provenance line of the embedded OUI table.
func OUISource() string {
	ouiOnce.Do(loadOUI)
	return ouiMeta
}

// LookupMAC returns registry information for mac. Locally administered
// addresses (randomized "private Wi-Fi addresses" on phones, virtual NICs) do
// not belong to any vendor, so no vendor is returned for them.
func LookupMAC(mac net.HardwareAddr) MACInfo {
	info := MACInfo{MAC: strings.ToLower(mac.String())}
	if len(mac) < 3 {
		return info
	}
	info.Multicast = mac[0]&0x01 != 0
	info.LocallyAdministered = mac[0]&0x02 != 0
	if info.Multicast || info.LocallyAdministered {
		return info
	}
	ouiOnce.Do(loadOUI)
	prefix := strings.ToUpper(strings.ReplaceAll(mac[:3].String(), ":", ""))
	info.Vendor = ouiTable[prefix]
	return info
}

// ---- DHCP --------------------------------------------------------------------

// DHCPClientInfo holds the client-supplied identity fields of a DHCP message.
type DHCPClientInfo struct {
	MessageType string
	ClientMAC   net.HardwareAddr
	ClientIP    net.IP // ciaddr, or the requested IP (option 50)
	Hostname    string // option 12
	VendorClass string // option 60
	// ParamRequestList is option 55 as a comma separated list. Its order is a
	// well-known passive OS/device fingerprint (as used by Fingerbank).
	ParamRequestList string
}

// ParseDHCPClient extracts client identity hints from a BOOTREQUEST.
// Server replies are ignored; they describe the network, not the device.
func ParseDHCPClient(d *layers.DHCPv4) (DHCPClientInfo, bool) {
	if d == nil || d.Operation != layers.DHCPOpRequest || len(d.ClientHWAddr) < 6 {
		return DHCPClientInfo{}, false
	}
	info := DHCPClientInfo{ClientMAC: d.ClientHWAddr}
	if d.ClientIP != nil && !d.ClientIP.IsUnspecified() {
		info.ClientIP = d.ClientIP
	}
	for _, opt := range d.Options {
		switch opt.Type {
		case layers.DHCPOptMessageType:
			if len(opt.Data) == 1 {
				info.MessageType = layers.DHCPMsgType(opt.Data[0]).String()
			}
		case layers.DHCPOptHostname:
			info.Hostname = printable(string(opt.Data), 64)
		case layers.DHCPOptClassID:
			info.VendorClass = printable(string(opt.Data), 128)
		case layers.DHCPOptParamsRequest:
			parts := make([]string, 0, len(opt.Data))
			for _, b := range opt.Data {
				parts = append(parts, strconv.Itoa(int(b)))
			}
			info.ParamRequestList = strings.Join(parts, ",")
		case layers.DHCPOptRequestIP:
			if len(opt.Data) == 4 && info.ClientIP == nil {
				info.ClientIP = net.IP(append([]byte(nil), opt.Data...))
			}
		}
	}
	return info, true
}

// ---- mDNS --------------------------------------------------------------------

// MDNSInfo summarizes what a host announced over multicast DNS.
type MDNSInfo struct {
	Services  []string // e.g. _http._tcp.local
	Instances []string // e.g. smartplug-3a4f1c
	Hostnames []string // e.g. smartplug.local (A/AAAA owner names)
	TXT       []string // key=value pairs; values may describe model/firmware
}

// ParseMDNSAnnouncement reads answer and additional records of an mDNS
// response. Queries are ignored because they describe what a host is looking
// for, not what it is.
func ParseMDNSAnnouncement(d *layers.DNS) (MDNSInfo, bool) {
	if d == nil || !d.QR {
		return MDNSInfo{}, false
	}
	var info MDNSInfo
	records := append(append([]layers.DNSResourceRecord{}, d.Answers...), d.Additionals...)
	for _, rr := range records {
		name := strings.TrimSuffix(string(rr.Name), ".")
		switch rr.Type {
		case layers.DNSTypePTR:
			target := strings.TrimSuffix(string(rr.PTR), ".")
			if strings.HasPrefix(name, "_") && !strings.HasPrefix(name, "_services.") {
				info.Services = append(info.Services, name)
				if instance, _, ok := strings.Cut(target, "._"); ok {
					info.Instances = append(info.Instances, printable(instance, 64))
				}
			}
		case layers.DNSTypeSRV:
			if host := strings.TrimSuffix(string(rr.SRV.Name), "."); host != "" {
				info.Hostnames = append(info.Hostnames, host)
			}
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if name != "" {
				info.Hostnames = append(info.Hostnames, name)
			}
		case layers.DNSTypeTXT:
			for _, txt := range rr.TXTs {
				if s := printable(string(txt), 96); strings.Contains(s, "=") {
					info.TXT = append(info.TXT, s)
				}
			}
		}
	}
	info.Services = uniqueSorted(info.Services)
	info.Instances = uniqueSorted(info.Instances)
	info.Hostnames = uniqueSorted(info.Hostnames)
	info.TXT = uniqueSorted(info.TXT)
	if len(info.Services)+len(info.Instances)+len(info.Hostnames)+len(info.TXT) == 0 {
		return MDNSInfo{}, false
	}
	return info, true
}

// ---- SSDP --------------------------------------------------------------------

// SSDPInfo holds identity-relevant headers of an SSDP NOTIFY or search reply.
type SSDPInfo struct {
	Kind     string // notify | response | search
	Server   string // SERVER: often "OS/ver UPnP/1.0 Product/ver"
	Location string // URL of the device description
	Target   string // NT or ST
	USN      string
}

// ParseSSDP parses an SSDP message (HTTP-over-UDP).
func ParseSSDP(payload []byte) (SSDPInfo, bool) {
	head, _, _ := bytes.Cut(payload, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\n")
	if len(lines) == 0 {
		return SSDPInfo{}, false
	}
	var info SSDPInfo
	start := strings.ToUpper(strings.TrimSpace(lines[0]))
	switch {
	case strings.HasPrefix(start, "NOTIFY "):
		info.Kind = "notify"
	case strings.HasPrefix(start, "M-SEARCH "):
		info.Kind = "search"
	case strings.HasPrefix(start, "HTTP/1."):
		info.Kind = "response"
	default:
		return SSDPInfo{}, false
	}
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !ok {
			continue
		}
		value = printable(strings.TrimSpace(value), 200)
		switch strings.ToUpper(strings.TrimSpace(key)) {
		case "SERVER", "USER-AGENT":
			if info.Server == "" {
				info.Server = value
			}
		case "LOCATION":
			info.Location = value
		case "NT", "ST":
			info.Target = value
		case "USN":
			info.USN = value
		}
	}
	return info, true
}

var upnpDeviceTypeRe = regexp.MustCompile(`(?i)urn:[a-z0-9.-]+:device:[a-z0-9_-]+:\d+`)

// UPnPDeviceType extracts a UPnP device type URN from an SSDP NT, ST or USN
// value ("" when the value names a service, a UUID or the root device).
func UPnPDeviceType(v string) string {
	return upnpDeviceTypeRe.FindString(v)
}

// ---- helpers -------------------------------------------------------------------

// printable keeps printable ASCII only and truncates to max bytes. Identity
// strings end up in reports, so control bytes from the wire are dropped.
func printable(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
		if b.Len() >= max {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
