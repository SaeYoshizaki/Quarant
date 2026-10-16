package device

import (
	"sort"
	"strings"
	"time"
)

// IdentityEvidence is one identity attribute of a device together with where
// it came from. Basis is "observed" (seen verbatim on the wire),
// "reference_match" (looked up in an external registry such as the IEEE OUI
// list) or "inferred" (derived by heuristics).
type IdentityEvidence struct {
	Attribute string `json:"attribute"`
	Value     string `json:"value"`
	Basis     string `json:"basis"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Count     int    `json:"count"`
}

// maxIdentityEvidence bounds per-device identity hints so that a noisy or
// hostile device cannot grow memory without limit.
const maxIdentityEvidence = 64

// maxDNSQueries bounds the per-device set of queried names.
const maxDNSQueries = 512

type identityHint struct {
	evidence  IdentityEvidence
	firstSeen time.Time
	lastSeen  time.Time
}

// AddIdentityEvidence records an identity attribute. Repeated values only
// update the count and last-seen time.
func (p *DeviceProfile) AddIdentityEvidence(now time.Time, attribute, value, basis, source string) {
	value = strings.TrimSpace(value)
	if p == nil || attribute == "" || value == "" {
		return
	}
	if p.IdentityHints == nil {
		p.IdentityHints = map[string]*identityHint{}
	}
	key := attribute + "|" + source + "|" + value
	if h, ok := p.IdentityHints[key]; ok {
		h.evidence.Count++
		if now.After(h.lastSeen) {
			h.lastSeen = now
		}
		return
	}
	if len(p.IdentityHints) >= maxIdentityEvidence {
		return
	}
	p.IdentityHints[key] = &identityHint{
		evidence:  IdentityEvidence{Attribute: attribute, Value: value, Basis: basis, Source: source, Count: 1},
		firstSeen: now,
		lastSeen:  now,
	}
}

// ObserveMAC binds a link-layer address to the device. More than one MAC for
// the same IP can mean DHCP reassignment, a bridge/repeater, or ARP spoofing.
func (p *DeviceProfile) ObserveMAC(mac string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if p == nil || mac == "" {
		return
	}
	if p.MACs == nil {
		p.MACs = map[string]bool{}
	}
	if p.MAC == "" {
		p.MAC = mac
	}
	if len(p.MACs) < 16 {
		p.MACs[mac] = true
	}
}

// ObserveDNSQuery records a name the device resolved.
func (p *DeviceProfile) ObserveDNSQuery(name string) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if p == nil || name == "" {
		return
	}
	if p.DNSQueries == nil {
		p.DNSQueries = map[string]bool{}
	}
	if len(p.DNSQueries) < maxDNSQueries {
		p.DNSQueries[name] = true
	}
}

// IdentityEvidenceList returns hints sorted by attribute, source and value.
func (p *DeviceProfile) IdentityEvidenceList() []IdentityEvidence {
	if p == nil || len(p.IdentityHints) == 0 {
		return nil
	}
	out := make([]IdentityEvidence, 0, len(p.IdentityHints))
	for _, h := range p.IdentityHints {
		e := h.evidence
		e.FirstSeen = formatSnapshotTime(h.firstSeen)
		e.LastSeen = formatSnapshotTime(h.lastSeen)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Attribute != out[j].Attribute {
			return out[i].Attribute < out[j].Attribute
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Value < out[j].Value
	})
	return out
}

// firstIdentityValue returns the value of the first hint for attribute in
// source preference order.
func (p *DeviceProfile) firstIdentityValue(attribute string, sources ...string) string {
	list := p.IdentityEvidenceList()
	for _, source := range sources {
		for _, e := range list {
			if e.Attribute == attribute && e.Source == source {
				return e.Value
			}
		}
	}
	return ""
}
