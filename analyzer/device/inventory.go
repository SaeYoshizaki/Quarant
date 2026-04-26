package device

import (
	"sort"
	"strings"
	"time"
)

type InventorySnapshot struct {
	IP                 string         `json:"ip"`
	FirstSeen          string         `json:"first_seen,omitempty"`
	LastSeen           string         `json:"last_seen,omitempty"`
	ObservedProtocols  []string       `json:"observed_protocols,omitempty"`
	ObservedPorts      []uint16       `json:"observed_ports,omitempty"`
	ObservedHosts      []string       `json:"observed_hosts,omitempty"`
	ObservedSNI        []string       `json:"observed_sni,omitempty"`
	CategoryCandidate  string         `json:"category_candidate,omitempty"`
	CategoryConfidence string         `json:"category_confidence,omitempty"`
	VendorCandidate    string         `json:"vendor_candidate,omitempty"`
	VendorConfidence   string         `json:"vendor_confidence,omitempty"`
	FamilyCandidate    string         `json:"family_candidate,omitempty"`
	FamilyConfidence   string         `json:"family_confidence,omitempty"`
	RiskEventCount     int            `json:"risk_event_count,omitempty"`
	SeverityCounts     map[string]int `json:"severity_counts,omitempty"`
	OWASPTagCounts     map[string]int `json:"owasp_tag_counts,omitempty"`
	LastRiskEventType  string         `json:"last_risk_event_type,omitempty"`
	LastRiskEventTS    string         `json:"last_risk_event_ts,omitempty"`
}

func (p *DeviceProfile) ObserveActivity(now time.Time) {
	if p == nil || now.IsZero() {
		return
	}
	if p.FirstSeen.IsZero() || now.Before(p.FirstSeen) {
		p.FirstSeen = now
	}
	if p.LastSeen.IsZero() || now.After(p.LastSeen) {
		p.LastSeen = now
	}
}

func (p *DeviceProfile) RecordRiskEvent(now time.Time, eventType, severity string, owaspTags []string) {
	if p == nil {
		return
	}
	p.ObserveActivity(now)

	p.RiskEventCount++
	if p.SeverityCounts == nil {
		p.SeverityCounts = map[string]int{}
	}
	if severity = strings.TrimSpace(severity); severity != "" {
		p.SeverityCounts[severity]++
	}

	if p.OWASPTagCounts == nil {
		p.OWASPTagCounts = map[string]int{}
	}
	for _, tag := range owaspTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		p.OWASPTagCounts[tag]++
	}

	if eventType = strings.TrimSpace(eventType); eventType != "" {
		p.LastRiskEventType = eventType
	}
	if !now.IsZero() {
		p.LastRiskEventAt = now
	}
}

func (p *DeviceProfile) Snapshot() InventorySnapshot {
	if p == nil {
		return InventorySnapshot{}
	}

	categoryCandidate := p.Classification.NormalizedCategory()
	if categoryCandidate == "" {
		categoryCandidate = "GenericIoT"
	}
	categoryConfidence := strings.TrimSpace(p.Classification.ConfidenceLabel)
	if categoryConfidence == "" {
		categoryConfidence = "very_low"
	}

	return InventorySnapshot{
		IP:                 p.IP,
		FirstSeen:          formatSnapshotTime(p.FirstSeen),
		LastSeen:           formatSnapshotTime(p.LastSeen),
		ObservedProtocols:  sortedStringMapKeys(p.Protocols),
		ObservedPorts:      sortedPortMapKeys(p.Ports),
		ObservedHosts:      sortedStringMapKeys(p.Hosts),
		ObservedSNI:        sortedStringMapKeys(p.SNIValues),
		CategoryCandidate:  categoryCandidate,
		CategoryConfidence: categoryConfidence,
		VendorCandidate:    p.Identity.VendorCandidate,
		VendorConfidence:   p.Identity.VendorConfidence,
		FamilyCandidate:    p.Identity.FamilyCandidate,
		FamilyConfidence:   p.Identity.FamilyConfidence,
		RiskEventCount:     p.RiskEventCount,
		SeverityCounts:     cloneStringIntMap(p.SeverityCounts),
		OWASPTagCounts:     cloneStringIntMap(p.OWASPTagCounts),
		LastRiskEventType:  p.LastRiskEventType,
		LastRiskEventTS:    formatSnapshotTime(p.LastRiskEventAt),
	}
}

func formatSnapshotTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func sortedStringMapKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortedPortMapKeys(values map[uint16]bool) []uint16 {
	if len(values) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneStringIntMap(values map[string]int) map[string]int {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]int, len(values))
	for key, value := range values {
		if strings.TrimSpace(key) == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
