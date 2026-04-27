package device

import (
	"sort"
	"strings"
	"time"
)

type RiskSummary struct {
	RiskEventCount         int      `json:"risk_event_count,omitempty"`
	HighestSeverity        string   `json:"highest_severity,omitempty"`
	TopOWASPTags           []string `json:"top_owasp_tags,omitempty"`
	TopSeverities          []string `json:"top_severities,omitempty"`
	LastRiskEventType      string   `json:"last_risk_event_type,omitempty"`
	LastRiskEventTS        string   `json:"last_risk_event_ts,omitempty"`
	RecommendedNextAction  string   `json:"recommended_next_action,omitempty"`
}

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
	RiskSummary        *RiskSummary   `json:"risk_summary,omitempty"`
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
		RiskSummary: buildRiskSummary(
			p.RiskEventCount,
			p.SeverityCounts,
			p.OWASPTagCounts,
			p.LastRiskEventType,
			formatSnapshotTime(p.LastRiskEventAt),
		),
	}
}

func buildRiskSummary(riskEventCount int, severityCounts, owaspTagCounts map[string]int, lastRiskEventType, lastRiskEventTS string) *RiskSummary {
	highestSeverity := highestSeverityLabel(severityCounts)
	if highestSeverity == "" || severityRank(highestSeverity) <= severityRank("INFO") {
		return nil
	}

	return &RiskSummary{
		RiskEventCount:        riskEventCount,
		HighestSeverity:       highestSeverity,
		TopOWASPTags:          topCountKeysAlphaTie(owaspTagCounts, 5),
		TopSeverities:         topSeverityLabels(severityCounts, 5),
		LastRiskEventType:     strings.TrimSpace(lastRiskEventType),
		LastRiskEventTS:       strings.TrimSpace(lastRiskEventTS),
		RecommendedNextAction: recommendedNextAction(owaspTagCounts),
	}
}

func highestSeverityLabel(counts map[string]int) string {
	best := ""
	bestRank := -1
	for label, count := range counts {
		if count <= 0 {
			continue
		}
		label = strings.TrimSpace(label)
		rank := severityRank(label)
		if rank > bestRank || (rank == bestRank && label < best) {
			best = label
			bestRank = rank
		}
	}
	return best
}

func severityRank(label string) int {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "INFO":
		return 1
	case "LOW":
		return 2
	case "WARNING":
		return 3
	case "MEDIUM":
		return 4
	case "HIGH":
		return 5
	case "CRITICAL":
		return 6
	default:
		return 0
	}
}

func topCountKeysAlphaTie(counts map[string]int, limit int) []string {
	type kv struct {
		key   string
		count int
	}

	items := make([]kv, 0, len(counts))
	for key, count := range counts {
		key = strings.TrimSpace(key)
		if key == "" || count <= 0 {
			continue
		}
		items = append(items, kv{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].key < items[j].key
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func topSeverityLabels(counts map[string]int, limit int) []string {
	type kv struct {
		key   string
		count int
	}

	items := make([]kv, 0, len(counts))
	for key, count := range counts {
		key = strings.TrimSpace(key)
		if key == "" || count <= 0 {
			continue
		}
		items = append(items, kv{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			if severityRank(items[i].key) == severityRank(items[j].key) {
				return items[i].key < items[j].key
			}
			return severityRank(items[i].key) > severityRank(items[j].key)
		}
		return items[i].count > items[j].count
	})
	if limit > 0 && len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.key)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func recommendedNextAction(owaspTagCounts map[string]int) string {
	has := func(tag string) bool {
		return owaspTagCounts != nil && owaspTagCounts[tag] > 0
	}
	switch {
	case has("I7") && has("I3"):
		return "Review plaintext API usage, token handling, and ecosystem interface transport security."
	case has("I7"):
		return "Review plaintext communication and exposed credentials or tokens."
	case has("I3"):
		return "Review API, management, and cloud/backend interface exposure."
	case has("I9"):
		return "Review setup endpoints, default hostname patterns, and initial configuration state."
	case has("I2"):
		return "Review exposed or unnecessary network services."
	case has("I6"):
		return "Review unexpected privacy-related communication and destination patterns."
	case has("I4") || has("I5"):
		return "Review firmware update state, device model, and known-vulnerability applicability."
	default:
		return "Review the latest risk event and confirm whether the observed behavior is expected."
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
