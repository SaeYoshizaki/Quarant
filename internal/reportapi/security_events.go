package reportapi

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type SecurityEvent struct {
	Timestamp       time.Time         `json:"ts"`
	EventID         string            `json:"event_id,omitempty"`
	Source          string            `json:"source,omitempty"`
	SourceFormat    string            `json:"source_format,omitempty"`
	Sensor          string            `json:"sensor,omitempty"`
	EventType       string            `json:"event_type"`
	AttackCategory  string            `json:"attack_category,omitempty"`
	AttackTechnique string            `json:"attack_technique,omitempty"`
	Severity        string            `json:"severity"`
	Confidence      string            `json:"confidence"`
	Action          string            `json:"action,omitempty"`
	Verdict         string            `json:"verdict,omitempty"`
	Direction       string            `json:"direction,omitempty"`
	SrcIP           string            `json:"src_ip,omitempty"`
	SrcPort         uint16            `json:"src_port,omitempty"`
	DstIP           string            `json:"dst_ip,omitempty"`
	DstPort         uint16            `json:"dst_port,omitempty"`
	Protocol        string            `json:"protocol,omitempty"`
	TCPFlags        []string          `json:"tcp_flags,omitempty"`
	DeviceIP        string            `json:"device_ip,omitempty"`
	AssetRole       string            `json:"asset_role,omitempty"`
	AggregationKey  string            `json:"aggregation_key,omitempty"`
	Raw             string            `json:"raw,omitempty"`
	Evidence        map[string]string `json:"evidence,omitempty"`
}

type AttackEvidenceReport struct {
	GeneratedAt     string                  `json:"generated_at"`
	Source          AttackEvidenceSources   `json:"source"`
	Window          Window                  `json:"window"`
	Metrics         AttackEvidenceMetrics   `json:"metrics"`
	DecisionPolicy  AttackEvidencePolicy    `json:"decision_policy"`
	Findings        []AttackEvidenceFinding `json:"findings"`
	Recommendations []string                `json:"recommendations"`
	Limitations     []string                `json:"limitations"`
}

type AttackEvidenceSources struct {
	SecurityEvents string `json:"security_events,omitempty"`
}

type AttackEvidenceMetrics struct {
	SecurityEventCount         int  `json:"security_event_count"`
	ObservedCount              int  `json:"observed_count"`
	BlockedCount               int  `json:"blocked_count"`
	AllowedCount               int  `json:"allowed_count"`
	AcceptedCount              int  `json:"accepted_count"`
	ExposedServiceAttemptCount int  `json:"exposed_service_attempt_count"`
	ScanCandidateCount         int  `json:"scan_candidate_count"`
	SweepCandidateCount        int  `json:"sweep_candidate_count"`
	SensitiveServiceProbeCount int  `json:"sensitive_service_probe_count"`
	SuspiciousTCPFlagCount     int  `json:"suspicious_tcp_flag_count"`
	TargetedDeviceCount        int  `json:"targeted_device_count"`
	UniqueAttackSourceCount    int  `json:"unique_attack_source_count"`
	UniqueTargetPortCount      int  `json:"unique_target_port_count"`
	ActionCounts               []KV `json:"action_counts,omitempty"`
	VerdictCounts              []KV `json:"verdict_counts,omitempty"`
	TechniqueCounts            []KV `json:"technique_counts,omitempty"`
}

type AttackEvidencePolicy struct {
	Version    string               `json:"version"`
	Thresholds []PrecisionThreshold `json:"thresholds"`
	Notes      []string             `json:"notes"`
}

type AttackEvidenceFinding struct {
	ID             string   `json:"id"`
	Kind           string   `json:"kind"`
	State          string   `json:"state"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	SrcIP          string   `json:"src_ip,omitempty"`
	TargetDeviceIP string   `json:"target_device_ip,omitempty"`
	Protocol       string   `json:"protocol,omitempty"`
	Ports          []uint16 `json:"ports,omitempty"`
	Targets        []string `json:"targets,omitempty"`
	EventCount     int      `json:"event_count"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	LastSeen       string   `json:"last_seen,omitempty"`
	Taxonomy       []string `json:"taxonomy,omitempty"`
	RecommendedUse string   `json:"recommended_use,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

type attackEvidenceAccumulator struct {
	srcIP     string
	targetIP  string
	protocol  string
	ports     map[uint16]bool
	targets   map[string]bool
	events    int
	first     time.Time
	last      time.Time
	evidence  map[string]bool
	technique map[string]bool
}

func LoadSecurityEvents(path string) ([]SecurityEvent, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	var events []SecurityEvent
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var event SecurityEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, normalizeSecurityEvent(event))
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return events, nil
}

func LoadAttackEvidenceReport(securityEventsPath string) (AttackEvidenceReport, error) {
	events, err := LoadSecurityEvents(securityEventsPath)
	if err != nil {
		return AttackEvidenceReport{}, err
	}
	report := BuildAttackEvidenceReport(events)
	report.Source.SecurityEvents = securityEventsPath
	return report, nil
}

func BuildAttackEvidenceReport(events []SecurityEvent) AttackEvidenceReport {
	events = normalizedSecurityEvents(events)
	report := AttackEvidenceReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		DecisionPolicy: AttackEvidencePolicy{
			Version: "attack-evidence-v1",
			Thresholds: []PrecisionThreshold{
				{Name: "port_scan", Condition: "same source targets one device on >=3 ports or produces >=5 observed events", Description: "psad-style inbound scan candidate."},
				{Name: "host_sweep", Condition: "same source targets >=3 local devices", Description: "psad-style horizontal sweep candidate."},
				{Name: "sensitive_service_probe", Condition: "inbound evidence targets a sensitive IoT or management service port", Description: "Probe targeted at services such as Telnet, HTTP admin, RTSP, MQTT, or SSH."},
				{Name: "suspicious_tcp_flags", Condition: "TCP flag pattern resembles FIN, XMAS, or other suspicious scan probes", Description: "TCP flag evidence is preserved separately from ordinary SYN probes."},
				{Name: "single_block", Condition: "one blocked packet", Description: "retained as evidence but not promoted by itself."},
			},
			Notes: []string{
				"Firewall evidence is boundary evidence; it does not prove compromise.",
				"Repeated or fan-out activity is promoted before single denied packets.",
				"Observed evidence is separated into blocked, accepted, and exposed-service attempts so before/after metrics are not interpreted as internet attack-volume reduction.",
			},
		},
		Recommendations: []string{
			"Prioritize findings that repeat, fan out across ports, or target sensitive IoT services.",
			"Correlate attack evidence with device behavior before applying disruptive mitigation.",
		},
		Limitations: []string{
			"Internet scan volume is not controlled by the protected network.",
			"Blocked packets show gateway posture, not whether the device was exploitable.",
		},
	}
	actionCounts := map[string]int{}
	verdictCounts := map[string]int{}
	techniqueCounts := map[string]int{}
	sources := map[string]bool{}
	targets := map[string]bool{}
	ports := map[uint16]bool{}
	byPair := map[string]*attackEvidenceAccumulator{}
	bySource := map[string]*attackEvidenceAccumulator{}

	for _, event := range events {
		report.Metrics.SecurityEventCount++
		report.Metrics.ObservedCount++
		addCount(actionCounts, event.Action)
		addCount(verdictCounts, event.Verdict)
		addCount(techniqueCounts, event.AttackTechnique)
		addStringBool(sources, event.SrcIP)
		addStringBool(targets, firstNonEmpty(event.DeviceIP, event.DstIP))
		if event.DstPort != 0 {
			ports[event.DstPort] = true
		}
		switch strings.ToLower(event.Verdict) {
		case "blocked", "rejected", "dropped":
			report.Metrics.BlockedCount++
		case "allowed", "accepted":
			report.Metrics.AllowedCount++
			report.Metrics.AcceptedCount++
		}
		if isExposedServiceAttempt(event) {
			report.Metrics.ExposedServiceAttemptCount++
		}
		if isSensitiveSecurityEvent(event) {
			report.Metrics.SensitiveServiceProbeCount++
		}
		if hasSuspiciousTCPFlags(event) {
			report.Metrics.SuspiciousTCPFlagCount++
		}
		if !isInboundSecurityEvent(event) {
			continue
		}
		target := firstNonEmpty(event.DeviceIP, event.DstIP)
		pair := attackEvidenceKey(event.SrcIP, target, event.Protocol)
		acc := ensureAttackEvidenceAccumulator(byPair, pair, event.SrcIP, target, event.Protocol)
		applyAttackEvidenceEvent(acc, event)
		sourceAcc := ensureAttackEvidenceAccumulator(bySource, event.SrcIP, event.SrcIP, "", event.Protocol)
		applyAttackEvidenceEvent(sourceAcc, event)
	}

	findings := []AttackEvidenceFinding{}
	for _, acc := range byPair {
		if finding, ok := attackFindingFromPair(acc); ok {
			findings = append(findings, finding)
		}
	}
	for _, acc := range bySource {
		if finding, ok := attackFindingFromSource(acc); ok {
			findings = append(findings, finding)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			if findings[i].EventCount == findings[j].EventCount {
				return findings[i].ID < findings[j].ID
			}
			return findings[i].EventCount > findings[j].EventCount
		}
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	report.Findings = findings
	for _, finding := range findings {
		switch finding.Kind {
		case "port_scan", "repeated_inbound_probe", "sensitive_service_probe", "suspicious_tcp_flags":
			report.Metrics.ScanCandidateCount++
		case "sweep":
			report.Metrics.SweepCandidateCount++
		}
	}
	report.Metrics.TargetedDeviceCount = len(targets)
	report.Metrics.UniqueAttackSourceCount = len(sources)
	report.Metrics.UniqueTargetPortCount = len(ports)
	report.Metrics.ActionCounts = toSortedKV(actionCounts)
	report.Metrics.VerdictCounts = toSortedKV(verdictCounts)
	report.Metrics.TechniqueCounts = toSortedKV(techniqueCounts)
	report.Window = securityEventWindow(events)
	return report
}

func normalizedSecurityEvents(events []SecurityEvent) []SecurityEvent {
	out := make([]SecurityEvent, 0, len(events))
	for _, event := range events {
		out = append(out, normalizeSecurityEvent(event))
	}
	return out
}

func normalizeSecurityEvent(event SecurityEvent) SecurityEvent {
	event.Source = strings.TrimSpace(event.Source)
	event.SourceFormat = strings.TrimSpace(event.SourceFormat)
	event.Sensor = strings.TrimSpace(event.Sensor)
	event.EventType = strings.TrimSpace(event.EventType)
	event.AttackCategory = strings.TrimSpace(event.AttackCategory)
	event.AttackTechnique = strings.TrimSpace(event.AttackTechnique)
	event.Severity = strings.ToUpper(strings.TrimSpace(event.Severity))
	event.Confidence = strings.ToLower(strings.TrimSpace(event.Confidence))
	event.Action = strings.ToUpper(strings.TrimSpace(event.Action))
	event.Verdict = strings.ToLower(strings.TrimSpace(event.Verdict))
	event.Direction = strings.ToLower(strings.TrimSpace(event.Direction))
	event.Protocol = strings.ToLower(strings.TrimSpace(event.Protocol))
	event.DeviceIP = strings.TrimSpace(event.DeviceIP)
	if event.EventType == "" {
		event.EventType = "security_event"
	}
	if event.Severity == "" {
		event.Severity = "INFO"
	}
	if event.Confidence == "" {
		event.Confidence = "low"
	}
	if event.Verdict == "" {
		event.Verdict = verdictFromAction(event.Action)
	}
	if event.AttackCategory == "" && isInboundSecurityEvent(event) {
		event.AttackCategory = "inbound_probe"
	}
	if event.AttackTechnique == "" && isInboundSecurityEvent(event) {
		event.AttackTechnique = "inbound_block"
	}
	if event.DeviceIP == "" && isLocalDeviceIP(event.DstIP) {
		event.DeviceIP = event.DstIP
	}
	if event.AssetRole == "" && event.DeviceIP != "" {
		event.AssetRole = "iot_device"
	}
	if event.AggregationKey == "" {
		event.AggregationKey = attackEvidenceKey(event.SrcIP, firstNonEmpty(event.DeviceIP, event.DstIP), event.Protocol)
	}
	if event.EventID == "" {
		event.EventID = securityEventID(event)
	}
	return event
}

func securityEventID(event SecurityEvent) string {
	parts := []string{
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.Source,
		event.EventType,
		event.SrcIP,
		fmt.Sprintf("%d", event.SrcPort),
		event.DstIP,
		fmt.Sprintf("%d", event.DstPort),
		event.Protocol,
		event.Action,
		event.Raw,
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return "sec_" + hex.EncodeToString(sum[:])[:12]
}

func verdictFromAction(action string) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DROP":
		return "dropped"
	case "REJECT":
		return "rejected"
	case "ACCEPT":
		return "accepted"
	default:
		return ""
	}
}

func isInboundSecurityEvent(event SecurityEvent) bool {
	if strings.Contains(strings.ToLower(event.Direction), "wan_to") || strings.EqualFold(event.Direction, "inbound") {
		return true
	}
	return !isLocalDeviceIP(event.SrcIP) && isLocalDeviceIP(firstNonEmpty(event.DeviceIP, event.DstIP))
}

func isExposedServiceAttempt(event SecurityEvent) bool {
	if !isInboundSecurityEvent(event) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(event.Verdict)) {
	case "accepted", "allowed":
		return true
	default:
		return false
	}
}

func isSensitiveSecurityEvent(event SecurityEvent) bool {
	return isInboundSecurityEvent(event) && isSensitiveEvidencePort(event.DstPort)
}

func isSensitiveEvidencePort(port uint16) bool {
	switch port {
	case 21, 22, 23, 80, 81, 443, 554, 1883, 2323, 5000, 8000, 8080, 8443, 8883:
		return true
	default:
		return false
	}
}

func containsSensitivePort(ports map[uint16]bool) bool {
	for port := range ports {
		if isSensitiveEvidencePort(port) {
			return true
		}
	}
	return false
}

func hasSuspiciousTCPFlags(event SecurityEvent) bool {
	if !strings.EqualFold(event.Protocol, "tcp") {
		return false
	}
	technique := strings.ToLower(strings.TrimSpace(event.AttackTechnique))
	if technique == "tcp_fin_scan" || technique == "tcp_xmas_scan" || technique == "tcp_null_scan" || technique == "suspicious_tcp_flags" {
		return true
	}
	flags := map[string]bool{}
	for _, flag := range event.TCPFlags {
		flags[strings.ToUpper(strings.TrimSpace(flag))] = true
	}
	return (flags["FIN"] && !flags["ACK"] && !flags["SYN"]) || (flags["FIN"] && flags["PSH"] && flags["URG"])
}

func attackEvidenceKey(srcIP, targetIP, protocol string) string {
	return strings.Join([]string{strings.TrimSpace(srcIP), strings.TrimSpace(targetIP), strings.ToLower(strings.TrimSpace(protocol))}, "|")
}

func ensureAttackEvidenceAccumulator(items map[string]*attackEvidenceAccumulator, key, srcIP, targetIP, protocol string) *attackEvidenceAccumulator {
	if items[key] != nil {
		return items[key]
	}
	items[key] = &attackEvidenceAccumulator{
		srcIP:     strings.TrimSpace(srcIP),
		targetIP:  strings.TrimSpace(targetIP),
		protocol:  strings.ToLower(strings.TrimSpace(protocol)),
		ports:     map[uint16]bool{},
		targets:   map[string]bool{},
		evidence:  map[string]bool{},
		technique: map[string]bool{},
	}
	return items[key]
}

func applyAttackEvidenceEvent(acc *attackEvidenceAccumulator, event SecurityEvent) {
	if acc == nil {
		return
	}
	acc.events++
	if event.DstPort != 0 {
		acc.ports[event.DstPort] = true
	}
	addStringBool(acc.targets, firstNonEmpty(event.DeviceIP, event.DstIP))
	addStringBool(acc.technique, event.AttackTechnique)
	if event.Raw != "" && len(acc.evidence) < 8 {
		acc.evidence[event.Raw] = true
	}
	if !event.Timestamp.IsZero() {
		if acc.first.IsZero() || event.Timestamp.Before(acc.first) {
			acc.first = event.Timestamp
		}
		if event.Timestamp.After(acc.last) {
			acc.last = event.Timestamp
		}
	}
}

func attackFindingFromPair(acc *attackEvidenceAccumulator) (AttackEvidenceFinding, bool) {
	if acc == nil {
		return AttackEvidenceFinding{}, false
	}
	portCount := len(acc.ports)
	if portCount < 3 && acc.events < 5 {
		return AttackEvidenceFinding{}, false
	}
	kind := "repeated_inbound_probe"
	if portCount >= 3 {
		kind = "port_scan"
	}
	if acc.technique["suspicious_tcp_flags"] || acc.technique["tcp_fin_scan"] || acc.technique["tcp_xmas_scan"] {
		kind = "suspicious_tcp_flags"
	} else if kind == "repeated_inbound_probe" && containsSensitivePort(acc.ports) {
		kind = "sensitive_service_probe"
	}
	return attackFinding(acc, kind, acc.targetIP), true
}

func attackFindingFromSource(acc *attackEvidenceAccumulator) (AttackEvidenceFinding, bool) {
	if acc == nil || len(acc.targets) < 3 {
		return AttackEvidenceFinding{}, false
	}
	return attackFinding(acc, "sweep", ""), true
}

func attackFinding(acc *attackEvidenceAccumulator, kind, target string) AttackEvidenceFinding {
	severity := "WARNING"
	confidence := "medium"
	if acc.events >= 20 || len(acc.ports) >= 10 || len(acc.targets) >= 10 {
		severity = "HIGH"
		confidence = "high"
	}
	finding := AttackEvidenceFinding{
		Kind:           kind,
		State:          "suspicious",
		Severity:       severity,
		Confidence:     confidence,
		SrcIP:          acc.srcIP,
		TargetDeviceIP: target,
		Protocol:       acc.protocol,
		Ports:          sortedUint16Set(acc.ports),
		Targets:        sortedStringSet(acc.targets),
		EventCount:     acc.events,
		Taxonomy:       []string{"attack_like", kind},
		RecommendedUse: "precision_evidence",
		Evidence:       limitEvidenceStrings(sortedStringSet(acc.evidence), 5),
	}
	if !acc.first.IsZero() {
		finding.FirstSeen = acc.first.UTC().Format(time.RFC3339)
	}
	if !acc.last.IsZero() {
		finding.LastSeen = acc.last.UTC().Format(time.RFC3339)
	}
	sum := sha1.Sum([]byte(strings.Join([]string{kind, acc.srcIP, target, acc.protocol, strings.Join(finding.Targets, ","), joinPorts(finding.Ports)}, "|")))
	finding.ID = "atk_" + hex.EncodeToString(sum[:])[:12]
	return finding
}

func securityEventWindow(events []SecurityEvent) Window {
	var first, last time.Time
	for _, event := range events {
		if event.Timestamp.IsZero() {
			continue
		}
		if first.IsZero() || event.Timestamp.Before(first) {
			first = event.Timestamp
		}
		if event.Timestamp.After(last) {
			last = event.Timestamp
		}
	}
	window := Window{}
	if !first.IsZero() {
		window.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		window.End = last.UTC().Format(time.RFC3339)
	}
	return window
}

func sortedUint16Set(set map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(set))
	for value := range set {
		if value != 0 {
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
