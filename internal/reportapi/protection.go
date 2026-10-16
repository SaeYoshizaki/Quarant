package reportapi

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
	"time"

	"quarant/analyzer/knowledge"
)

type ProtectionSummary struct {
	HomeRiskScore   int                    `json:"home_risk_score"`
	RiskLevel       string                 `json:"risk_level"`
	PassiveCoverage PassiveCoverage        `json:"passive_coverage"`
	Baseline        BehaviorBaseline       `json:"baseline"`
	Metrics         ProtectionMetrics      `json:"metrics"`
	TopDevices      []DeviceProtectionRisk `json:"top_devices"`
	TopReasons      []ProtectionReason     `json:"top_reasons"`
	Recommendations []string               `json:"recommendations"`
	Limitations     []string               `json:"limitations"`
}

type PassiveCoverage struct {
	Score       int            `json:"score"`
	Observed    []CoverageItem `json:"observed"`
	NotObserved []CoverageItem `json:"not_observed"`
}

type CoverageItem struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type ProtectionMetrics struct {
	DeviceCount              int `json:"device_count"`
	DevicesWithRisk          int `json:"devices_with_risk"`
	HighRiskDevices          int `json:"high_risk_devices"`
	UnknownDevices           int `json:"unknown_devices"`
	TotalFlowCount           int `json:"total_flow_count"`
	LocalFlowCount           int `json:"local_flow_count"`
	ExternalFlowCount        int `json:"external_flow_count"`
	NoiseFlowCount           int `json:"noise_flow_count"`
	MulticastBroadcastFlows  int `json:"multicast_broadcast_flows"`
	BaselineDeviceCount      int `json:"baseline_device_count"`
	BaselineReadyDevices     int `json:"baseline_ready_devices"`
	NovelDestinationCount    int `json:"novel_destination_count"`
	NovelProtocolCount       int `json:"novel_protocol_count"`
	NovelPortCount           int `json:"novel_port_count"`
	CategoryProfiledDevices  int `json:"category_profiled_devices"`
	CategoryDeviationCount   int `json:"category_deviation_count"`
	ExternalDestinationCount int `json:"external_destination_count"`
	InsecureServiceCount     int `json:"insecure_service_count"`
	PlaintextTrafficCount    int `json:"plaintext_traffic_count"`
	CriticalEventCount       int `json:"critical_event_count"`
	HighOrCriticalEventCount int `json:"high_or_critical_event_count"`
	QuarantineCandidates     int `json:"quarantine_candidates"`
}

type DeviceProtectionRisk struct {
	IP                 string   `json:"ip"`
	Label              string   `json:"label,omitempty"`
	Category           string   `json:"category,omitempty"`
	RiskScore          int      `json:"risk_score"`
	RiskLevel          string   `json:"risk_level"`
	SignalCount        int      `json:"signal_count"`
	TopSeverity        string   `json:"top_severity,omitempty"`
	ExternalTargets    int      `json:"external_targets"`
	NoveltyCount       int      `json:"novelty_count"`
	CategoryDeviations int      `json:"category_deviations"`
	Reasons            []string `json:"reasons"`
	Recommendation     string   `json:"recommendation,omitempty"`
}

type ProtectionReason struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type BehaviorBaseline struct {
	DeviceCount           int                     `json:"device_count"`
	ReadyDeviceCount      int                     `json:"ready_device_count"`
	NovelDestinationCount int                     `json:"novel_destination_count"`
	NovelProtocolCount    int                     `json:"novel_protocol_count"`
	NovelPortCount        int                     `json:"novel_port_count"`
	WindowPolicy          string                  `json:"window_policy"`
	Devices               []DeviceBehaviorProfile `json:"devices"`
}

type DeviceBehaviorProfile struct {
	IP                  string   `json:"ip"`
	BaselineReady       bool     `json:"baseline_ready"`
	FirstSeen           string   `json:"first_seen,omitempty"`
	LastSeen            string   `json:"last_seen,omitempty"`
	BaselineUntil       string   `json:"baseline_until,omitempty"`
	LearnedDestinations []string `json:"learned_destinations,omitempty"`
	LearnedProtocols    []string `json:"learned_protocols,omitempty"`
	LearnedPorts        []uint16 `json:"learned_ports,omitempty"`
	NovelDestinations   []string `json:"novel_destinations,omitempty"`
	NovelProtocols      []string `json:"novel_protocols,omitempty"`
	NovelPorts          []uint16 `json:"novel_ports,omitempty"`
	Category            string   `json:"category,omitempty"`
	ExpectedProtocols   []string `json:"expected_protocols,omitempty"`
	ExpectedPorts       []uint16 `json:"expected_ports,omitempty"`
	UnexpectedProtocols []string `json:"unexpected_protocols,omitempty"`
	UnexpectedPorts     []uint16 `json:"unexpected_ports,omitempty"`
	PlaintextConcern    bool     `json:"plaintext_concern,omitempty"`
}

type protectionFlowClass string

const (
	protectionFlowExternal protectionFlowClass = "external"
	protectionFlowLocal    protectionFlowClass = "local"
	protectionFlowNoise    protectionFlowClass = "noise"
	protectionFlowUnknown  protectionFlowClass = "unknown"
)

type deviceRiskAccumulator struct {
	ip                 string
	label              string
	category           string
	score              float64
	signals            int
	topSeverity        string
	reasons            map[string]int
	externalTargets    map[string]bool
	noveltyCount       int
	categoryDeviations int
}

func BuildProtectionSummary(events []Event, flows []FlowRecord, devices []InventoryDevice, fallbackUnknownDevices, fallbackQuarantineCandidates int) ProtectionSummary {
	accumulators := map[string]*deviceRiskAccumulator{}
	ensure := func(ip string) *deviceRiskAccumulator {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return nil
		}
		acc := accumulators[ip]
		if acc != nil {
			return acc
		}
		acc = &deviceRiskAccumulator{
			ip:              ip,
			reasons:         map[string]int{},
			externalTargets: map[string]bool{},
		}
		accumulators[ip] = acc
		return acc
	}

	for _, device := range devices {
		acc := ensure(device.IP)
		if acc == nil {
			continue
		}
		acc.label = firstNonEmpty(device.FamilyCandidate, device.VendorCandidate, device.CategoryCandidate)
		acc.category = device.CategoryCandidate
		if device.RiskEventCount > 0 {
			acc.signals += device.RiskEventCount
		}
		for severity, count := range device.SeverityCounts {
			if count <= 0 {
				continue
			}
			if severityRank(severity) > severityRank(acc.topSeverity) {
				acc.topSeverity = severity
			}
		}
	}

	metrics := ProtectionMetrics{}
	reasonCounts := map[string]int{}
	unknownDeviceSet := map[string]bool{}
	quarantineCandidateEvents := 0

	for _, event := range events {
		if event.Debug {
			continue
		}
		rule := canonicalRuleID(event)
		if rule == "" {
			rule = strings.TrimSpace(event.Type)
		}
		reasonCounts[rule]++

		if isUnknownDeviceEvent(event) {
			key := firstNonEmpty(event.DeviceKey, event.SrcIP, event.DstIP)
			if key != "" {
				unknownDeviceSet[key] = true
			}
		}
		if rule == "R1_QUARANTINE_RECOMMENDATION" {
			quarantineCandidateEvents++
		}
		if isInsecureServiceEvent(event) {
			metrics.InsecureServiceCount++
		}
		if isPlaintextEvent(event) {
			metrics.PlaintextTrafficCount++
		}
		if strings.EqualFold(event.Severity, "CRITICAL") {
			metrics.CriticalEventCount++
		}
		if severityRank(event.Severity) >= severityRank("HIGH") {
			metrics.HighOrCriticalEventCount++
		}

		weight := weightedEventScore(event)
		for _, ip := range eventDeviceIPs(event) {
			acc := ensure(ip)
			if acc == nil {
				continue
			}
			acc.score += weight
			acc.signals++
			if severityRank(event.Severity) > severityRank(acc.topSeverity) {
				acc.topSeverity = event.Severity
			}
			if rule != "" {
				acc.reasons[rule]++
			}
			if acc.label == "" {
				acc.label = event.DeviceLabel
			}
		}
	}

	externalTargets := map[string]bool{}
	for _, flow := range flows {
		metrics.TotalFlowCount++
		class := classifyProtectionFlow(flow)
		if class == protectionFlowNoise {
			metrics.NoiseFlowCount++
		}
		if isMulticastOrBroadcastIP(flow.DstIP) {
			metrics.MulticastBroadcastFlows++
		}

		if isLocalDeviceIP(flow.SrcIP) {
			ensure(flow.SrcIP)
		}
		if isLocalDeviceIP(flow.DstIP) && !isMulticastOrBroadcastIP(flow.DstIP) {
			ensure(flow.DstIP)
		}

		switch class {
		case protectionFlowExternal:
			metrics.ExternalFlowCount++
		case protectionFlowLocal:
			metrics.LocalFlowCount++
		}
		if class != protectionFlowExternal {
			continue
		}
		target := normalizedProtectionDestination(flow)
		if target != "" {
			externalTargets[target] = true
		}
		if acc := ensure(flow.SrcIP); acc != nil && target != "" {
			acc.externalTargets[target] = true
		}
	}

	metrics.DeviceCount = len(accumulators)
	metrics.UnknownDevices = maxInt(fallbackUnknownDevices, len(unknownDeviceSet))
	metrics.ExternalDestinationCount = len(externalTargets)
	metrics.QuarantineCandidates = maxInt(fallbackQuarantineCandidates, quarantineCandidateEvents)
	baseline := buildBehaviorBaseline(flows, devices)
	metrics.BaselineDeviceCount = baseline.DeviceCount
	metrics.BaselineReadyDevices = baseline.ReadyDeviceCount
	metrics.NovelDestinationCount = baseline.NovelDestinationCount
	metrics.NovelProtocolCount = baseline.NovelProtocolCount
	metrics.NovelPortCount = baseline.NovelPortCount
	metrics.CategoryProfiledDevices = countCategoryProfiledDevices(baseline)
	metrics.CategoryDeviationCount = countCategoryDeviations(baseline)
	applyBaselineNovelty(accumulators, baseline)

	deviceRisks := make([]DeviceProtectionRisk, 0, len(accumulators))
	totalDeviceScore := 0
	for _, acc := range accumulators {
		score := clampInt(roundScore(acc.score), 0, 100)
		if acc.signals == 1 && score > 35 {
			score = 35
		}
		if score > 0 {
			metrics.DevicesWithRisk++
		}
		if score >= 60 {
			metrics.HighRiskDevices++
		}
		totalDeviceScore += score
		deviceRisks = append(deviceRisks, DeviceProtectionRisk{
			IP:                 acc.ip,
			Label:              acc.label,
			Category:           acc.category,
			RiskScore:          score,
			RiskLevel:          riskLevel(score),
			SignalCount:        acc.signals,
			TopSeverity:        acc.topSeverity,
			ExternalTargets:    len(acc.externalTargets),
			NoveltyCount:       acc.noveltyCount,
			CategoryDeviations: acc.categoryDeviations,
			Reasons:            topReasonLabels(acc.reasons, 3),
			Recommendation:     recommendationForRisk(score),
		})
	}
	sort.Slice(deviceRisks, func(i, j int) bool {
		if deviceRisks[i].RiskScore == deviceRisks[j].RiskScore {
			return deviceRisks[i].IP < deviceRisks[j].IP
		}
		return deviceRisks[i].RiskScore > deviceRisks[j].RiskScore
	})

	homeScore := homeRiskScore(metrics, totalDeviceScore, len(deviceRisks))
	summary := ProtectionSummary{
		HomeRiskScore:   homeScore,
		RiskLevel:       riskLevel(homeScore),
		PassiveCoverage: buildPassiveCoverage(events, flows, devices),
		Baseline:        baseline,
		Metrics:         metrics,
		TopDevices:      limitDeviceRisks(deviceRisks, 5),
		TopReasons:      topProtectionReasons(reasonCounts, 6),
		Recommendations: recommendationsForMetrics(metrics, homeScore),
		Limitations: []string{
			"Passive monitoring cannot inspect encrypted HTTPS payloads.",
			"Passive monitoring cannot prove whether an exploit succeeded inside a device.",
			"Risk scores are based on observed network signals, not active vulnerability confirmation.",
		},
	}
	return summary
}

func weightedEventScore(event Event) float64 {
	base := float64(severityScore(event.Severity))
	if base <= 0 {
		base = 2
	}
	base *= confidenceMultiplier(event.Confidence)
	base *= categoryMultiplier(event.Category, canonicalRuleID(event))
	if isLowNoiseEvent(event) {
		base *= 0.35
	}
	return base
}

func severityScore(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 32
	case "HIGH":
		return 22
	case "MEDIUM", "WARNING":
		return 12
	case "LOW":
		return 5
	case "INFO":
		return 1
	default:
		return 3
	}
}

func confidenceMultiplier(confidence string) float64 {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high":
		return 1.0
	case "medium":
		return 0.75
	case "low":
		return 0.4
	default:
		return 0.65
	}
}

func categoryMultiplier(category, rule string) float64 {
	category = strings.ToUpper(strings.TrimSpace(category))
	rule = strings.ToUpper(strings.TrimSpace(rule))
	switch {
	case category == "I2", strings.Contains(rule, "TELNET"), strings.Contains(rule, "INSECURE_SERVICE"):
		return 1.2
	case category == "I7", strings.Contains(rule, "PLAINTEXT"), strings.Contains(rule, "TOKEN"):
		return 1.15
	case category == "I1", category == "I3":
		return 1.1
	case category == "R1":
		return 1.2
	case category == "I8":
		return 0.75
	default:
		return 1
	}
}

func isLowNoiseEvent(event Event) bool {
	rule := strings.ToUpper(canonicalRuleID(event))
	return strings.Contains(rule, "DEBUG") ||
		strings.Contains(rule, "MDNS") ||
		strings.Contains(rule, "SSDP") ||
		strings.Contains(rule, "DHCP") ||
		strings.Contains(rule, "NTP")
}

func eventDeviceIPs(event Event) []string {
	set := map[string]bool{}
	for _, ip := range []string{event.DeviceKey, event.SrcIP, event.DstIP} {
		ip = strings.TrimSpace(ip)
		if ip == "" || set[ip] || !isLocalDeviceIP(ip) {
			continue
		}
		set[ip] = true
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func isLocalDeviceIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

func classifyProtectionFlow(flow FlowRecord) protectionFlowClass {
	if isNoiseFlow(flow) {
		return protectionFlowNoise
	}
	if strings.EqualFold(strings.TrimSpace(flow.Direction), "external") {
		return protectionFlowExternal
	}
	if strings.EqualFold(strings.TrimSpace(flow.Direction), "local") {
		return protectionFlowLocal
	}

	dst := strings.TrimSpace(flow.DstIP)
	if dst == "" {
		return protectionFlowUnknown
	}
	if isLocalDeviceIP(dst) || isMulticastOrBroadcastIP(dst) {
		return protectionFlowLocal
	}
	return protectionFlowExternal
}

func isNoiseFlow(flow FlowRecord) bool {
	if isMulticastOrBroadcastIP(flow.DstIP) {
		return true
	}
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(flow.AppProtocol, flow.Protocol)))
	switch protocol {
	case "mdns", "ssdp", "dhcp", "arp", "llmnr", "nbns", "ntp":
		return true
	}
	switch flow.DstPort {
	case 53:
		return strings.EqualFold(protocol, "dns")
	case 67, 68, 123, 137, 138, 1900, 5353, 5355:
		return true
	default:
		return false
	}
}

func isMulticastOrBroadcastIP(ip string) bool {
	value := strings.TrimSpace(ip)
	if value == "" {
		return false
	}
	parsed := net.ParseIP(value)
	if parsed == nil {
		return false
	}
	if parsed.IsMulticast() {
		return true
	}
	v4 := parsed.To4()
	if v4 == nil {
		return false
	}
	return v4[0] == 255 && v4[1] == 255 && v4[2] == 255 && v4[3] == 255 ||
		v4[3] == 255
}

type protectionCategoryBaseline struct {
	ExpectedProtocols  []string `json:"expected_protocols"`
	CommonPorts        []int    `json:"common_ports"`
	PlaintextTolerance string   `json:"plaintext_tolerance"`
}

func buildBehaviorBaseline(flows []FlowRecord, devices []InventoryDevice) BehaviorBaseline {
	baseline := BehaviorBaseline{
		WindowPolicy: "adaptive: first third of observed non-noise traffic, capped at 24h",
		Devices:      []DeviceBehaviorProfile{},
	}
	categoryByIP := deviceCategoriesByIP(devices, flows)
	categoryBaselines := loadProtectionCategoryBaselines()
	byDevice := map[string][]FlowRecord{}
	for _, flow := range flows {
		if !isLocalDeviceIP(flow.SrcIP) || isNoiseFlow(flow) {
			continue
		}
		if normalizedProtectionDestination(flow) == "" && firstNonEmpty(flow.AppProtocol, flow.Protocol) == "" && flow.DstPort == 0 {
			continue
		}
		byDevice[strings.TrimSpace(flow.SrcIP)] = append(byDevice[strings.TrimSpace(flow.SrcIP)], flow)
	}

	for ip, deviceFlows := range byDevice {
		profile := buildDeviceBehaviorProfile(ip, deviceFlows)
		applyCategoryExpectations(&profile, categoryByIP[ip], categoryBaselines)
		baseline.Devices = append(baseline.Devices, profile)
		baseline.DeviceCount++
		if profile.BaselineReady {
			baseline.ReadyDeviceCount++
		}
		baseline.NovelDestinationCount += len(profile.NovelDestinations)
		baseline.NovelProtocolCount += len(profile.NovelProtocols)
		baseline.NovelPortCount += len(profile.NovelPorts)
	}
	sort.Slice(baseline.Devices, func(i, j int) bool {
		leftNovelty := len(baseline.Devices[i].NovelDestinations) + len(baseline.Devices[i].NovelProtocols) + len(baseline.Devices[i].NovelPorts)
		rightNovelty := len(baseline.Devices[j].NovelDestinations) + len(baseline.Devices[j].NovelProtocols) + len(baseline.Devices[j].NovelPorts)
		if leftNovelty == rightNovelty {
			return baseline.Devices[i].IP < baseline.Devices[j].IP
		}
		return leftNovelty > rightNovelty
	})
	return baseline
}

func deviceCategoriesByIP(devices []InventoryDevice, flows []FlowRecord) map[string]string {
	out := map[string]string{}
	for _, device := range devices {
		ip := strings.TrimSpace(device.IP)
		category := normalizeProtectionCategory(device.CategoryCandidate)
		if ip != "" && category != "" {
			out[ip] = category
		}
	}
	for _, flow := range flows {
		ip := strings.TrimSpace(flow.SrcIP)
		category := normalizeProtectionCategory(flow.DeviceCategory)
		if ip != "" && category != "" && out[ip] == "" {
			out[ip] = category
		}
	}
	return out
}

func normalizeProtectionCategory(category string) string {
	category = strings.TrimSpace(category)
	if category == "" || strings.EqualFold(category, "unknown") || strings.EqualFold(category, "GenericIoT") {
		return ""
	}
	return category
}

func loadProtectionCategoryBaselines() map[string]protectionCategoryBaseline {
	data, err := knowledge.ReadFile("category_behavior_baselines.json")
	if err != nil {
		return fallbackProtectionCategoryBaselines()
	}
	var out map[string]protectionCategoryBaseline
	if err := json.Unmarshal(data, &out); err != nil {
		return fallbackProtectionCategoryBaselines()
	}
	if len(out) == 0 {
		return fallbackProtectionCategoryBaselines()
	}
	return out
}

func fallbackProtectionCategoryBaselines() map[string]protectionCategoryBaseline {
	return map[string]protectionCategoryBaseline{
		"Camera": {
			ExpectedProtocols:  []string{"https", "rtsp", "tls"},
			CommonPorts:        []int{443, 554, 123},
			PlaintextTolerance: "limited",
		},
		"Hub": {
			ExpectedProtocols:  []string{"https", "mqtt", "coap", "tls"},
			CommonPorts:        []int{443, 8883, 5683, 123},
			PlaintextTolerance: "limited",
		},
		"Sensor": {
			ExpectedProtocols:  []string{"https", "mqtt", "coap", "tls"},
			CommonPorts:        []int{443, 8883, 5683, 123},
			PlaintextTolerance: "low",
		},
		"Controller": {
			ExpectedProtocols:  []string{"https", "tls", "http"},
			CommonPorts:        []int{443, 80, 123},
			PlaintextTolerance: "limited",
		},
	}
}

func applyCategoryExpectations(profile *DeviceBehaviorProfile, category string, baselines map[string]protectionCategoryBaseline) {
	if profile == nil || category == "" || len(baselines) == 0 {
		return
	}
	entry, ok := baselines[category]
	if !ok {
		return
	}
	profile.Category = category
	profile.ExpectedProtocols = normalizedExpectedProtocols(entry.ExpectedProtocols)
	profile.ExpectedPorts = normalizedExpectedPorts(entry.CommonPorts)

	expectedProtocols := stringSetLower(profile.ExpectedProtocols)
	expectedPorts := portSet(profile.ExpectedPorts)
	unexpectedProtocols := map[string]bool{}
	unexpectedPorts := map[uint16]bool{}

	for _, protocol := range profile.NovelProtocols {
		normalized := strings.ToLower(strings.TrimSpace(protocol))
		if normalized == "" || expectedProtocols[normalized] || transportProtocol(normalized) {
			continue
		}
		if normalized == "http" && entry.PlaintextTolerance != "low" {
			continue
		}
		unexpectedProtocols[strings.ToUpper(protocol)] = true
	}
	for _, port := range profile.NovelPorts {
		if port == 0 || expectedPorts[port] {
			continue
		}
		unexpectedPorts[port] = true
	}
	if containsStringLower(profile.NovelProtocols, "http") && strings.EqualFold(entry.PlaintextTolerance, "low") {
		profile.PlaintextConcern = true
	}

	profile.UnexpectedProtocols = sortedStringSet(unexpectedProtocols)
	profile.UnexpectedPorts = sortedPortSet(unexpectedPorts)
}

func buildDeviceBehaviorProfile(ip string, flows []FlowRecord) DeviceBehaviorProfile {
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].Timestamp.Before(flows[j].Timestamp)
	})

	profile := DeviceBehaviorProfile{IP: ip}
	if len(flows) == 0 {
		return profile
	}

	first, last := flowWindow(flows)
	if !first.IsZero() {
		profile.FirstSeen = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		profile.LastSeen = last.UTC().Format(time.RFC3339)
	}

	baselineUntil, ready := baselineCutoff(first, last)
	profile.BaselineReady = ready
	if ready {
		profile.BaselineUntil = baselineUntil.UTC().Format(time.RFC3339)
	}

	learnedDestinations := map[string]bool{}
	learnedProtocols := map[string]bool{}
	learnedPorts := map[uint16]bool{}
	novelDestinations := map[string]bool{}
	novelProtocols := map[string]bool{}
	novelPorts := map[uint16]bool{}

	for _, flow := range flows {
		destination := normalizedProtectionDestination(flow)
		protocol := normalizedProtectionProtocol(flow)
		port := flow.DstPort
		inLearningWindow := !ready || flow.Timestamp.IsZero() || !flow.Timestamp.After(baselineUntil)

		if inLearningWindow {
			addBehaviorSignal(learnedDestinations, learnedProtocols, learnedPorts, destination, protocol, port)
			continue
		}
		if destination != "" && !learnedDestinations[destination] {
			novelDestinations[destination] = true
		}
		if protocol != "" && !learnedProtocols[protocol] {
			novelProtocols[protocol] = true
		}
		if port != 0 && !learnedPorts[port] {
			novelPorts[port] = true
		}
	}

	profile.LearnedDestinations = sortedStringSet(learnedDestinations)
	profile.LearnedProtocols = sortedStringSet(learnedProtocols)
	profile.LearnedPorts = sortedPortSet(learnedPorts)
	profile.NovelDestinations = sortedStringSet(novelDestinations)
	profile.NovelProtocols = sortedStringSet(novelProtocols)
	profile.NovelPorts = sortedPortSet(novelPorts)
	return profile
}

func flowWindow(flows []FlowRecord) (time.Time, time.Time) {
	var first time.Time
	var last time.Time
	for _, flow := range flows {
		if flow.Timestamp.IsZero() {
			continue
		}
		if first.IsZero() || flow.Timestamp.Before(first) {
			first = flow.Timestamp
		}
		if flow.Timestamp.After(last) {
			last = flow.Timestamp
		}
	}
	return first, last
}

func baselineCutoff(first, last time.Time) (time.Time, bool) {
	if first.IsZero() || last.IsZero() || !last.After(first) {
		return time.Time{}, false
	}
	duration := last.Sub(first)
	if duration < 2*time.Minute {
		return time.Time{}, false
	}

	window := duration / 3
	if window > 24*time.Hour {
		window = 24 * time.Hour
	}
	if window < 5*time.Minute && duration >= 10*time.Minute {
		window = 5 * time.Minute
	}
	if window <= 0 || window >= duration {
		return time.Time{}, false
	}
	return first.Add(window), true
}

func addBehaviorSignal(destinations map[string]bool, protocols map[string]bool, ports map[uint16]bool, destination, protocol string, port uint16) {
	if destination != "" {
		destinations[destination] = true
	}
	if protocol != "" {
		protocols[protocol] = true
	}
	if port != 0 {
		ports[port] = true
	}
}

func normalizedProtectionProtocol(flow FlowRecord) string {
	return strings.ToUpper(strings.TrimSpace(firstNonEmpty(flow.AppProtocol, flow.Protocol)))
}

func sortedStringSet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	return uniqueSortedStrings(values)
}

func sortedPortSet(set map[uint16]bool) []uint16 {
	values := make([]uint16, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	return uniqueSortedPorts(values)
}

func normalizedExpectedProtocols(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value != "" {
			out = append(out, value)
		}
	}
	return uniqueSortedStrings(out)
}

func normalizedExpectedPorts(values []int) []uint16 {
	out := make([]uint16, 0, len(values))
	for _, value := range values {
		if value <= 0 || value > 65535 {
			continue
		}
		out = append(out, uint16(value))
	}
	return uniqueSortedPorts(out)
}

func stringSetLower(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			out[value] = true
		}
	}
	return out
}

func portSet(values []uint16) map[uint16]bool {
	out := map[uint16]bool{}
	for _, value := range values {
		if value != 0 {
			out[value] = true
		}
	}
	return out
}

func transportProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tcp", "udp", "icmp":
		return true
	default:
		return false
	}
}

func containsStringLower(values []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == needle {
			return true
		}
	}
	return false
}

func countCategoryProfiledDevices(baseline BehaviorBaseline) int {
	count := 0
	for _, profile := range baseline.Devices {
		if strings.TrimSpace(profile.Category) != "" {
			count++
		}
	}
	return count
}

func countCategoryDeviations(baseline BehaviorBaseline) int {
	count := 0
	for _, profile := range baseline.Devices {
		count += len(profile.UnexpectedProtocols)
		count += len(profile.UnexpectedPorts)
		if profile.PlaintextConcern {
			count++
		}
	}
	return count
}

func applyBaselineNovelty(accumulators map[string]*deviceRiskAccumulator, baseline BehaviorBaseline) {
	for _, profile := range baseline.Devices {
		noveltyCount := len(profile.NovelDestinations) + len(profile.NovelProtocols) + len(profile.NovelPorts)
		categoryDeviationCount := len(profile.UnexpectedProtocols) + len(profile.UnexpectedPorts)
		if profile.PlaintextConcern {
			categoryDeviationCount++
		}
		if noveltyCount == 0 && categoryDeviationCount == 0 {
			continue
		}
		acc := accumulators[profile.IP]
		if acc == nil {
			continue
		}
		acc.noveltyCount = noveltyCount
		acc.categoryDeviations = categoryDeviationCount
		acc.signals += noveltyCount
		acc.score += float64(minInt(noveltyCount*8, 24))
		if noveltyCount > 0 {
			acc.reasons["BASELINE_NOVELTY"] += noveltyCount
		}
		if categoryDeviationCount > 0 {
			acc.signals += categoryDeviationCount
			acc.score += float64(minInt(categoryDeviationCount*12, 36))
			acc.reasons["CATEGORY_BASELINE_DEVIATION"] += categoryDeviationCount
		}
	}
}

func normalizedProtectionDestination(flow FlowRecord) string {
	for _, candidate := range []string{flow.ObservedDestination, flow.SNI, flow.Host, flow.DstIP} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" && candidate != "-" {
			return candidate
		}
	}
	return ""
}

func isUnknownDeviceEvent(event Event) bool {
	rule := strings.ToUpper(canonicalRuleID(event))
	return rule == "I8_UNREGISTERED_DEVICE_ACTIVE" || rule == "I8_NEW_DEVICE_OBSERVED"
}

func isInsecureServiceEvent(event Event) bool {
	rule := strings.ToUpper(canonicalRuleID(event))
	return strings.Contains(rule, "TELNET") ||
		strings.Contains(rule, "FTP") ||
		strings.Contains(rule, "RTSP") ||
		strings.Contains(rule, "COAP") ||
		strings.Contains(rule, "MQTT") ||
		strings.Contains(rule, "INSECURE_SERVICE") ||
		strings.EqualFold(event.Category, "I2")
}

func isPlaintextEvent(event Event) bool {
	rule := strings.ToUpper(canonicalRuleID(event))
	return strings.Contains(rule, "PLAINTEXT") ||
		strings.Contains(rule, "HTTP_TOKEN") ||
		strings.Contains(rule, "HTTP_AUTH") ||
		strings.Contains(rule, "HTTP_BODY_SECRET")
}

func roundScore(value float64) int {
	if value < 0 {
		return 0
	}
	return int(value + 0.5)
}

func clampInt(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 35:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "observed"
	}
}

func homeRiskScore(metrics ProtectionMetrics, totalDeviceScore, deviceCount int) int {
	avgDeviceScore := 0
	if deviceCount > 0 {
		avgDeviceScore = totalDeviceScore / deviceCount
	}
	score := avgDeviceScore
	score += metrics.HighRiskDevices * 10
	score += metrics.UnknownDevices * 4
	score += minInt(metrics.ExternalDestinationCount, 20)
	score += metrics.InsecureServiceCount * 9
	score += metrics.PlaintextTrafficCount * 6
	score += minInt(metrics.NovelDestinationCount*6+metrics.NovelProtocolCount*5+metrics.NovelPortCount*4, 24)
	score += minInt(metrics.CategoryDeviationCount*8, 24)
	score += metrics.CriticalEventCount * 10
	score += metrics.QuarantineCandidates * 8
	return clampInt(score, 0, 100)
}

func buildPassiveCoverage(events []Event, flows []FlowRecord, devices []InventoryDevice) PassiveCoverage {
	capabilities := []CoverageItem{
		{Key: "device_inventory", Label: "Device inventory from passive observations"},
		{Key: "flow_metadata", Label: "Flow metadata and traffic direction"},
		{Key: "protocol_metadata", Label: "Protocol and port metadata"},
		{Key: "tls_metadata", Label: "TLS SNI or certificate-visible metadata"},
		{Key: "http_metadata", Label: "Plaintext HTTP host/path metadata"},
		{Key: "risk_events", Label: "Network-visible risk signals"},
		{Key: "recommendations", Label: "Actionable recommendations"},
	}
	observedKeys := map[string]bool{}
	if len(devices) > 0 {
		observedKeys["device_inventory"] = true
	}
	if len(flows) > 0 {
		observedKeys["flow_metadata"] = true
	}
	for _, flow := range flows {
		if strings.TrimSpace(flow.Protocol) != "" || strings.TrimSpace(flow.AppProtocol) != "" || flow.DstPort != 0 {
			observedKeys["protocol_metadata"] = true
		}
		if strings.TrimSpace(flow.SNI) != "" {
			observedKeys["tls_metadata"] = true
		}
		if strings.TrimSpace(flow.Host) != "" || strings.TrimSpace(flow.HTTPPath) != "" {
			observedKeys["http_metadata"] = true
		}
	}
	for _, event := range events {
		if event.Debug {
			continue
		}
		observedKeys["risk_events"] = true
		if strings.TrimSpace(event.Recommendation) != "" || strings.TrimSpace(event.RecommendedAction) != "" || len(event.UserActions) > 0 {
			observedKeys["recommendations"] = true
		}
	}

	coverage := PassiveCoverage{}
	for _, item := range capabilities {
		if observedKeys[item.Key] {
			coverage.Observed = append(coverage.Observed, item)
		} else {
			coverage.NotObserved = append(coverage.NotObserved, item)
		}
	}
	coverage.Score = percentInt(len(coverage.Observed), len(capabilities))
	return coverage
}

func percentInt(count, total int) int {
	if total <= 0 {
		return 0
	}
	return int(float64(count)/float64(total)*100 + 0.5)
}

func limitDeviceRisks(devices []DeviceProtectionRisk, limit int) []DeviceProtectionRisk {
	if len(devices) <= limit {
		return devices
	}
	return devices[:limit]
}

func topProtectionReasons(counts map[string]int, limit int) []ProtectionReason {
	items := make([]ProtectionReason, 0, len(counts))
	for key, count := range counts {
		if strings.TrimSpace(key) == "" || count <= 0 {
			continue
		}
		items = append(items, ProtectionReason{Key: key, Label: protectionReasonLabel(key), Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Key < items[j].Key
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		return items[:limit]
	}
	return items
}

func topReasonLabels(counts map[string]int, limit int) []string {
	reasons := topProtectionReasons(counts, limit)
	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, reason.Label)
	}
	return out
}

func protectionReasonLabel(rule string) string {
	token := strings.ToUpper(strings.TrimSpace(rule))
	switch token {
	case "I7_HTTP_PLAINTEXT":
		return "Plaintext HTTP traffic"
	case "I7_HTTP_TOKEN", "I3_AUTH_TOKEN_IN_URL":
		return "Token-like value over plaintext traffic"
	case "I7_HTTP_AUTH":
		return "Authorization data over plaintext HTTP"
	case "I2_TELNET_SERVICE_OBSERVED", "I7_TELNET_PLAINTEXT":
		return "Telnet traffic observed"
	case "I2_MQTT_SERVICE_OBSERVED", "I7_MQTT_PLAINTEXT":
		return "Plaintext MQTT traffic observed"
	case "I8_UNREGISTERED_DEVICE_ACTIVE":
		return "Unregistered device activity"
	case "I8_NEW_DEVICE_OBSERVED":
		return "New device observed"
	case "R1_QUARANTINE_RECOMMENDATION":
		return "Quarantine recommended"
	case "BASELINE_NOVELTY":
		return "Behavior differs from learned baseline"
	case "CATEGORY_BASELINE_DEVIATION":
		return "Behavior differs from category baseline"
	default:
		if token == "" {
			return "Unclassified risk signal"
		}
		return token
	}
}

func recommendationForRisk(score int) string {
	switch {
	case score >= 80:
		return "Isolate this device and review its external destinations before trusting it again."
	case score >= 60:
		return "Move this device to an IoT network and verify firmware, credentials, and exposed services."
	case score >= 35:
		return "Investigate this device's recent traffic and compare it with expected behavior."
	case score > 0:
		return "Keep monitoring this device and collect more baseline traffic."
	default:
		return "No risk action is suggested from passive observations yet."
	}
}

func recommendationsForMetrics(metrics ProtectionMetrics, homeScore int) []string {
	recs := []string{}
	if homeScore >= 60 {
		recs = append(recs, "Review high-risk devices first and consider temporary IoT-network isolation.")
	}
	if metrics.PlaintextTrafficCount > 0 {
		recs = append(recs, "Replace plaintext HTTP or credential-bearing traffic with HTTPS where the device supports it.")
	}
	if metrics.InsecureServiceCount > 0 {
		recs = append(recs, "Disable Telnet, FTP, unauthenticated MQTT, or other insecure services that are not required.")
	}
	if metrics.UnknownDevices > 0 {
		recs = append(recs, "Identify unknown devices and move unrecognized devices to a guest or quarantine network.")
	}
	if metrics.ExternalDestinationCount > 0 {
		recs = append(recs, "Review external destinations and block destinations that are not needed for device operation.")
	}
	if metrics.NovelDestinationCount > 0 || metrics.NovelProtocolCount > 0 || metrics.NovelPortCount > 0 {
		recs = append(recs, "Compare baseline novelty with expected device behavior before treating it as malicious.")
	}
	if metrics.CategoryDeviationCount > 0 {
		recs = append(recs, "Review category baseline deviations first; they are unusual for the inferred device type.")
	}
	if metrics.NoiseFlowCount > 0 && metrics.ExternalDestinationCount == 0 && homeScore < 35 {
		recs = append(recs, "Discovery and housekeeping traffic was treated as baseline noise; keep collecting traffic to strengthen the baseline.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Continue passive monitoring to build a stronger normal-behavior baseline.")
	}
	return recs
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
