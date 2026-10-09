package reportapi

import (
	"sort"
	"strings"
	"time"
)

type DeviceEvidenceReport struct {
	GeneratedAt string                  `json:"generated_at"`
	Source      DeviceEvidenceSources   `json:"source"`
	Window      Window                  `json:"window"`
	Metrics     DeviceEvidenceMetrics   `json:"metrics"`
	Devices     []DeviceEvidenceProfile `json:"devices"`
}

type DeviceEvidenceSources struct {
	Events       string `json:"events,omitempty"`
	Flows        string `json:"flows,omitempty"`
	Observations string `json:"observations,omitempty"`
	Inventory    string `json:"inventory,omitempty"`
}

type DeviceEvidenceMetrics struct {
	DeviceCount           int `json:"device_count"`
	DevicesWithRisk       int `json:"devices_with_risk"`
	DevicesWithBlindSpot  int `json:"devices_with_blind_spot"`
	DefenseCandidateCount int `json:"defense_candidate_count"`
	JudgedNormal          int `json:"judged_normal"`
	JudgedSuspicious      int `json:"judged_suspicious"`
	JudgedRisky           int `json:"judged_risky"`
	JudgedUnknown         int `json:"judged_unknown"`
}

type DeviceEvidenceProfile struct {
	IP                 string                 `json:"ip"`
	Label              string                 `json:"label,omitempty"`
	Category           string                 `json:"category,omitempty"`
	CategoryConfidence string                 `json:"category_confidence,omitempty"`
	Vendor             string                 `json:"vendor,omitempty"`
	VendorConfidence   string                 `json:"vendor_confidence,omitempty"`
	Family             string                 `json:"family,omitempty"`
	FamilyConfidence   string                 `json:"family_confidence,omitempty"`
	FirstSeen          string                 `json:"first_seen,omitempty"`
	LastSeen           string                 `json:"last_seen,omitempty"`
	EventCount         int                    `json:"event_count"`
	FlowCount          int                    `json:"flow_count"`
	ObservationCount   int                    `json:"observation_count"`
	ObservedEvidence   DeviceObservedEvidence `json:"observed_evidence"`
	InferredFacts      []EvidenceFinding      `json:"inferred_facts"`
	RiskSignals        []DeviceRiskSignal     `json:"risk_signals"`
	PassiveBlindSpots  []EvidenceFinding      `json:"passive_blind_spots"`
	DefenseCandidates  []EvidenceFinding      `json:"defense_candidates"`
	Judgment           DeviceJudgment         `json:"judgment"`
}

type DeviceObservedEvidence struct {
	Protocols            []string `json:"protocols,omitempty"`
	Ports                []uint16 `json:"ports,omitempty"`
	DNSQueries           []string `json:"dns_queries,omitempty"`
	TLSSNI               []string `json:"tls_sni,omitempty"`
	HTTPHosts            []string `json:"http_hosts,omitempty"`
	HTTPRequests         []string `json:"http_requests,omitempty"`
	ExternalDestinations []string `json:"external_destinations,omitempty"`
	LocalDestinations    []string `json:"local_destinations,omitempty"`
	DiscoveryProtocols   []string `json:"discovery_protocols,omitempty"`
	UnknownUDPPorts      []uint16 `json:"unknown_udp_ports,omitempty"`
}

type EvidenceFinding struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	Source     string `json:"source,omitempty"`
}

type DeviceRiskSignal struct {
	RuleID         string   `json:"rule_id"`
	Severity       string   `json:"severity,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	Count          int      `json:"count"`
	FirstSeen      string   `json:"first_seen,omitempty"`
	LastSeen       string   `json:"last_seen,omitempty"`
	ObservedFact   string   `json:"observed_fact,omitempty"`
	Inference      string   `json:"inference,omitempty"`
	Limitation     string   `json:"limitation,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
}

type deviceEvidenceAccumulator struct {
	profile              DeviceEvidenceProfile
	protocols            map[string]bool
	ports                map[uint16]bool
	dnsQueries           map[string]bool
	tlsSNI               map[string]bool
	httpHosts            map[string]bool
	httpRequests         map[string]bool
	externalDestinations map[string]bool
	localDestinations    map[string]bool
	discoveryProtocols   map[string]bool
	unknownUDPPorts      map[uint16]bool
	riskSignals          map[string]*riskSignalAccumulator
	eventKeys            map[string]bool
	flowKeys             map[string]bool
	observationKeys      map[string]bool
}

type riskSignalAccumulator struct {
	ruleID         string
	severity       string
	confidence     string
	count          int
	first          time.Time
	last           time.Time
	observedFact   string
	inference      string
	limitation     string
	recommendation string
	evidence       map[string]bool
}

func LoadDeviceEvidenceReport(eventsPath, flowsPath, observationsPath, inventoryPath string) (DeviceEvidenceReport, error) {
	report, err := LoadReport(eventsPath)
	if err != nil {
		return DeviceEvidenceReport{}, err
	}
	flows, err := LoadFlows(flowsPath)
	if err != nil {
		return DeviceEvidenceReport{}, err
	}
	observations, err := LoadObservations(observationsPath)
	if err != nil {
		return DeviceEvidenceReport{}, err
	}
	inventory, err := LoadInventoryWithFallback(inventoryPath, eventsPath, flowsPath)
	if err != nil {
		return DeviceEvidenceReport{}, err
	}
	out := BuildDeviceEvidenceReport(report.Events, flows, observations, inventory.Devices)
	out.Source = DeviceEvidenceSources{
		Events:       eventsPath,
		Flows:        flowsPath,
		Observations: observationsPath,
		Inventory:    inventoryPath,
	}
	return out, nil
}

func BuildDeviceEvidenceReport(events []Event, flows []FlowRecord, observations []ObservationRecord, devices []InventoryDevice) DeviceEvidenceReport {
	accs := map[string]*deviceEvidenceAccumulator{}
	ensure := func(ip string) *deviceEvidenceAccumulator {
		ip = strings.TrimSpace(ip)
		if ip == "" || !isEvidenceDeviceIP(ip, devices) {
			return nil
		}
		if accs[ip] != nil {
			return accs[ip]
		}
		accs[ip] = &deviceEvidenceAccumulator{
			profile:              DeviceEvidenceProfile{IP: ip},
			protocols:            map[string]bool{},
			ports:                map[uint16]bool{},
			dnsQueries:           map[string]bool{},
			tlsSNI:               map[string]bool{},
			httpHosts:            map[string]bool{},
			httpRequests:         map[string]bool{},
			externalDestinations: map[string]bool{},
			localDestinations:    map[string]bool{},
			discoveryProtocols:   map[string]bool{},
			unknownUDPPorts:      map[uint16]bool{},
			riskSignals:          map[string]*riskSignalAccumulator{},
			eventKeys:            map[string]bool{},
			flowKeys:             map[string]bool{},
			observationKeys:      map[string]bool{},
		}
		return accs[ip]
	}

	for _, device := range devices {
		acc := ensure(device.IP)
		if acc == nil {
			continue
		}
		acc.profile.Label = firstNonEmpty(device.FamilyCandidate, device.VendorCandidate, device.CategoryCandidate)
		acc.profile.Category = device.CategoryCandidate
		acc.profile.CategoryConfidence = device.CategoryConfidence
		acc.profile.Vendor = device.VendorCandidate
		acc.profile.VendorConfidence = device.VendorConfidence
		acc.profile.Family = device.FamilyCandidate
		acc.profile.FamilyConfidence = device.FamilyConfidence
		acc.profile.FirstSeen = device.FirstSeen
		acc.profile.LastSeen = device.LastSeen
		for _, protocol := range device.ObservedProtocols {
			addString(acc.protocols, protocol)
		}
		for _, port := range device.ObservedPorts {
			addPort(acc.ports, port)
		}
		for _, host := range device.ObservedHosts {
			addString(acc.httpHosts, host)
		}
		for _, sni := range device.ObservedSNI {
			addString(acc.tlsSNI, sni)
		}
	}

	for _, event := range events {
		for _, ip := range eventEvidenceIPs(event, devices) {
			acc := ensure(ip)
			if acc == nil {
				continue
			}
			key := eventDedupKey(event)
			if acc.eventKeys[key] {
				continue
			}
			acc.eventKeys[key] = true
			acc.profile.EventCount++
			observeEvidenceBounds(&acc.profile, event.Timestamp)
			if !event.Debug {
				addRiskSignal(acc, event)
			}
		}
	}

	for _, flow := range flows {
		for _, ip := range flowEvidenceIPs(flow, devices) {
			acc := ensure(ip)
			if acc == nil {
				continue
			}
			key := flowDedupKey(flow)
			if acc.flowKeys[key] {
				continue
			}
			acc.flowKeys[key] = true
			acc.profile.FlowCount++
			observeEvidenceBounds(&acc.profile, flow.Timestamp)
			applyFlowEvidence(acc, flow, ip)
		}
	}

	for _, observation := range observations {
		for _, ip := range observationEvidenceIPs(observation, devices) {
			acc := ensure(ip)
			if acc == nil {
				continue
			}
			key := observationEvidenceKey(observation)
			if acc.observationKeys[key] {
				continue
			}
			acc.observationKeys[key] = true
			acc.profile.ObservationCount++
			observeEvidenceBounds(&acc.profile, observation.Timestamp)
			applyObservationEvidence(acc, observation, ip)
		}
	}

	out := DeviceEvidenceReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Devices:     []DeviceEvidenceProfile{},
	}
	var first, last time.Time
	for _, acc := range accs {
		finalizeEvidenceProfile(acc)
		if acc.profile.IP == "" {
			continue
		}
		if t, ok := parseRFC3339(acc.profile.FirstSeen); ok && (first.IsZero() || t.Before(first)) {
			first = t
		}
		if t, ok := parseRFC3339(acc.profile.LastSeen); ok && t.After(last) {
			last = t
		}
		if len(acc.profile.RiskSignals) > 0 {
			out.Metrics.DevicesWithRisk++
		}
		if len(acc.profile.PassiveBlindSpots) > 0 {
			out.Metrics.DevicesWithBlindSpot++
		}
		switch acc.profile.Judgment.State {
		case "normal":
			out.Metrics.JudgedNormal++
		case "suspicious":
			out.Metrics.JudgedSuspicious++
		case "risky":
			out.Metrics.JudgedRisky++
		default:
			out.Metrics.JudgedUnknown++
		}
		out.Metrics.DefenseCandidateCount += len(acc.profile.DefenseCandidates)
		out.Devices = append(out.Devices, acc.profile)
	}
	sort.SliceStable(out.Devices, func(i, j int) bool {
		if len(out.Devices[i].RiskSignals) == len(out.Devices[j].RiskSignals) {
			return out.Devices[i].IP < out.Devices[j].IP
		}
		return len(out.Devices[i].RiskSignals) > len(out.Devices[j].RiskSignals)
	})
	out.Metrics.DeviceCount = len(out.Devices)
	if !first.IsZero() {
		out.Window.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		out.Window.End = last.UTC().Format(time.RFC3339)
	}
	return out
}

func applyFlowEvidence(acc *deviceEvidenceAccumulator, flow FlowRecord, deviceIP string) {
	addString(acc.protocols, flow.Protocol)
	addString(acc.protocols, flow.AppProtocol)
	addPort(acc.ports, flow.SrcPort)
	addPort(acc.ports, flow.DstPort)
	addString(acc.httpHosts, flow.Host)
	addString(acc.tlsSNI, flow.SNI)
	if flow.HTTPMethod != "" || flow.HTTPPath != "" {
		addString(acc.httpRequests, strings.TrimSpace(flow.HTTPMethod+" "+flow.HTTPPath))
	}
	destination := normalizedProtectionDestination(flow)
	if destination == "" {
		destination = flow.DstIP
	}
	if strings.TrimSpace(flow.SrcIP) == deviceIP {
		if classifyProtectionFlow(flow) == protectionFlowExternal {
			addString(acc.externalDestinations, destination)
		} else if destination != "" {
			addString(acc.localDestinations, destination)
		}
	}
	if isDiscoveryProtocol(flow.AppProtocol) {
		addString(acc.discoveryProtocols, flow.AppProtocol)
	}
}

func applyObservationEvidence(acc *deviceEvidenceAccumulator, observation ObservationRecord, deviceIP string) {
	addString(acc.protocols, observation.Protocol)
	addString(acc.protocols, observation.AppProtocol)
	addPort(acc.ports, observation.SrcPort)
	addPort(acc.ports, observation.DstPort)
	addString(acc.dnsQueries, observation.DNSQuery)
	addString(acc.httpHosts, observation.Host)
	addString(acc.tlsSNI, observation.SNI)
	if observation.HTTPMethod != "" || observation.HTTPPath != "" {
		addString(acc.httpRequests, strings.TrimSpace(observation.HTTPMethod+" "+observation.HTTPPath))
	}
	if isDiscoveryProtocol(observation.AppProtocol) || observation.Kind == "ssdp_discovery" || observation.Kind == "mdns_query" {
		addString(acc.discoveryProtocols, firstNonEmpty(observation.AppProtocol, observation.Kind))
	}
	if strings.TrimSpace(observation.SrcIP) == deviceIP {
		destination := normalizedObservationDestination(observation)
		if isObservationExternal(observation) {
			addString(acc.externalDestinations, destination)
		} else {
			addString(acc.localDestinations, destination)
		}
		if strings.EqualFold(observation.Protocol, "udp") && strings.TrimSpace(observation.AppProtocol) == "" && observation.DstPort != 0 {
			addPort(acc.unknownUDPPorts, observation.DstPort)
		}
	}
}

func addRiskSignal(acc *deviceEvidenceAccumulator, event Event) {
	rule := canonicalRuleID(event)
	if rule == "" {
		return
	}
	signal := acc.riskSignals[rule]
	if signal == nil {
		signal = &riskSignalAccumulator{ruleID: rule, evidence: map[string]bool{}}
		acc.riskSignals[rule] = signal
	}
	signal.count++
	if severityRank(event.Severity) > severityRank(signal.severity) {
		signal.severity = event.Severity
	}
	if signal.confidence == "" || confidenceRank(event.Confidence) > confidenceRank(signal.confidence) {
		signal.confidence = event.Confidence
	}
	if signal.observedFact == "" {
		signal.observedFact = event.ObservedFact
	}
	if signal.inference == "" {
		signal.inference = event.Inference
	}
	if signal.limitation == "" {
		signal.limitation = event.Limitation
	}
	if signal.recommendation == "" {
		signal.recommendation = event.Recommendation
	}
	if evidence := strings.TrimSpace(event.Evidence); evidence != "" {
		signal.evidence[evidence] = true
	}
	if !event.Timestamp.IsZero() {
		if signal.first.IsZero() || event.Timestamp.Before(signal.first) {
			signal.first = event.Timestamp
		}
		if event.Timestamp.After(signal.last) {
			signal.last = event.Timestamp
		}
	}
}

func finalizeEvidenceProfile(acc *deviceEvidenceAccumulator) {
	acc.profile.ObservedEvidence = DeviceObservedEvidence{
		Protocols:            sortedStringSet(acc.protocols),
		Ports:                sortedPortSet(acc.ports),
		DNSQueries:           sortedStringSet(acc.dnsQueries),
		TLSSNI:               sortedStringSet(acc.tlsSNI),
		HTTPHosts:            sortedStringSet(acc.httpHosts),
		HTTPRequests:         sortedStringSet(acc.httpRequests),
		ExternalDestinations: sortedStringSet(acc.externalDestinations),
		LocalDestinations:    sortedStringSet(acc.localDestinations),
		DiscoveryProtocols:   sortedStringSet(acc.discoveryProtocols),
		UnknownUDPPorts:      sortedPortSet(acc.unknownUDPPorts),
	}
	acc.profile.RiskSignals = sortedRiskSignals(acc.riskSignals)
	acc.profile.InferredFacts = buildInferredFacts(acc.profile)
	acc.profile.PassiveBlindSpots = buildPassiveBlindSpots(acc.profile)
	acc.profile.DefenseCandidates = buildDefenseCandidates(acc.profile)
	acc.profile.Judgment = BuildDeviceJudgment(acc.profile)
}

func buildInferredFacts(profile DeviceEvidenceProfile) []EvidenceFinding {
	var out []EvidenceFinding
	if profile.Category != "" {
		out = append(out, EvidenceFinding{
			Key:        "category_candidate",
			Label:      "Device category candidate",
			Detail:     profile.Category,
			Confidence: profile.CategoryConfidence,
			Source:     "device_inventory",
		})
	}
	if profile.Vendor != "" {
		out = append(out, EvidenceFinding{
			Key:        "vendor_candidate",
			Label:      "Vendor candidate",
			Detail:     profile.Vendor,
			Confidence: profile.VendorConfidence,
			Source:     "device_inventory",
		})
	}
	if profile.Family != "" {
		out = append(out, EvidenceFinding{
			Key:        "family_candidate",
			Label:      "Device family candidate",
			Detail:     profile.Family,
			Confidence: profile.FamilyConfidence,
			Source:     "device_inventory",
		})
	}
	if len(profile.ObservedEvidence.ExternalDestinations) > 0 {
		out = append(out, EvidenceFinding{
			Key:        "cloud_dependency",
			Label:      "External service dependency observed",
			Detail:     strings.Join(limitEvidenceStrings(profile.ObservedEvidence.ExternalDestinations, 3), ", "),
			Confidence: "medium",
			Source:     "flows/observations",
		})
	}
	if len(profile.ObservedEvidence.DiscoveryProtocols) > 0 {
		out = append(out, EvidenceFinding{
			Key:        "local_discovery",
			Label:      "Local discovery behavior observed",
			Detail:     strings.Join(profile.ObservedEvidence.DiscoveryProtocols, ", "),
			Confidence: "high",
			Source:     "observations",
		})
	}
	return out
}

func buildPassiveBlindSpots(profile DeviceEvidenceProfile) []EvidenceFinding {
	out := []EvidenceFinding{{
		Key:    "firmware_internals_not_visible",
		Label:  "Firmware internals are not visible",
		Detail: "Passive network observation cannot inspect firmware code, local storage, or device-internal state.",
		Source: "passive_limit",
	}}
	if hasAny(profile.ObservedEvidence.TLSSNI) || containsEvidenceString(profile.ObservedEvidence.Protocols, "tls") || containsEvidenceString(profile.ObservedEvidence.Protocols, "https") {
		out = append(out, EvidenceFinding{
			Key:    "encrypted_payload_not_visible",
			Label:  "Encrypted payload is not visible",
			Detail: "TLS metadata can expose SNI, certificate, versions, or ciphers, but not HTTPS application payloads.",
			Source: "passive_limit",
		})
	}
	if len(profile.ObservedEvidence.UnknownUDPPorts) > 0 {
		out = append(out, EvidenceFinding{
			Key:    "unknown_udp_purpose",
			Label:  "Unknown UDP purpose",
			Detail: "UDP ports " + joinPorts(profile.ObservedEvidence.UnknownUDPPorts) + " were observed without a decoded application protocol.",
			Source: "observations",
		})
	}
	if len(profile.RiskSignals) > 0 {
		out = append(out, EvidenceFinding{
			Key:    "exploit_success_not_proven",
			Label:  "Exploit success is not proven",
			Detail: "Observed risk signals show exposure or weak behavior, but passive monitoring cannot prove compromise by itself.",
			Source: "passive_limit",
		})
	}
	return out
}

func buildDefenseCandidates(profile DeviceEvidenceProfile) []EvidenceFinding {
	seen := map[string]EvidenceFinding{}
	add := func(item EvidenceFinding) {
		if item.Key == "" {
			return
		}
		seen[item.Key] = item
	}
	if len(profile.ObservedEvidence.ExternalDestinations) > 0 {
		add(EvidenceFinding{
			Key:        "review_outbound_allowlist",
			Label:      "Review outbound allowlist",
			Detail:     "Review whether the device only needs the observed external destinations before enforcing allowlist-style rules.",
			Confidence: "medium",
			Source:     "flows/observations",
		})
	}
	if hasRisk(profile, "I7_HTTP_PLAINTEXT") || hasRisk(profile, "I7_HTTP_AUTH") || hasRisk(profile, "I7_HTTP_BODY_SECRET") || hasRisk(profile, "I7_HTTP_TOKEN") {
		add(EvidenceFinding{
			Key:        "restrict_plaintext_http",
			Label:      "Restrict plaintext HTTP",
			Detail:     "Prefer HTTPS where supported, and consider blocking nonessential outbound HTTP after checking device functionality.",
			Confidence: "high",
			Source:     "risk_signals",
		})
	}
	if hasRiskPrefix(profile, "I2_") || containsPort(profile.ObservedEvidence.Ports, 23) || containsPort(profile.ObservedEvidence.Ports, 21) {
		add(EvidenceFinding{
			Key:        "block_insecure_management",
			Label:      "Block insecure management paths",
			Detail:     "Keep Telnet/FTP/legacy management traffic away from untrusted networks and isolate the device if possible.",
			Confidence: "high",
			Source:     "risk_signals",
		})
	}
	if len(profile.RiskSignals) > 0 {
		add(EvidenceFinding{
			Key:        "iot_segment_review",
			Label:      "Review IoT segment isolation",
			Detail:     "Keep the device in an IoT segment and limit lateral access to important home assets.",
			Confidence: "medium",
			Source:     "risk_signals",
		})
	}
	out := make([]EvidenceFinding, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func eventEvidenceIPs(event Event, devices []InventoryDevice) []string {
	return uniqueSortedStrings([]string{event.DeviceKey, event.SrcIP, event.DstIP})
}

func flowEvidenceIPs(flow FlowRecord, devices []InventoryDevice) []string {
	return uniqueSortedStrings([]string{flow.SrcIP, flow.DstIP})
}

func observationEvidenceIPs(observation ObservationRecord, devices []InventoryDevice) []string {
	return uniqueSortedStrings([]string{observation.SrcIP, observation.DstIP})
}

func isEvidenceDeviceIP(ip string, devices []InventoryDevice) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	return isLocalDeviceIP(ip)
}

func observationEvidenceKey(observation ObservationRecord) string {
	parts := []string{
		observation.Timestamp.UTC().Format(time.RFC3339Nano),
		observation.Kind,
		observation.SrcIP,
		itoaUint16(observation.SrcPort),
		observation.DstIP,
		itoaUint16(observation.DstPort),
		observation.Protocol,
		observation.AppProtocol,
		observation.DNSQuery,
		observation.SNI,
		observation.Host,
	}
	return strings.Join(parts, "|")
}

func observeEvidenceBounds(profile *DeviceEvidenceProfile, ts time.Time) {
	if profile == nil || ts.IsZero() {
		return
	}
	value := ts.UTC().Format(time.RFC3339)
	if profile.FirstSeen == "" || earlierTime(value, profile.FirstSeen) {
		profile.FirstSeen = value
	}
	if profile.LastSeen == "" || laterTime(value, profile.LastSeen) {
		profile.LastSeen = value
	}
}

func sortedRiskSignals(items map[string]*riskSignalAccumulator) []DeviceRiskSignal {
	out := make([]DeviceRiskSignal, 0, len(items))
	for _, item := range items {
		if item == nil || item.ruleID == "" {
			continue
		}
		signal := DeviceRiskSignal{
			RuleID:         item.ruleID,
			Severity:       item.severity,
			Confidence:     item.confidence,
			Count:          item.count,
			ObservedFact:   item.observedFact,
			Inference:      item.inference,
			Limitation:     item.limitation,
			Recommendation: item.recommendation,
			Evidence:       sortedStringSet(item.evidence),
		}
		if !item.first.IsZero() {
			signal.FirstSeen = item.first.UTC().Format(time.RFC3339)
		}
		if !item.last.IsZero() {
			signal.LastSeen = item.last.UTC().Format(time.RFC3339)
		}
		out = append(out, signal)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if severityRank(out[i].Severity) == severityRank(out[j].Severity) {
			return out[i].RuleID < out[j].RuleID
		}
		return severityRank(out[i].Severity) > severityRank(out[j].Severity)
	})
	return out
}

func addString(set map[string]bool, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		set[value] = true
	}
}

func addPort(set map[uint16]bool, value uint16) {
	if value != 0 {
		set[value] = true
	}
}

func confidenceRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strong":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "very_low":
		return 1
	default:
		return 0
	}
}

func isDiscoveryProtocol(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "mdns", "ssdp", "dhcp", "llmnr", "nbns":
		return true
	default:
		return false
	}
}

func hasAny(values []string) bool {
	return len(values) > 0
}

func hasRisk(profile DeviceEvidenceProfile, ruleID string) bool {
	for _, signal := range profile.RiskSignals {
		if signal.RuleID == ruleID {
			return true
		}
	}
	return false
}

func hasRiskPrefix(profile DeviceEvidenceProfile, prefix string) bool {
	for _, signal := range profile.RiskSignals {
		if strings.HasPrefix(signal.RuleID, prefix) {
			return true
		}
	}
	return false
}

func containsPort(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func joinPorts(values []uint16) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, itoaUint16(value))
	}
	return strings.Join(parts, ", ")
}

func limitEvidenceStrings(values []string, limit int) []string {
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return values[:limit]
}

func containsEvidenceString(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.ToLower(strings.TrimSpace(value)) == target {
			return true
		}
	}
	return false
}
