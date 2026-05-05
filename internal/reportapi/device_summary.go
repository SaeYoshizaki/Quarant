package reportapi

import (
	"sort"
	"strings"
	"time"
)

func canonicalRuleID(event Event) string {
	if strings.TrimSpace(event.RuleID) != "" {
		return strings.TrimSpace(event.RuleID)
	}
	return strings.TrimSpace(event.Type)
}

func eventDedupKey(event Event) string {
	parts := []string{
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		canonicalRuleID(event),
		strings.TrimSpace(event.FlowKey),
		strings.TrimSpace(event.DeviceKey),
		strings.TrimSpace(event.SrcIP),
		strings.TrimSpace(event.DstIP),
		itoaUint16(event.SrcPort),
		itoaUint16(event.DstPort),
	}
	return strings.Join(parts, "|")
}

func flowDedupKey(flow FlowRecord) string {
	parts := []string{
		flow.Timestamp.UTC().Format(time.RFC3339Nano),
		strings.TrimSpace(flow.FlowKey),
		strings.TrimSpace(flow.SrcIP),
		strings.TrimSpace(flow.DstIP),
		itoaUint16(flow.SrcPort),
		itoaUint16(flow.DstPort),
		strings.TrimSpace(flow.Protocol),
		strings.TrimSpace(flow.AppProtocol),
	}
	return strings.Join(parts, "|")
}

func deviceMatchesEvent(ip string, event Event) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	return strings.TrimSpace(event.DeviceKey) == ip ||
		strings.TrimSpace(event.SrcIP) == ip ||
		strings.TrimSpace(event.DstIP) == ip
}

func deviceMatchesFlow(ip string, flow FlowRecord) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	return strings.TrimSpace(flow.SrcIP) == ip ||
		strings.TrimSpace(flow.DstIP) == ip ||
		strings.Contains(strings.TrimSpace(flow.FlowKey), ip)
}

func derivedInventoryFromObservations(events []Event, flows []FlowRecord) InventoryReport {
	report := InventoryReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Devices:     []InventoryDevice{},
	}
	devicesByIP := map[string]*InventoryDevice{}
	eventSeen := map[string]map[string]bool{}
	flowSeen := map[string]map[string]bool{}
	flowKeySeen := map[string]map[string]bool{}

	ensureDevice := func(ip string) *InventoryDevice {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			return nil
		}
		if devicesByIP[ip] != nil {
			return devicesByIP[ip]
		}
		devicesByIP[ip] = &InventoryDevice{
			IP:             ip,
			SeverityCounts: map[string]int{},
			OWASPTagCounts: map[string]int{},
		}
		return devicesByIP[ip]
	}

	for _, event := range events {
		seenIPs := map[string]bool{}
		for _, candidate := range []string{event.DeviceKey, event.SrcIP, event.DstIP} {
			ip := strings.TrimSpace(candidate)
			if ip == "" || seenIPs[ip] {
				continue
			}
			seenIPs[ip] = true
			device := ensureDevice(ip)
			if eventSeen[ip] == nil {
				eventSeen[ip] = map[string]bool{}
			}
			key := eventDedupKey(event)
			if eventSeen[ip][key] {
				continue
			}
			eventSeen[ip][key] = true
			applyEventObservation(device, event)
		}
	}

	for _, flow := range flows {
		seenIPs := map[string]bool{}
		for _, candidate := range []string{flow.SrcIP, flow.DstIP} {
			ip := strings.TrimSpace(candidate)
			if ip == "" || seenIPs[ip] {
				continue
			}
			seenIPs[ip] = true
			device := ensureDevice(ip)
			if flowSeen[ip] == nil {
				flowSeen[ip] = map[string]bool{}
			}
			if flowKeySeen[ip] == nil {
				flowKeySeen[ip] = map[string]bool{}
			}
			key := flowDedupKey(flow)
			if flowSeen[ip][key] {
				continue
			}
			flowSeen[ip][key] = true
			applyFlowObservation(device, flow)
			if flowKey := strings.TrimSpace(flow.FlowKey); flowKey != "" && !flowKeySeen[ip][flowKey] {
				flowKeySeen[ip][flowKey] = true
				device.FlowCount++
			}
		}
	}

	for _, device := range devicesByIP {
		finalizeInventoryDevice(device)
		report.Devices = append(report.Devices, *device)
	}
	sortInventoryDevices(report.Devices)
	return report
}

func mergeInventoryWithObserved(base InventoryReport, derived InventoryReport) InventoryReport {
	if base.GeneratedAt == "" {
		base.GeneratedAt = derived.GeneratedAt
	}

	byIP := map[string]*InventoryDevice{}
	for i := range base.Devices {
		normalizeInventoryMaps(&base.Devices[i])
		byIP[base.Devices[i].IP] = &base.Devices[i]
	}

	for _, derivedDevice := range derived.Devices {
		if current := byIP[derivedDevice.IP]; current != nil {
			mergeInventoryDevice(current, derivedDevice)
			continue
		}
		copyDevice := derivedDevice
		base.Devices = append(base.Devices, copyDevice)
		byIP[derivedDevice.IP] = &base.Devices[len(base.Devices)-1]
	}

	sortInventoryDevices(base.Devices)
	return base
}

func mergeInventoryDevice(dst *InventoryDevice, src InventoryDevice) {
	if dst == nil {
		return
	}
	normalizeInventoryMaps(dst)
	if strings.TrimSpace(dst.FirstSeen) == "" || earlierTime(src.FirstSeen, dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if laterTime(src.LastSeen, dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	dst.EventCount = src.EventCount
	dst.FlowCount = src.FlowCount
	dst.ObservedProtocols = uniqueSortedStrings(append(dst.ObservedProtocols, src.ObservedProtocols...))
	dst.ObservedPorts = uniqueSortedPorts(append(dst.ObservedPorts, src.ObservedPorts...))
	dst.ObservedHosts = uniqueSortedStrings(append(dst.ObservedHosts, src.ObservedHosts...))
	dst.ObservedSNI = uniqueSortedStrings(append(dst.ObservedSNI, src.ObservedSNI...))
	dst.RiskEventCount = src.RiskEventCount
	dst.SeverityCounts = cloneStringIntMap(src.SeverityCounts)
	dst.OWASPTagCounts = cloneStringIntMap(src.OWASPTagCounts)
	dst.LastRiskEventType = src.LastRiskEventType
	dst.LastRiskEventTS = src.LastRiskEventTS
	dst.RiskSummary = cloneRiskSummary(src.RiskSummary)
}

func applyEventObservation(device *InventoryDevice, event Event) {
	if device == nil {
		return
	}
	device.EventCount++
	observeTimestampBounds(device, event.Timestamp)
	if event.Debug {
		return
	}
	if severity := strings.TrimSpace(event.Severity); severity != "" {
		device.SeverityCounts[severity]++
	}
	for _, tag := range event.OWASPTags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		device.OWASPTagCounts[tag]++
	}
	device.RiskEventCount++
	device.LastRiskEventType = canonicalRuleID(event)
	device.LastRiskEventTS = event.Timestamp.UTC().Format(time.RFC3339)
}

func applyFlowObservation(device *InventoryDevice, flow FlowRecord) {
	if device == nil {
		return
	}
	observeTimestampBounds(device, flow.Timestamp)
	device.ObservedProtocols = uniqueSortedStrings(append(device.ObservedProtocols, flow.AppProtocol, flow.Protocol))
	device.ObservedPorts = uniqueSortedPorts(append(device.ObservedPorts, flow.SrcPort, flow.DstPort))
	device.ObservedHosts = uniqueSortedStrings(append(device.ObservedHosts, flow.Host))
	device.ObservedSNI = uniqueSortedStrings(append(device.ObservedSNI, flow.SNI))
}

func finalizeInventoryDevice(device *InventoryDevice) {
	if device == nil {
		return
	}
	normalizeInventoryMaps(device)
	device.RiskSummary = buildInventoryRiskSummary(
		device.RiskEventCount,
		device.SeverityCounts,
		device.OWASPTagCounts,
		device.LastRiskEventType,
		device.LastRiskEventTS,
	)
}

func normalizeInventoryMaps(device *InventoryDevice) {
	if device == nil {
		return
	}
	if device.SeverityCounts == nil {
		device.SeverityCounts = map[string]int{}
	}
	if device.OWASPTagCounts == nil {
		device.OWASPTagCounts = map[string]int{}
	}
}

func buildInventoryRiskSummary(riskEventCount int, severityCounts, owaspTagCounts map[string]int, lastRiskEventType, lastRiskEventTS string) *InventoryRiskSummary {
	highestSeverity := highestSeverityLabel(severityCounts)
	if highestSeverity == "" || severityRank(highestSeverity) <= severityRank("INFO") {
		return nil
	}
	return &InventoryRiskSummary{
		RiskEventCount:        riskEventCount,
		HighestSeverity:       highestSeverity,
		TopOWASPTags:          topCountKeysAlphaTie(owaspTagCounts, 5),
		TopSeverities:         topSeverityLabels(severityCounts, 5),
		LastRiskEventType:     strings.TrimSpace(lastRiskEventType),
		LastRiskEventTS:       strings.TrimSpace(lastRiskEventTS),
		RecommendedNextAction: recommendedNextAction(owaspTagCounts),
	}
}

func cloneRiskSummary(summary *InventoryRiskSummary) *InventoryRiskSummary {
	if summary == nil {
		return nil
	}
	copySummary := *summary
	copySummary.TopOWASPTags = append([]string(nil), summary.TopOWASPTags...)
	copySummary.TopSeverities = append([]string(nil), summary.TopSeverities...)
	return &copySummary
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
		return "Review ecosystem interface exposure and account or backend communication paths."
	case has("I6"):
		return "Review privacy-related data exposure, telemetry contents, and external recipients."
	case has("I2"):
		return "Review exposed services and whether remote management is necessary."
	default:
		return "Review observed risk events and confirm whether mitigations are available."
	}
}
