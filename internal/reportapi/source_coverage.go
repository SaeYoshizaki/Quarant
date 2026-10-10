package reportapi

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type EvidenceManifest struct {
	GeneratedAt string                   `json:"generated_at"`
	Version     string                   `json:"version"`
	Sources     []EvidenceManifestSource `json:"sources"`
	Outputs     EvidenceManifestOutputs  `json:"outputs"`
	Metrics     EvidenceManifestMetrics  `json:"metrics"`
}

type EvidenceManifestSource struct {
	Name         string `json:"name"`
	Path         string `json:"path"`
	Events       int    `json:"events"`
	Security     int    `json:"security_events"`
	Flows        int    `json:"flows"`
	Observations int    `json:"observations"`
}

type EvidenceManifestOutputs struct {
	Events               string `json:"events,omitempty"`
	SecurityEvents       string `json:"security_events,omitempty"`
	Flows                string `json:"flows,omitempty"`
	Observations         string `json:"observations,omitempty"`
	AttackEvidenceReport string `json:"attack_evidence_report,omitempty"`
	SourceCoverageReport string `json:"source_coverage_report,omitempty"`
}

type EvidenceManifestMetrics struct {
	SourceCount             int `json:"source_count"`
	EventCount              int `json:"event_count"`
	SecurityEventCount      int `json:"security_event_count"`
	FlowCount               int `json:"flow_count"`
	ObservationCount        int `json:"observation_count"`
	AttackFindingCount      int `json:"attack_finding_count"`
	DedupedEventCount       int `json:"deduped_event_count"`
	DedupedSecurityCount    int `json:"deduped_security_event_count"`
	DedupedFlowCount        int `json:"deduped_flow_count"`
	DedupedObservationCount int `json:"deduped_observation_count"`
}

type SourceCoverageReport struct {
	GeneratedAt     string                  `json:"generated_at"`
	Version         string                  `json:"version"`
	Metrics         SourceCoverageMetrics   `json:"metrics"`
	BySource        []SourceCoverageSource  `json:"by_source"`
	ServiceCoverage []SourceCoverageService `json:"service_coverage"`
	ClaimSupport    []SourceCoverageClaim   `json:"claim_support"`
	Limitations     []string                `json:"limitations"`
}

type SourceCoverageMetrics struct {
	SourceCount              int `json:"source_count"`
	SecurityEventCount       int `json:"security_event_count"`
	FlowCount                int `json:"flow_count"`
	ObservationCount         int `json:"observation_count"`
	OpenWrtOnlyServiceCount  int `json:"openwrt_only_service_count"`
	SuricataOnlyServiceCount int `json:"suricata_only_service_count"`
	ZeekOnlyServiceCount     int `json:"zeek_only_service_count"`
	MultiSourceServiceCount  int `json:"multi_source_service_count"`
	OpenWrtSuricataOverlap   int `json:"openwrt_suricata_overlap_count"`
	OpenWrtZeekOverlap       int `json:"openwrt_zeek_overlap_count"`
	SuricataZeekOverlap      int `json:"suricata_zeek_overlap_count"`
	AllSourceOverlap         int `json:"all_source_overlap_count"`
}

type SourceCoverageSource struct {
	Source       string `json:"source"`
	Security     int    `json:"security_events"`
	Flows        int    `json:"flows"`
	Observations int    `json:"observations"`
	Services     int    `json:"services"`
}

type SourceCoverageService struct {
	Key          string   `json:"key"`
	DeviceIP     string   `json:"device_ip,omitempty"`
	Protocol     string   `json:"protocol,omitempty"`
	Port         uint16   `json:"port,omitempty"`
	Sources      []string `json:"sources"`
	Security     int      `json:"security_events"`
	Flows        int      `json:"flows"`
	Observations int      `json:"observations"`
}

type SourceCoverageClaim struct {
	Claim    string   `json:"claim"`
	Sources  []string `json:"sources"`
	Evidence string   `json:"evidence"`
}

type SourceCoverageInput struct {
	Source       string
	Security     []SecurityEvent
	Flows        []FlowRecord
	Observations []ObservationRecord
}

func BuildSourceCoverageReport(securityEvents []SecurityEvent, flows []FlowRecord, observations []ObservationRecord) SourceCoverageReport {
	return BuildSourceCoverageReportFromInputs([]SourceCoverageInput{{Security: securityEvents, Flows: flows, Observations: observations}})
}

func BuildSourceCoverageReportFromInputs(inputs []SourceCoverageInput) SourceCoverageReport {
	report := SourceCoverageReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "source-coverage-v1",
		Limitations: []string{
			"Coverage overlap is based on normalized device/protocol/port tuples; it does not prove packet-level identity.",
			"Zeek visibility depends on monitored links and protocol parsers.",
			"IDS alerts should be interpreted with rule metadata and human review.",
		},
	}
	sourceStats := map[string]*SourceCoverageSource{}
	services := map[string]*SourceCoverageService{}
	var securityEventCount, flowCount, observationCount int
	for _, input := range inputs {
		inputSource := normalizedInputCoverageSource(input.Source)
		for _, event := range input.Security {
			source := firstNonEmpty(inputSource, normalizedCoverageSource(event.Source, event.Engine))
			stat := ensureCoverageSource(sourceStats, source)
			stat.Security++
			securityEventCount++
			key, device, proto, port := securityCoverageKey(event)
			if key != "" {
				addCoverageService(services, key, device, proto, port, source, "security")
			}
		}
		for _, flow := range input.Flows {
			source := firstNonEmpty(inputSource, normalizedFlowCoverageSource(flow))
			stat := ensureCoverageSource(sourceStats, source)
			stat.Flows++
			flowCount++
			key, device, proto, port := flowCoverageKey(flow)
			if key != "" {
				addCoverageService(services, key, device, proto, port, source, "flow")
			}
		}
		for _, observation := range input.Observations {
			source := firstNonEmpty(inputSource, normalizedObservationCoverageSource(observation))
			stat := ensureCoverageSource(sourceStats, source)
			stat.Observations++
			observationCount++
			key, device, proto, port := observationCoverageKey(observation)
			if key != "" {
				addCoverageService(services, key, device, proto, port, source, "observation")
			}
		}
	}
	for _, service := range services {
		for _, source := range service.Sources {
			ensureCoverageSource(sourceStats, source).Services++
		}
		addCoverageOverlapMetrics(&report.Metrics, service.Sources)
		report.ServiceCoverage = append(report.ServiceCoverage, *service)
	}
	for _, stat := range sourceStats {
		report.BySource = append(report.BySource, *stat)
	}
	sort.SliceStable(report.BySource, func(i, j int) bool { return report.BySource[i].Source < report.BySource[j].Source })
	sort.SliceStable(report.ServiceCoverage, func(i, j int) bool { return report.ServiceCoverage[i].Key < report.ServiceCoverage[j].Key })
	report.Metrics.SourceCount = len(report.BySource)
	report.Metrics.SecurityEventCount = securityEventCount
	report.Metrics.FlowCount = flowCount
	report.Metrics.ObservationCount = observationCount
	report.ClaimSupport = buildSourceCoverageClaims(report)
	return report
}

func ensureCoverageSource(items map[string]*SourceCoverageSource, source string) *SourceCoverageSource {
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	if items[source] == nil {
		items[source] = &SourceCoverageSource{Source: source}
	}
	return items[source]
}

func addCoverageService(items map[string]*SourceCoverageService, key, device, proto string, port uint16, source, kind string) {
	item := items[key]
	if item == nil {
		item = &SourceCoverageService{Key: key, DeviceIP: device, Protocol: proto, Port: port}
		items[key] = item
	}
	switch kind {
	case "security":
		item.Security++
	case "flow":
		item.Flows++
	case "observation":
		item.Observations++
	}
	if !coverageStringSliceContains(item.Sources, source) {
		item.Sources = append(item.Sources, source)
		sort.Strings(item.Sources)
	}
}

func addCoverageOverlapMetrics(metrics *SourceCoverageMetrics, sources []string) {
	hasOpenWrt := coverageStringSliceContains(sources, "openwrt")
	hasSuricata := coverageStringSliceContains(sources, "suricata")
	hasZeek := coverageStringSliceContains(sources, "zeek")
	count := 0
	for _, ok := range []bool{hasOpenWrt, hasSuricata, hasZeek} {
		if ok {
			count++
		}
	}
	if count > 1 {
		metrics.MultiSourceServiceCount++
	}
	if count == 1 {
		switch {
		case hasOpenWrt:
			metrics.OpenWrtOnlyServiceCount++
		case hasSuricata:
			metrics.SuricataOnlyServiceCount++
		case hasZeek:
			metrics.ZeekOnlyServiceCount++
		}
	}
	if hasOpenWrt && hasSuricata {
		metrics.OpenWrtSuricataOverlap++
	}
	if hasOpenWrt && hasZeek {
		metrics.OpenWrtZeekOverlap++
	}
	if hasSuricata && hasZeek {
		metrics.SuricataZeekOverlap++
	}
	if hasOpenWrt && hasSuricata && hasZeek {
		metrics.AllSourceOverlap++
	}
}

func buildSourceCoverageClaims(report SourceCoverageReport) []SourceCoverageClaim {
	claims := []SourceCoverageClaim{}
	if report.Metrics.OpenWrtSuricataOverlap > 0 {
		claims = append(claims, SourceCoverageClaim{Claim: "router-boundary exposure has IDS corroboration", Sources: []string{"openwrt", "suricata"}, Evidence: "OpenWrt and Suricata observed the same device/protocol/port tuple."})
	}
	if report.Metrics.OpenWrtZeekOverlap > 0 {
		claims = append(claims, SourceCoverageClaim{Claim: "router-boundary evidence can be compared with passive NSM behavior", Sources: []string{"openwrt", "zeek"}, Evidence: "OpenWrt and Zeek observed the same device/protocol/port tuple."})
	}
	if report.Metrics.SuricataZeekOverlap > 0 {
		claims = append(claims, SourceCoverageClaim{Claim: "IDS alerts have passive flow context", Sources: []string{"suricata", "zeek"}, Evidence: "Suricata and Zeek observed the same device/protocol/port tuple."})
	}
	if len(claims) == 0 {
		claims = append(claims, SourceCoverageClaim{Claim: "sensor evidence was assembled", Sources: sourceCoverageSourceNames(report.BySource), Evidence: "No cross-source service overlap was detected in the current window."})
	}
	return claims
}

func sourceCoverageSourceNames(items []SourceCoverageSource) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Source)
	}
	sort.Strings(out)
	return out
}

func normalizedCoverageSource(source, engine string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	engine = strings.ToLower(strings.TrimSpace(engine))
	switch {
	case strings.Contains(source, "openwrt"):
		return "openwrt"
	case strings.Contains(source, "suricata") || strings.Contains(engine, "suricata"):
		return "suricata"
	case strings.Contains(source, "snort") || strings.Contains(engine, "snort"):
		return "snort"
	case strings.Contains(source, "zeek"):
		return "zeek"
	default:
		return firstNonEmpty(source, engine, "unknown")
	}
}

func normalizedInputCoverageSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(source, "openwrt"):
		return "openwrt"
	case strings.Contains(source, "suricata"):
		return "suricata"
	case strings.Contains(source, "zeek"):
		return "zeek"
	case strings.Contains(source, "snort"):
		return "snort"
	default:
		return source
	}
}

func normalizedFlowCoverageSource(flow FlowRecord) string {
	key := strings.ToLower(strings.TrimSpace(flow.FlowKey))
	app := strings.ToLower(strings.TrimSpace(flow.AppProtocol))
	switch {
	case strings.HasPrefix(key, "c") || strings.HasPrefix(key, "d") || strings.HasPrefix(key, "h") || strings.HasPrefix(key, "s"):
		return "zeek"
	case strings.HasPrefix(key, "sensor_"):
		return "suricata"
	case app == "dns" || app == "http" || app == "tls" || app == "ssl":
		return "zeek"
	default:
		return "flow"
	}
}

func normalizedObservationCoverageSource(observation ObservationRecord) string {
	kind := strings.ToLower(strings.TrimSpace(observation.Kind))
	flowKey := strings.ToLower(strings.TrimSpace(observation.FlowKey))
	switch {
	case strings.HasPrefix(kind, "suricata_") || strings.HasPrefix(flowKey, "sensor_"):
		return "suricata"
	case strings.HasPrefix(kind, "zeek_") || kind == "dns_query" || kind == "http_request" || kind == "tls_sni":
		return "zeek"
	default:
		return "observation"
	}
}

func securityCoverageKey(event SecurityEvent) (string, string, string, uint16) {
	device := strings.TrimSpace(firstNonEmpty(event.DeviceIP, event.DstIP, event.SrcIP))
	proto := strings.ToLower(strings.TrimSpace(event.Protocol))
	port := event.DstPort
	return coverageKey(device, proto, port), device, proto, port
}

func flowCoverageKey(flow FlowRecord) (string, string, string, uint16) {
	device := strings.TrimSpace(firstNonEmpty(flow.SrcIP, flow.DstIP))
	if !isEvidencePrivateIP(device) && isEvidencePrivateIP(flow.DstIP) {
		device = flow.DstIP
	}
	proto := strings.ToLower(strings.TrimSpace(flow.Protocol))
	port := flow.DstPort
	return coverageKey(device, proto, port), device, proto, port
}

func observationCoverageKey(observation ObservationRecord) (string, string, string, uint16) {
	device := strings.TrimSpace(firstNonEmpty(observation.SrcIP, observation.DstIP))
	if !isEvidencePrivateIP(device) && isEvidencePrivateIP(observation.DstIP) {
		device = observation.DstIP
	}
	proto := strings.ToLower(strings.TrimSpace(observation.Protocol))
	port := observation.DstPort
	return coverageKey(device, proto, port), device, proto, port
}

func coverageKey(device, proto string, port uint16) string {
	device = strings.TrimSpace(device)
	proto = strings.ToLower(strings.TrimSpace(proto))
	if device == "" || proto == "" || port == 0 {
		return ""
	}
	return strings.Join([]string{device, proto, uint16String(port)}, "|")
}

func uint16String(value uint16) string {
	return strconv.Itoa(int(value))
}

func isEvidencePrivateIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.IsPrivate()
}

func coverageStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
