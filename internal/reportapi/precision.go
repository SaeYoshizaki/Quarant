package reportapi

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	precisionRiskyScoreThreshold      = 65
	precisionSuspiciousScoreThreshold = 30
	precisionHighSeverityThreshold    = 75
	precisionMediumSeverityThreshold  = 50
	precisionWarningSeverityThreshold = 30
	precisionHighConfidenceThreshold  = 50
	precisionMinIncidentScore         = 14
)

type DetectionPrecisionReport struct {
	GeneratedAt          string                        `json:"generated_at"`
	Source               PrecisionSources              `json:"source"`
	Window               Window                        `json:"window"`
	Metrics              PrecisionMetrics              `json:"metrics"`
	DecisionPolicy       PrecisionDecisionPolicy       `json:"decision_policy"`
	DecisionBreakdown    PrecisionDecisionBreakdown    `json:"decision_breakdown"`
	SuppressionBreakdown PrecisionSuppressionBreakdown `json:"suppression_breakdown"`
	ScoreDistribution    []PrecisionScoreBucket        `json:"score_distribution"`
	EvaluationReadiness  PrecisionEvaluationReadiness  `json:"evaluation_readiness"`
	PaperSummary         PrecisionPaperSummary         `json:"paper_summary"`
	Layers               PrecisionLayerBreakdown       `json:"layers"`
	Baseline             BehaviorBaseline              `json:"baseline"`
	Incidents            []PrecisionIncident           `json:"incidents"`
	SuppressedSignals    []SuppressedSignalSummary     `json:"suppressed_signals"`
	Recommendations      []string                      `json:"recommendations"`
	Limitations          []string                      `json:"limitations"`
}

type PrecisionSources struct {
	Events         string `json:"events,omitempty"`
	SecurityEvents string `json:"security_events,omitempty"`
	Flows          string `json:"flows,omitempty"`
	Observations   string `json:"observations,omitempty"`
	Inventory      string `json:"inventory,omitempty"`
}

type PrecisionMetrics struct {
	DeviceCount              int  `json:"device_count"`
	IncidentCount            int  `json:"incident_count"`
	RiskyIncidentCount       int  `json:"risky_incident_count"`
	SuspiciousIncidentCount  int  `json:"suspicious_incident_count"`
	ObserveIncidentCount     int  `json:"observe_incident_count"`
	HighSeverityCount        int  `json:"high_severity_count"`
	MediumSeverityCount      int  `json:"medium_severity_count"`
	WarningSeverityCount     int  `json:"warning_severity_count"`
	HighConfidenceCount      int  `json:"high_confidence_count"`
	MediumConfidenceCount    int  `json:"medium_confidence_count"`
	AttackLikeIncidentCount  int  `json:"attack_like_incident_count"`
	SuppressedSignalCount    int  `json:"suppressed_signal_count"`
	BaselineReadyDeviceCount int  `json:"baseline_ready_device_count"`
	NovelSignalCount         int  `json:"novel_signal_count"`
	CategoryDeviationCount   int  `json:"category_deviation_count"`
	SignalTaxonomies         []KV `json:"signal_taxonomies,omitempty"`
}

type PrecisionDecisionPolicy struct {
	Version            string                       `json:"version"`
	IncidentModel      string                       `json:"incident_model"`
	StateThresholds    []PrecisionThreshold         `json:"state_thresholds"`
	SeverityThresholds []PrecisionThreshold         `json:"severity_thresholds"`
	ConfidencePolicy   []PrecisionThreshold         `json:"confidence_policy"`
	SignalTaxonomy     []PrecisionTaxonomyPolicy    `json:"signal_taxonomy"`
	SuppressionPolicy  []PrecisionSuppressionPolicy `json:"suppression_policy"`
	Limitations        []string                     `json:"limitations"`
}

type PrecisionThreshold struct {
	Name        string `json:"name"`
	Condition   string `json:"condition"`
	Description string `json:"description"`
}

type PrecisionTaxonomyPolicy struct {
	Key         string `json:"key"`
	Layer       string `json:"layer"`
	Description string `json:"description"`
}

type PrecisionSuppressionPolicy struct {
	Key         string `json:"key"`
	Layer       string `json:"layer"`
	Description string `json:"description"`
}

type PrecisionDecisionBreakdown struct {
	ByState      []KV `json:"by_state"`
	BySeverity   []KV `json:"by_severity"`
	ByConfidence []KV `json:"by_confidence"`
	ByTaxonomy   []KV `json:"by_taxonomy"`
	ByLayer      []KV `json:"by_layer"`
	ByScoreBand  []KV `json:"by_score_band"`
}

type PrecisionSuppressionBreakdown struct {
	TotalSuppressed int                    `json:"total_suppressed"`
	ByReason        []SuppressionBreakdown `json:"by_reason"`
	ByLayer         []KV                   `json:"by_layer"`
	PromotionRatio  float64                `json:"promotion_ratio"`
	Summary         string                 `json:"summary"`
}

type SuppressionBreakdown struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Layer  string `json:"layer"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

type PrecisionScoreBucket struct {
	Band        string `json:"band"`
	MinScore    int    `json:"min_score"`
	MaxScore    int    `json:"max_score"`
	Count       int    `json:"count"`
	Description string `json:"description"`
}

type PrecisionEvaluationReadiness struct {
	ReadyForPrecisionEval bool     `json:"ready_for_precision_eval"`
	ReadyForRecallEval    bool     `json:"ready_for_recall_eval"`
	IncidentLabelCount    int      `json:"incident_label_count"`
	RequiredLabelCount    int      `json:"required_label_count"`
	RequiredLabels        []string `json:"required_labels"`
	LabelTemplateFields   []string `json:"label_template_fields"`
	RecommendedProtocol   []string `json:"recommended_protocol"`
	BlockingIssues        []string `json:"blocking_issues,omitempty"`
}

type PrecisionPaperSummary struct {
	ObservationWindow       Window   `json:"observation_window"`
	DeviceCount             int      `json:"device_count"`
	IncidentCount           int      `json:"incident_count"`
	RiskyIncidentCount      int      `json:"risky_incident_count"`
	SuspiciousIncidentCount int      `json:"suspicious_incident_count"`
	ObserveIncidentCount    int      `json:"observe_incident_count"`
	SuppressedSignalCount   int      `json:"suppressed_signal_count"`
	TopTaxonomies           []KV     `json:"top_taxonomies"`
	TopSuppressionReasons   []KV     `json:"top_suppression_reasons"`
	ResearchClaimsSupported []string `json:"research_claims_supported"`
	ResearchClaimsMissing   []string `json:"research_claims_missing"`
}

type PrecisionLayerBreakdown struct {
	Observation PrecisionLayerSummary `json:"observation"`
	Context     PrecisionLayerSummary `json:"context"`
	Correlation PrecisionLayerSummary `json:"correlation"`
}

type PrecisionLayerSummary struct {
	Key             string `json:"key"`
	Label           string `json:"label"`
	SignalCount     int    `json:"signal_count"`
	SuppressedCount int    `json:"suppressed_count"`
	IncidentCount   int    `json:"incident_count"`
	Summary         string `json:"summary"`
}

type PrecisionIncident struct {
	ID                string            `json:"id"`
	State             string            `json:"state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	Score             int               `json:"score"`
	ScoreBand         string            `json:"score_band"`
	PrimaryTaxonomy   string            `json:"primary_taxonomy,omitempty"`
	Taxonomies        []string          `json:"taxonomies,omitempty"`
	DeviceIP          string            `json:"device_ip"`
	DeviceLabel       string            `json:"device_label,omitempty"`
	Category          string            `json:"category,omitempty"`
	Title             string            `json:"title"`
	Summary           string            `json:"summary"`
	FirstSeen         string            `json:"first_seen,omitempty"`
	LastSeen          string            `json:"last_seen,omitempty"`
	Signals           []PrecisionSignal `json:"signals"`
	Decision          PrecisionDecision `json:"decision"`
	Evidence          []string          `json:"evidence,omitempty"`
	RecommendedAction string            `json:"recommended_action,omitempty"`
}

type PrecisionSignal struct {
	Key        string `json:"key"`
	Layer      string `json:"layer,omitempty"`
	Taxonomy   string `json:"taxonomy,omitempty"`
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Weight     int    `json:"weight"`
	Confidence string `json:"confidence,omitempty"`
	Source     string `json:"source,omitempty"`
}

type PrecisionDecision struct {
	StateReason      string   `json:"state_reason"`
	SeverityReason   string   `json:"severity_reason"`
	ConfidenceReason string   `json:"confidence_reason"`
	PromotedBy       []string `json:"promoted_by,omitempty"`
	SuppressedBy     []string `json:"suppressed_by,omitempty"`
}

type SuppressedSignalSummary struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Count  int    `json:"count"`
	Reason string `json:"reason"`
}

type precisionIncidentBuilder struct {
	deviceIP    string
	deviceLabel string
	category    string
	score       int
	first       time.Time
	last        time.Time
	signals     map[string]PrecisionSignal
	evidence    map[string]bool
}

type precisionSuppressionCounter struct {
	label  string
	reason string
	count  int
}

type precisionDeviceContext struct {
	ip                            string
	label                         string
	category                      string
	baseline                      *DeviceBehaviorProfile
	externalFlowCount             int
	dnsOnlyCount                  int
	unknownUDPPorts               map[uint16]bool
	inboundBlockCount             int
	inboundBlockSources           map[string]bool
	inboundBlockPorts             map[uint16]bool
	attackEvidenceCount           int
	attackEvidenceBlocked         int
	attackEvidenceAccepted        int
	attackEvidenceExposed         int
	attackEvidenceSources         map[string]bool
	attackEvidencePorts           map[uint16]bool
	attackEvidenceTechniques      map[string]bool
	attackEvidenceTaxonomies      map[string]bool
	attackEvidenceSweepSources    map[string]bool
	attackEvidenceSensitivePorts  map[uint16]bool
	attackEvidenceSuspiciousFlags int
	first                         time.Time
	last                          time.Time
}

func LoadDetectionPrecisionReport(eventsPath, flowsPath, observationsPath, inventoryPath string) (DetectionPrecisionReport, error) {
	return LoadDetectionPrecisionReportWithSecurityEvents(eventsPath, "", flowsPath, observationsPath, inventoryPath)
}

func LoadDetectionPrecisionReportWithSecurityEvents(eventsPath, securityEventsPath, flowsPath, observationsPath, inventoryPath string) (DetectionPrecisionReport, error) {
	report, err := LoadReport(eventsPath)
	if err != nil {
		return DetectionPrecisionReport{}, err
	}
	securityEvents, err := LoadSecurityEvents(securityEventsPath)
	if err != nil {
		return DetectionPrecisionReport{}, err
	}
	flows, err := LoadFlows(flowsPath)
	if err != nil {
		return DetectionPrecisionReport{}, err
	}
	observations, err := LoadObservations(observationsPath)
	if err != nil {
		return DetectionPrecisionReport{}, err
	}
	inventory, err := LoadInventoryWithFallback(inventoryPath, eventsPath, flowsPath)
	if err != nil {
		return DetectionPrecisionReport{}, err
	}
	out := BuildDetectionPrecisionReportWithSecurityEvents(report.Events, securityEvents, flows, observations, inventory.Devices)
	out.Source = PrecisionSources{
		Events:         eventsPath,
		SecurityEvents: securityEventsPath,
		Flows:          flowsPath,
		Observations:   observationsPath,
		Inventory:      inventoryPath,
	}
	return out, nil
}

func BuildDetectionPrecisionReport(events []Event, flows []FlowRecord, observations []ObservationRecord, devices []InventoryDevice) DetectionPrecisionReport {
	return BuildDetectionPrecisionReportWithSecurityEvents(events, nil, flows, observations, devices)
}

func BuildDetectionPrecisionReportWithSecurityEvents(events []Event, securityEvents []SecurityEvent, flows []FlowRecord, observations []ObservationRecord, devices []InventoryDevice) DetectionPrecisionReport {
	baseline := buildBehaviorBaseline(flows, devices)
	contexts := buildPrecisionDeviceContexts(flows, observations, devices, baseline)
	builders := map[string]*precisionIncidentBuilder{}
	suppressed := map[string]*precisionSuppressionCounter{}

	suppress := func(key, label, reason string, count int) {
		if count <= 0 {
			return
		}
		item := suppressed[key]
		if item == nil {
			item = &precisionSuppressionCounter{label: label, reason: reason}
			suppressed[key] = item
		}
		item.count += count
	}
	builderFor := func(ip string) *precisionIncidentBuilder {
		ip = strings.TrimSpace(ip)
		if ip == "" || !isLocalDeviceIP(ip) {
			return nil
		}
		builder := builders[ip]
		if builder != nil {
			return builder
		}
		ctx := contexts[ip]
		builder = &precisionIncidentBuilder{
			deviceIP: ip,
			signals:  map[string]PrecisionSignal{},
			evidence: map[string]bool{},
		}
		if ctx != nil {
			builder.deviceLabel = ctx.label
			builder.category = ctx.category
		}
		builders[ip] = builder
		return builder
	}

	for _, event := range events {
		if event.Debug {
			continue
		}
		rule := canonicalRuleID(event)
		if isPrecisionSuppressedEvent(event) {
			suppress("low_value_event", "Low-value event suppressed", "Discovery, housekeeping, or debug-like events do not become incidents by themselves.", 1)
			continue
		}
		if isSingleFirewallBlockEvent(event) {
			if dst := firstLocalIP(event.DeviceKey, event.DstIP, event.SrcIP); dst != "" {
				if ctx := ensurePrecisionContext(contexts, dst); ctx != nil {
					ctx.inboundBlockCount++
					addStringBool(ctx.inboundBlockSources, event.SrcIP)
					if event.DstPort != 0 {
						ctx.inboundBlockPorts[event.DstPort] = true
					}
					observePrecisionBounds(ctx, event.Timestamp)
				}
			}
			suppress("single_firewall_block", "Single firewall block suppressed", "A lone router block is treated as background noise until it repeats or touches multiple ports.", 1)
			continue
		}
		for _, ip := range eventDeviceIPs(event) {
			builder := builderFor(ip)
			if builder == nil {
				continue
			}
			weight := precisionEventWeight(event)
			if weight <= 0 {
				suppress("weak_event", "Weak event suppressed", "The event is too weak without supporting context.", 1)
				continue
			}
			addPrecisionSignal(builder, PrecisionSignal{
				Key:        "event_" + strings.ToLower(firstNonEmpty(rule, event.Type)),
				Layer:      "observation",
				Label:      precisionEventLabel(event),
				Detail:     firstNonEmpty(event.ObservedFact, event.Inference, event.Message, event.Evidence),
				Weight:     weight,
				Confidence: event.Confidence,
				Source:     "events",
			}, event.Timestamp)
			addPrecisionEvidence(builder, event.Evidence)
			addPrecisionEvidence(builder, fmt.Sprintf("%s %s:%d -> %s:%d", rule, event.SrcIP, event.SrcPort, event.DstIP, event.DstPort))
		}
	}

	sweepSources := securityEventSweepSources(securityEvents)
	for _, event := range securityEvents {
		if !isInboundSecurityEvent(event) {
			continue
		}
		dst := firstLocalIP(event.DeviceIP, event.DstIP)
		if dst == "" {
			continue
		}
		ctx := ensurePrecisionContext(contexts, dst)
		if ctx == nil {
			continue
		}
		ctx.attackEvidenceCount++
		switch strings.ToLower(event.Verdict) {
		case "dropped", "rejected", "blocked":
			ctx.attackEvidenceBlocked++
		case "accepted", "allowed":
			ctx.attackEvidenceAccepted++
		}
		if isExposedServiceAttempt(event) {
			ctx.attackEvidenceExposed++
		}
		addStringBool(ctx.attackEvidenceSources, event.SrcIP)
		addStringBool(ctx.attackEvidenceTechniques, event.AttackTechnique)
		addStringBool(ctx.attackEvidenceTechniques, event.NormalizedTechnique)
		for _, taxonomy := range event.Taxonomy {
			addStringBool(ctx.attackEvidenceTaxonomies, taxonomy)
		}
		if event.DstPort != 0 {
			ctx.attackEvidencePorts[event.DstPort] = true
			if isSensitiveEvidencePort(event.DstPort) {
				ctx.attackEvidenceSensitivePorts[event.DstPort] = true
			}
		}
		if hasSuspiciousTCPFlags(event) {
			ctx.attackEvidenceSuspiciousFlags++
		}
		if sweepSources[event.SrcIP] {
			addStringBool(ctx.attackEvidenceSweepSources, event.SrcIP)
		}
		observePrecisionBounds(ctx, event.Timestamp)
	}

	for ip, ctx := range contexts {
		if ctx == nil {
			continue
		}
		if ctx.dnsOnlyCount > 0 && ctx.externalFlowCount == 0 && len(ctx.unknownUDPPorts) == 0 {
			suppress("dns_only", "DNS-only signal suppressed", "DNS queries are kept as context but do not become incidents without flow, novelty, or risk evidence.", ctx.dnsOnlyCount)
		}
		if ctx.baseline != nil {
			novelCount := len(ctx.baseline.NovelDestinations) + len(ctx.baseline.NovelProtocols) + len(ctx.baseline.NovelPorts)
			if novelCount == 1 && len(ctx.unknownUDPPorts) == 0 && len(ctx.baseline.UnexpectedProtocols) == 0 && len(ctx.baseline.UnexpectedPorts) == 0 {
				suppress("single_baseline_novelty", "Single novelty suppressed", "One new destination, protocol, or port is monitored but not promoted alone.", 1)
			}
			if novelCount >= 2 || len(ctx.baseline.UnexpectedProtocols)+len(ctx.baseline.UnexpectedPorts) > 0 || ctx.baseline.PlaintextConcern {
				builder := builderFor(ip)
				if builder != nil {
					addBaselineSignals(builder, ctx.baseline)
				}
			}
		}
		if len(ctx.unknownUDPPorts) > 0 {
			if shouldSuppressUnknownUDP(ctx) {
				suppress("single_unknown_udp", "Single unknown UDP signal suppressed", "One undecoded UDP port is kept as context until it repeats or aligns with novelty, category deviation, or risk evidence.", len(ctx.unknownUDPPorts))
				continue
			}
			builder := builderFor(ip)
			if builder != nil {
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        "unknown_udp",
					Layer:      "context",
					Label:      "Unknown UDP behavior with context",
					Detail:     "UDP ports " + joinPorts(sortedPortSet(ctx.unknownUDPPorts)) + " were observed without decoded application context.",
					Weight:     14,
					Confidence: "medium",
					Source:     "observations",
				}, ctx.last)
			}
		}
		if ctx.inboundBlockCount >= 5 || len(ctx.inboundBlockPorts) >= 3 {
			builder := builderFor(ip)
			if builder != nil {
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        "attack_like_inbound_blocks",
					Layer:      "correlation",
					Label:      "Repeated inbound blocks",
					Detail:     fmt.Sprintf("%d blocked inbound packets from %d source(s) across %d port(s).", ctx.inboundBlockCount, len(ctx.inboundBlockSources), len(ctx.inboundBlockPorts)),
					Weight:     minInt(30, 12+ctx.inboundBlockCount+len(ctx.inboundBlockPorts)*3),
					Confidence: "medium",
					Source:     "firewall",
				}, ctx.last)
			}
		}
		if ctx.attackEvidenceCount >= 5 || len(ctx.attackEvidencePorts) >= 3 {
			builder := builderFor(ip)
			if builder != nil {
				key := "attack_evidence_inbound_scan"
				label := "Router-boundary inbound scan evidence"
				if len(ctx.attackEvidencePorts) >= 3 {
					key = "attack_evidence_port_scan"
					label = "Router-boundary port scan evidence"
				}
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        key,
					Layer:      "correlation",
					Label:      label,
					Detail:     attackEvidencePrecisionDetail(ctx),
					Weight:     attackEvidencePrecisionWeight(ctx, 18),
					Confidence: "medium",
					Source:     "security_events",
				}, ctx.last)
			}
		}
		if len(ctx.attackEvidenceSweepSources) > 0 {
			builder := builderFor(ip)
			if builder != nil {
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        "attack_evidence_host_sweep",
					Layer:      "correlation",
					Label:      "Router-boundary host sweep evidence",
					Detail:     attackEvidencePrecisionDetail(ctx),
					Weight:     attackEvidencePrecisionWeight(ctx, 20),
					Confidence: "medium",
					Source:     "security_events",
				}, ctx.last)
			}
		}
		if len(ctx.attackEvidenceSensitivePorts) > 0 {
			builder := builderFor(ip)
			if builder != nil {
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        "attack_evidence_sensitive_service_probe",
					Layer:      "correlation",
					Label:      "Sensitive service probe at router boundary",
					Detail:     attackEvidencePrecisionDetail(ctx),
					Weight:     attackEvidencePrecisionWeight(ctx, 22),
					Confidence: "medium",
					Source:     "security_events",
				}, ctx.last)
			}
		}
		if ctx.attackEvidenceSuspiciousFlags > 0 {
			builder := builderFor(ip)
			if builder != nil {
				addPrecisionSignal(builder, PrecisionSignal{
					Key:        "attack_evidence_suspicious_tcp_flags",
					Layer:      "correlation",
					Label:      "Suspicious TCP flags at router boundary",
					Detail:     attackEvidencePrecisionDetail(ctx),
					Weight:     attackEvidencePrecisionWeight(ctx, 24),
					Confidence: "medium",
					Source:     "security_events",
				}, ctx.last)
			}
		}
	}

	incidents := suppressWeakPrecisionIncidents(finalizePrecisionIncidents(builders), suppress)
	out := DetectionPrecisionReport{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		DecisionPolicy:    precisionDecisionPolicy(),
		Baseline:          baseline,
		Incidents:         incidents,
		SuppressedSignals: sortedSuppressedSignals(suppressed),
		Recommendations:   precisionRecommendations(incidents, suppressed),
		Limitations: []string{
			"Passive precision scoring reduces false positives but cannot prove compromise.",
			"DNS, conntrack, and firewall logs provide metadata; encrypted payload content remains invisible.",
			"Baseline quality depends on the observation window and whether the OpenWrt gateway sees all IoT traffic.",
		},
	}
	out.Metrics = buildPrecisionMetrics(out, contexts)
	out.Layers = buildPrecisionLayerBreakdown(out)
	out.Window = precisionWindow(events, flows, observations)
	out.DecisionBreakdown = buildPrecisionDecisionBreakdown(out)
	out.SuppressionBreakdown = buildPrecisionSuppressionBreakdown(out)
	out.ScoreDistribution = buildPrecisionScoreDistribution(out.Incidents)
	out.EvaluationReadiness = buildPrecisionEvaluationReadiness(out.Incidents)
	out.PaperSummary = buildPrecisionPaperSummary(out)
	return out
}

func buildPrecisionDeviceContexts(flows []FlowRecord, observations []ObservationRecord, devices []InventoryDevice, baseline BehaviorBaseline) map[string]*precisionDeviceContext {
	out := map[string]*precisionDeviceContext{}
	ensure := func(ip string) *precisionDeviceContext {
		ip = strings.TrimSpace(ip)
		if ip == "" || !isLocalDeviceIP(ip) {
			return nil
		}
		ctx := out[ip]
		if ctx != nil {
			return ctx
		}
		ctx = &precisionDeviceContext{
			ip:                           ip,
			unknownUDPPorts:              map[uint16]bool{},
			inboundBlockSources:          map[string]bool{},
			inboundBlockPorts:            map[uint16]bool{},
			attackEvidenceSources:        map[string]bool{},
			attackEvidencePorts:          map[uint16]bool{},
			attackEvidenceTechniques:     map[string]bool{},
			attackEvidenceTaxonomies:     map[string]bool{},
			attackEvidenceSweepSources:   map[string]bool{},
			attackEvidenceSensitivePorts: map[uint16]bool{},
		}
		out[ip] = ctx
		return ctx
	}
	for _, device := range devices {
		ctx := ensure(device.IP)
		if ctx == nil {
			continue
		}
		ctx.label = firstNonEmpty(device.FamilyCandidate, device.VendorCandidate, device.CategoryCandidate)
		ctx.category = device.CategoryCandidate
	}
	for i := range baseline.Devices {
		profile := &baseline.Devices[i]
		ctx := ensure(profile.IP)
		if ctx == nil {
			continue
		}
		ctx.baseline = profile
		if ctx.category == "" {
			ctx.category = profile.Category
		}
	}
	for _, flow := range flows {
		ctx := ensure(flow.SrcIP)
		if ctx == nil {
			continue
		}
		if ctx.label == "" {
			ctx.label = flow.DeviceLabel
		}
		if ctx.category == "" {
			ctx.category = flow.DeviceCategory
		}
		if classifyProtectionFlow(flow) == protectionFlowExternal {
			ctx.externalFlowCount++
		}
		observePrecisionBounds(ctx, flow.Timestamp)
	}
	for _, observation := range observations {
		ctx := ensure(observation.SrcIP)
		if ctx == nil {
			ctx = ensure(observation.DstIP)
		}
		if ctx == nil {
			continue
		}
		if isObservationDNS(observation) {
			ctx.dnsOnlyCount++
		}
		if strings.EqualFold(observation.Protocol, "udp") && strings.TrimSpace(observation.AppProtocol) == "" && observation.DstPort != 0 {
			ctx.unknownUDPPorts[observation.DstPort] = true
		}
		observePrecisionBounds(ctx, observation.Timestamp)
	}
	return out
}

func ensurePrecisionContext(contexts map[string]*precisionDeviceContext, ip string) *precisionDeviceContext {
	ip = strings.TrimSpace(ip)
	if ip == "" || !isLocalDeviceIP(ip) {
		return nil
	}
	ctx := contexts[ip]
	if ctx == nil {
		ctx = &precisionDeviceContext{
			ip:                           ip,
			unknownUDPPorts:              map[uint16]bool{},
			inboundBlockSources:          map[string]bool{},
			inboundBlockPorts:            map[uint16]bool{},
			attackEvidenceSources:        map[string]bool{},
			attackEvidencePorts:          map[uint16]bool{},
			attackEvidenceTechniques:     map[string]bool{},
			attackEvidenceTaxonomies:     map[string]bool{},
			attackEvidenceSweepSources:   map[string]bool{},
			attackEvidenceSensitivePorts: map[uint16]bool{},
		}
		contexts[ip] = ctx
	}
	return ctx
}

func isPrecisionSuppressedEvent(event Event) bool {
	rule := strings.ToUpper(canonicalRuleID(event))
	if isLowNoiseEvent(event) {
		return true
	}
	return strings.Contains(rule, "MDNS") || strings.Contains(rule, "SSDP") || strings.Contains(rule, "NTP")
}

func isSingleFirewallBlockEvent(event Event) bool {
	return strings.EqualFold(canonicalRuleID(event), "OPENWRT_FIREWALL_BLOCK") && !isLocalDeviceIP(event.SrcIP) && isLocalDeviceIP(event.DstIP)
}

func precisionEventWeight(event Event) int {
	rule := strings.ToUpper(canonicalRuleID(event))
	switch {
	case rule == "I7_HTTP_AUTH" || rule == "I7_HTTP_BODY_SECRET" || rule == "I7_HTTP_TOKEN" || rule == "I3_AUTH_TOKEN_IN_URL":
		return 42
	case strings.Contains(rule, "TELNET") || strings.Contains(rule, "FTP"):
		return 36
	case strings.Contains(rule, "PLAINTEXT") && severityRank(event.Severity) >= severityRank("WARNING"):
		return 22
	case severityRank(event.Severity) >= severityRank("HIGH"):
		return 24
	case severityRank(event.Severity) >= severityRank("WARNING"):
		return 10
	default:
		return 0
	}
}

func precisionEventLabel(event Event) string {
	rule := canonicalRuleID(event)
	if rule == "" {
		rule = event.Type
	}
	return protectionReasonLabel(rule)
}

func addBaselineSignals(builder *precisionIncidentBuilder, profile *DeviceBehaviorProfile) {
	if builder == nil || profile == nil {
		return
	}
	novelCount := len(profile.NovelDestinations) + len(profile.NovelProtocols) + len(profile.NovelPorts)
	if novelCount >= 2 {
		addPrecisionSignal(builder, PrecisionSignal{
			Key:        "baseline_novelty",
			Layer:      "context",
			Label:      "Behavior differs from learned baseline",
			Detail:     baselineNoveltyDetail(profile),
			Weight:     minInt(26, 8+novelCount*4),
			Confidence: baselineConfidence(profile),
			Source:     "baseline",
		}, parseTimeOrZero(profile.LastSeen))
	}
	categoryDeviationCount := len(profile.UnexpectedProtocols) + len(profile.UnexpectedPorts)
	if profile.PlaintextConcern {
		categoryDeviationCount++
	}
	if categoryDeviationCount > 0 {
		addPrecisionSignal(builder, PrecisionSignal{
			Key:        "category_deviation",
			Layer:      "context",
			Label:      "Behavior differs from expected device category",
			Detail:     categoryDeviationDetail(profile),
			Weight:     minInt(30, 12+categoryDeviationCount*6),
			Confidence: "medium",
			Source:     "category_baseline",
		}, parseTimeOrZero(profile.LastSeen))
	}
}

func addPrecisionSignal(builder *precisionIncidentBuilder, signal PrecisionSignal, ts time.Time) {
	if builder == nil || signal.Key == "" || signal.Weight <= 0 {
		return
	}
	signal.Layer = precisionLayer(signal)
	signal.Taxonomy = precisionTaxonomy(signal)
	if strings.TrimSpace(signal.Confidence) == "" {
		signal.Confidence = "low"
	}
	existing := builder.signals[signal.Key]
	if existing.Weight < signal.Weight {
		builder.signals[signal.Key] = signal
	}
	builder.score += signal.Weight
	if !ts.IsZero() {
		if builder.first.IsZero() || ts.Before(builder.first) {
			builder.first = ts
		}
		if ts.After(builder.last) {
			builder.last = ts
		}
	}
}

func addPrecisionEvidence(builder *precisionIncidentBuilder, value string) {
	if builder == nil {
		return
	}
	value = strings.TrimSpace(value)
	if value != "" {
		builder.evidence[value] = true
	}
}

func finalizePrecisionIncidents(builders map[string]*precisionIncidentBuilder) []PrecisionIncident {
	out := make([]PrecisionIncident, 0, len(builders))
	for _, builder := range builders {
		if builder == nil || len(builder.signals) == 0 {
			continue
		}
		addCorrelationSignals(builder)
		score := clampInt(builder.score, 0, 100)
		if score < precisionMinIncidentScore {
			continue
		}
		signals := sortedPrecisionSignals(builder.signals)
		state := precisionState(score, signals)
		severity := precisionSeverity(score)
		confidence := precisionConfidence(score, signals)
		incident := PrecisionIncident{
			ID:                precisionIncidentID(builder.deviceIP, signals),
			State:             state,
			Severity:          severity,
			Confidence:        confidence,
			Score:             score,
			ScoreBand:         precisionScoreBand(score),
			PrimaryTaxonomy:   primaryPrecisionTaxonomy(signals),
			Taxonomies:        precisionTaxonomies(signals),
			DeviceIP:          builder.deviceIP,
			DeviceLabel:       builder.deviceLabel,
			Category:          builder.category,
			Title:             precisionTitle(score, signals),
			Summary:           precisionSummary(builder.deviceIP, score, signals),
			Signals:           signals,
			Decision:          precisionDecision(score, state, severity, confidence, signals),
			Evidence:          limitEvidenceStrings(sortedStringSet(builder.evidence), 6),
			RecommendedAction: precisionAction(score, signals),
		}
		if !builder.first.IsZero() {
			incident.FirstSeen = builder.first.UTC().Format(time.RFC3339)
		}
		if !builder.last.IsZero() {
			incident.LastSeen = builder.last.UTC().Format(time.RFC3339)
		}
		out = append(out, incident)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].DeviceIP < out[j].DeviceIP
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func suppressWeakPrecisionIncidents(incidents []PrecisionIncident, suppress func(key, label, reason string, count int)) []PrecisionIncident {
	out := make([]PrecisionIncident, 0, len(incidents))
	for _, incident := range incidents {
		switch {
		case shouldSuppressWeakPlaintextIncident(incident):
			suppress("weak_plaintext_only", "Weak plaintext-only incident suppressed", "Plaintext transport without credential, service, baseline, or correlation context is retained as evidence but not promoted to an incident.", 1)
			continue
		case shouldSuppressSingleWeakContextIncident(incident):
			suppress("single_weak_context", "Single weak context incident suppressed", "One weak context signal below the suspicious threshold is kept for baseline history but not promoted alone.", 1)
			continue
		default:
			out = append(out, incident)
		}
	}
	return out
}

func shouldSuppressWeakPlaintextIncident(incident PrecisionIncident) bool {
	if incident.State != "observe" || incident.Score >= precisionSuspiciousScoreThreshold {
		return false
	}
	return len(incident.Taxonomies) == 1 && incident.PrimaryTaxonomy == "plaintext_transport"
}

func shouldSuppressSingleWeakContextIncident(incident PrecisionIncident) bool {
	if incident.State != "observe" || incident.Score >= precisionSuspiciousScoreThreshold || len(incident.Signals) != 1 {
		return false
	}
	switch incident.PrimaryTaxonomy {
	case "unknown_udp", "category_deviation":
		return true
	default:
		return false
	}
}

func addCorrelationSignals(builder *precisionIncidentBuilder) {
	if builder == nil {
		return
	}
	signals := sortedPrecisionSignals(builder.signals)
	observationCount := 0
	contextCount := 0
	for _, signal := range signals {
		switch precisionLayer(signal) {
		case "observation":
			observationCount++
		case "context":
			contextCount++
		}
	}
	if observationCount > 0 && contextCount > 0 {
		addPrecisionSignal(builder, PrecisionSignal{
			Key:        "correlation_observation_context",
			Layer:      "correlation",
			Label:      "Observed risk aligns with device context",
			Detail:     "At least one observed risk signal overlaps with baseline, category, or protocol context.",
			Weight:     10,
			Confidence: "medium",
			Source:     "correlation",
		}, builder.last)
		return
	}
	if len(signals) >= 2 && contextCount >= 2 {
		addPrecisionSignal(builder, PrecisionSignal{
			Key:        "correlation_multi_context",
			Layer:      "correlation",
			Label:      "Multiple context signals align",
			Detail:     "Several weak context signals were observed together, so the device is promoted for review.",
			Weight:     6,
			Confidence: "medium",
			Source:     "correlation",
		}, builder.last)
		return
	}
	if hasPrecisionSignal(signals, "event_i7_http_auth") || hasPrecisionSignal(signals, "event_i7_http_token") || hasPrecisionSignal(signals, "event_i7_http_body_secret") {
		addPrecisionSignal(builder, PrecisionSignal{
			Key:        "correlation_direct_sensitive_exposure",
			Layer:      "correlation",
			Label:      "Direct sensitive exposure",
			Detail:     "Credential or token exposure is strong enough to promote without waiting for more context.",
			Weight:     8,
			Confidence: "high",
			Source:     "correlation",
		}, builder.last)
	}
}

func sortedPrecisionSignals(items map[string]PrecisionSignal) []PrecisionSignal {
	out := make([]PrecisionSignal, 0, len(items))
	for _, item := range items {
		if item.Layer == "" {
			item.Layer = precisionLayer(item)
		}
		if item.Taxonomy == "" {
			item.Taxonomy = precisionTaxonomy(item)
		}
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Weight == out[j].Weight {
			return out[i].Key < out[j].Key
		}
		return out[i].Weight > out[j].Weight
	})
	return out
}

func sortedSuppressedSignals(items map[string]*precisionSuppressionCounter) []SuppressedSignalSummary {
	out := make([]SuppressedSignalSummary, 0, len(items))
	for key, item := range items {
		if item == nil || item.count <= 0 {
			continue
		}
		out = append(out, SuppressedSignalSummary{Key: key, Label: item.label, Count: item.count, Reason: item.reason})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func buildPrecisionMetrics(report DetectionPrecisionReport, contexts map[string]*precisionDeviceContext) PrecisionMetrics {
	taxonomyCounts := map[string]int{}
	metrics := PrecisionMetrics{
		DeviceCount:              len(contexts),
		IncidentCount:            len(report.Incidents),
		BaselineReadyDeviceCount: report.Baseline.ReadyDeviceCount,
		NovelSignalCount:         report.Baseline.NovelDestinationCount + report.Baseline.NovelProtocolCount + report.Baseline.NovelPortCount,
		CategoryDeviationCount:   countCategoryDeviations(report.Baseline),
	}
	for _, incident := range report.Incidents {
		for _, taxonomy := range incident.Taxonomies {
			taxonomyCounts[taxonomy]++
		}
		switch incident.State {
		case "risky":
			metrics.RiskyIncidentCount++
		case "suspicious":
			metrics.SuspiciousIncidentCount++
		default:
			metrics.ObserveIncidentCount++
		}
		switch incident.Severity {
		case "HIGH":
			metrics.HighSeverityCount++
		case "MEDIUM":
			metrics.MediumSeverityCount++
		case "WARNING":
			metrics.WarningSeverityCount++
		}
		switch incident.Confidence {
		case "high":
			metrics.HighConfidenceCount++
		case "medium":
			metrics.MediumConfidenceCount++
		}
		for _, signal := range incident.Signals {
			if signal.Key == "attack_like_inbound_blocks" || strings.HasPrefix(signal.Key, "attack_evidence_") {
				metrics.AttackLikeIncidentCount++
				break
			}
		}
	}
	for _, item := range report.SuppressedSignals {
		metrics.SuppressedSignalCount += item.Count
	}
	metrics.SignalTaxonomies = toSortedKV(taxonomyCounts)
	return metrics
}

func buildPrecisionLayerBreakdown(report DetectionPrecisionReport) PrecisionLayerBreakdown {
	layers := PrecisionLayerBreakdown{
		Observation: PrecisionLayerSummary{
			Key:     "observation",
			Label:   "Observation Layer",
			Summary: "Normalizes raw events, flow metadata, DNS, firewall, and protocol observations.",
		},
		Context: PrecisionLayerSummary{
			Key:     "context",
			Label:   "Context Layer",
			Summary: "Compares observations against device baseline, category expectations, and passive blind spots.",
		},
		Correlation: PrecisionLayerSummary{
			Key:     "correlation",
			Label:   "Correlation Layer",
			Summary: "Promotes only repeated or mutually reinforcing signals into SOC incidents.",
		},
	}
	for _, incident := range report.Incidents {
		incidentLayers := map[string]bool{}
		for _, signal := range incident.Signals {
			layer := precisionLayer(signal)
			incidentLayers[layer] = true
			switch layer {
			case "observation":
				layers.Observation.SignalCount++
			case "context":
				layers.Context.SignalCount++
			case "correlation":
				layers.Correlation.SignalCount++
			}
		}
		if incidentLayers["observation"] {
			layers.Observation.IncidentCount++
		}
		if incidentLayers["context"] {
			layers.Context.IncidentCount++
		}
		if incidentLayers["correlation"] {
			layers.Correlation.IncidentCount++
		}
	}
	for _, item := range report.SuppressedSignals {
		switch item.Key {
		case "dns_only", "single_firewall_block", "low_value_event", "weak_event", "weak_plaintext_only":
			layers.Observation.SuppressedCount += item.Count
		case "single_baseline_novelty", "single_unknown_udp", "single_weak_context":
			layers.Context.SuppressedCount += item.Count
		default:
			layers.Correlation.SuppressedCount += item.Count
		}
	}
	return layers
}

func buildPrecisionDecisionBreakdown(report DetectionPrecisionReport) PrecisionDecisionBreakdown {
	stateCounts := map[string]int{}
	severityCounts := map[string]int{}
	confidenceCounts := map[string]int{}
	taxonomyCounts := map[string]int{}
	layerCounts := map[string]int{}
	scoreBandCounts := map[string]int{}

	for _, incident := range report.Incidents {
		addCount(stateCounts, incident.State)
		addCount(severityCounts, incident.Severity)
		addCount(confidenceCounts, incident.Confidence)
		addCount(scoreBandCounts, incident.ScoreBand)
		for _, taxonomy := range incident.Taxonomies {
			addCount(taxonomyCounts, taxonomy)
		}
		seenLayers := map[string]bool{}
		for _, signal := range incident.Signals {
			seenLayers[precisionLayer(signal)] = true
		}
		for layer := range seenLayers {
			addCount(layerCounts, layer)
		}
	}

	return PrecisionDecisionBreakdown{
		ByState:      toSortedKV(stateCounts),
		BySeverity:   toSortedKV(severityCounts),
		ByConfidence: toSortedKV(confidenceCounts),
		ByTaxonomy:   toSortedKV(taxonomyCounts),
		ByLayer:      toSortedKV(layerCounts),
		ByScoreBand:  toSortedKV(scoreBandCounts),
	}
}

func buildPrecisionSuppressionBreakdown(report DetectionPrecisionReport) PrecisionSuppressionBreakdown {
	layerCounts := map[string]int{}
	reasons := make([]SuppressionBreakdown, 0, len(report.SuppressedSignals))
	total := 0
	for _, item := range report.SuppressedSignals {
		layer := suppressionLayer(item.Key)
		total += item.Count
		addCountN(layerCounts, layer, item.Count)
		reasons = append(reasons, SuppressionBreakdown{
			Key:    item.Key,
			Label:  item.Label,
			Layer:  layer,
			Count:  item.Count,
			Reason: item.Reason,
		})
	}
	sort.SliceStable(reasons, func(i, j int) bool {
		if reasons[i].Count == reasons[j].Count {
			return reasons[i].Key < reasons[j].Key
		}
		return reasons[i].Count > reasons[j].Count
	})
	promoted := len(report.Incidents)
	summary := "No suppressed signals were recorded."
	if total > 0 {
		summary = fmt.Sprintf("%d incident(s) promoted while %d low-value signal(s) were suppressed.", promoted, total)
	}
	return PrecisionSuppressionBreakdown{
		TotalSuppressed: total,
		ByReason:        reasons,
		ByLayer:         toSortedKV(layerCounts),
		PromotionRatio:  ratio(promoted, promoted+total),
		Summary:         summary,
	}
}

func buildPrecisionScoreDistribution(incidents []PrecisionIncident) []PrecisionScoreBucket {
	buckets := []PrecisionScoreBucket{
		{Band: "0-13", MinScore: 0, MaxScore: 13, Description: "Suppressed or below incident threshold."},
		{Band: "14-29", MinScore: 14, MaxScore: 29, Description: "Observe-only incident candidate."},
		{Band: "30-49", MinScore: 30, MaxScore: 49, Description: "Suspicious incident requiring review."},
		{Band: "50-74", MinScore: 50, MaxScore: 74, Description: "Medium severity incident with stronger evidence."},
		{Band: "75-100", MinScore: 75, MaxScore: 100, Description: "High severity incident."},
	}
	for _, incident := range incidents {
		band := precisionScoreBand(incident.Score)
		for i := range buckets {
			if buckets[i].Band == band {
				buckets[i].Count++
				break
			}
		}
	}
	return buckets
}

func buildPrecisionEvaluationReadiness(incidents []PrecisionIncident) PrecisionEvaluationReadiness {
	required := make([]string, 0, len(incidents))
	for _, incident := range incidents {
		required = append(required, incident.ID)
	}
	sort.Strings(required)

	readiness := PrecisionEvaluationReadiness{
		ReadyForPrecisionEval: len(required) > 0,
		ReadyForRecallEval:    false,
		IncidentLabelCount:    0,
		RequiredLabelCount:    len(required),
		RequiredLabels:        required,
		LabelTemplateFields:   []string{"incident_id", "label", "device_ip", "note"},
		RecommendedProtocol: []string{
			"Generate incident_labels.jsonl with `quarant eval --init-labels`.",
			"Label every incident as true_positive, false_positive, or benign.",
			"Add explicit false_negative rows for important behavior observed by a human but missed by Quarant.",
			"Report precision only after all generated incidents are labeled; report recall only when false_negative review was performed.",
		},
	}
	if len(required) == 0 {
		readiness.ReadyForPrecisionEval = false
		readiness.BlockingIssues = append(readiness.BlockingIssues, "No incidents were generated; precision cannot be estimated from this run alone.")
	}
	readiness.BlockingIssues = append(readiness.BlockingIssues, "Human labels have not been loaded into this precision report; use the eval command for measured precision and recall.")
	return readiness
}

func buildPrecisionPaperSummary(report DetectionPrecisionReport) PrecisionPaperSummary {
	topSuppression := make([]KV, 0, len(report.SuppressedSignals))
	for _, item := range report.SuppressedSignals {
		topSuppression = append(topSuppression, KV{Key: item.Key, Count: item.Count})
	}
	sort.SliceStable(topSuppression, func(i, j int) bool {
		if topSuppression[i].Count == topSuppression[j].Count {
			return topSuppression[i].Key < topSuppression[j].Key
		}
		return topSuppression[i].Count > topSuppression[j].Count
	})

	supported := []string{
		"Incidents are deterministically generated from passive observation, context, and correlation signals.",
		"Each incident includes taxonomy, score band, decision reasons, and promoted evidence signals.",
	}
	if report.SuppressionBreakdown.TotalSuppressed > 0 {
		supported = append(supported, "False-positive reduction is measurable through suppression counts and reasons.")
	}
	if report.Baseline.ReadyDeviceCount > 0 {
		supported = append(supported, "Baseline-based novelty can be measured for devices with enough observed traffic.")
	}

	missing := []string{
		"Human-reviewed labels are still required to claim measured precision.",
		"False-negative review is still required to claim measured recall.",
	}
	if report.Metrics.IncidentCount == 0 {
		missing = append(missing, "This run has no promoted incidents, so mitigation effectiveness cannot be evaluated from it alone.")
	}

	return PrecisionPaperSummary{
		ObservationWindow:       report.Window,
		DeviceCount:             report.Metrics.DeviceCount,
		IncidentCount:           report.Metrics.IncidentCount,
		RiskyIncidentCount:      report.Metrics.RiskyIncidentCount,
		SuspiciousIncidentCount: report.Metrics.SuspiciousIncidentCount,
		ObserveIncidentCount:    report.Metrics.ObserveIncidentCount,
		SuppressedSignalCount:   report.Metrics.SuppressedSignalCount,
		TopTaxonomies:           limitKV(report.Metrics.SignalTaxonomies, 5),
		TopSuppressionReasons:   limitKV(topSuppression, 5),
		ResearchClaimsSupported: supported,
		ResearchClaimsMissing:   missing,
	}
}

func suppressionLayer(key string) string {
	switch key {
	case "dns_only", "single_firewall_block", "low_value_event", "weak_event", "weak_plaintext_only":
		return "observation"
	case "single_baseline_novelty", "single_unknown_udp", "single_weak_context":
		return "context"
	default:
		return "correlation"
	}
}

func addCount(counts map[string]int, key string) {
	addCountN(counts, key, 1)
}

func addCountN(counts map[string]int, key string, n int) {
	key = strings.TrimSpace(key)
	if key == "" || n <= 0 {
		return
	}
	counts[key] += n
}

func limitKV(items []KV, n int) []KV {
	if len(items) <= n {
		return items
	}
	out := make([]KV, n)
	copy(out, items[:n])
	return out
}

func precisionLayer(signal PrecisionSignal) string {
	layer := strings.ToLower(strings.TrimSpace(signal.Layer))
	switch layer {
	case "observation", "context", "correlation":
		return layer
	}
	switch {
	case strings.HasPrefix(signal.Key, "event_"):
		return "observation"
	case strings.HasPrefix(signal.Key, "correlation_"), signal.Key == "attack_like_inbound_blocks", strings.HasPrefix(signal.Key, "attack_evidence_"):
		return "correlation"
	default:
		return "context"
	}
}

func precisionWindow(events []Event, flows []FlowRecord, observations []ObservationRecord) Window {
	var first, last time.Time
	observe := func(ts time.Time) {
		if ts.IsZero() {
			return
		}
		if first.IsZero() || ts.Before(first) {
			first = ts
		}
		if ts.After(last) {
			last = ts
		}
	}
	for _, event := range events {
		observe(event.Timestamp)
	}
	for _, flow := range flows {
		observe(flow.Timestamp)
	}
	for _, observation := range observations {
		observe(observation.Timestamp)
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

func precisionState(score int, signals []PrecisionSignal) string {
	if score >= precisionRiskyScoreThreshold || hasPrecisionTaxonomy(signals, "credential_exposure") || hasPrecisionTaxonomy(signals, "insecure_service") {
		return "risky"
	}
	if score >= precisionSuspiciousScoreThreshold || len(signals) >= 2 || hasPrecisionTaxonomy(signals, "correlation") {
		return "suspicious"
	}
	return "observe"
}

func precisionSeverity(score int) string {
	switch {
	case score >= precisionHighSeverityThreshold:
		return "HIGH"
	case score >= precisionMediumSeverityThreshold:
		return "MEDIUM"
	case score >= precisionWarningSeverityThreshold:
		return "WARNING"
	default:
		return "INFO"
	}
}

func precisionConfidence(score int, signals []PrecisionSignal) string {
	if score >= precisionHighConfidenceThreshold && len(signals) >= 2 {
		return "high"
	}
	if score >= precisionSuspiciousScoreThreshold || len(signals) >= 2 {
		return "medium"
	}
	return "low"
}

func precisionTitle(score int, signals []PrecisionSignal) string {
	switch primaryPrecisionTaxonomy(signals) {
	case "credential_exposure":
		return "Credential exposure over plaintext traffic"
	case "insecure_service":
		return "Insecure service exposure"
	case "attack_like":
		return "Attack-like inbound activity"
	case "category_deviation":
		return "Device behavior differs from expected category"
	case "baseline_novelty":
		return "Device behavior changed from baseline"
	}
	if hasPrecisionSignal(signals, "attack_like_inbound_blocks") || hasPrecisionSignalPrefix(signals, "attack_evidence_") {
		return "Attack-like inbound activity"
	}
	if hasPrecisionSignal(signals, "category_deviation") {
		return "Device behavior differs from expected category"
	}
	if hasPrecisionSignal(signals, "baseline_novelty") {
		return "Device behavior changed from baseline"
	}
	if score >= 45 {
		return "High-confidence network risk"
	}
	return "Behavior to observe"
}

func precisionSummary(ip string, score int, signals []PrecisionSignal) string {
	labels := make([]string, 0, minInt(3, len(signals)))
	for _, signal := range signals {
		labels = append(labels, signal.Label)
		if len(labels) >= 3 {
			break
		}
	}
	return fmt.Sprintf("%s reached precision score %d from %s.", ip, score, strings.Join(labels, ", "))
}

func precisionAction(score int, signals []PrecisionSignal) string {
	switch {
	case score >= precisionHighSeverityThreshold:
		return "Investigate immediately and consider temporary IoT isolation while preserving logs."
	case score >= precisionMediumSeverityThreshold:
		return "Review device owner, firmware state, credentials, and recent destinations before applying blocks."
	case hasPrecisionSignal(signals, "attack_like_inbound_blocks") || hasPrecisionSignalPrefix(signals, "attack_evidence_"):
		return "Keep firewall logging enabled and confirm whether the traffic is internet background scan noise or targeted."
	default:
		return "Continue observation until the signal repeats or combines with another independent indicator."
	}
}

func precisionRecommendations(incidents []PrecisionIncident, suppressed map[string]*precisionSuppressionCounter) []string {
	recs := []string{}
	if len(incidents) == 0 {
		recs = append(recs, "Keep collecting baseline traffic; current low-value signals were suppressed instead of promoted.")
	}
	for _, incident := range incidents {
		if incident.State == "risky" {
			recs = append(recs, "Prioritize risky incidents with credential, plaintext, insecure service, or multi-signal evidence.")
			break
		}
	}
	if suppressed["dns_only"] != nil {
		recs = append(recs, "Use DNS-only observations as context; require flow, novelty, or risk evidence before alerting.")
	}
	if suppressed["single_firewall_block"] != nil {
		recs = append(recs, "Treat isolated firewall blocks as noise unless they repeat, fan out across ports, or target a sensitive IoT service.")
	}
	if len(recs) == 0 {
		recs = append(recs, "Review suspicious incidents first, then tune category baselines for devices that are known to be normal.")
	}
	return uniqueSortedStrings(recs)
}

func baselineNoveltyDetail(profile *DeviceBehaviorProfile) string {
	parts := []string{}
	if len(profile.NovelDestinations) > 0 {
		parts = append(parts, "destinations="+strings.Join(limitEvidenceStrings(profile.NovelDestinations, 3), ","))
	}
	if len(profile.NovelProtocols) > 0 {
		parts = append(parts, "protocols="+strings.Join(profile.NovelProtocols, ","))
	}
	if len(profile.NovelPorts) > 0 {
		parts = append(parts, "ports="+joinPorts(profile.NovelPorts))
	}
	return strings.Join(parts, " ")
}

func categoryDeviationDetail(profile *DeviceBehaviorProfile) string {
	parts := []string{}
	if len(profile.UnexpectedProtocols) > 0 {
		parts = append(parts, "unexpected_protocols="+strings.Join(profile.UnexpectedProtocols, ","))
	}
	if len(profile.UnexpectedPorts) > 0 {
		parts = append(parts, "unexpected_ports="+joinPorts(profile.UnexpectedPorts))
	}
	if profile.PlaintextConcern {
		parts = append(parts, "plaintext_concern=true")
	}
	return strings.Join(parts, " ")
}

func baselineConfidence(profile *DeviceBehaviorProfile) string {
	if profile != nil && profile.BaselineReady {
		return "medium"
	}
	return "low"
}

func hasPrecisionSignal(signals []PrecisionSignal, key string) bool {
	for _, signal := range signals {
		if signal.Key == key {
			return true
		}
	}
	return false
}

func hasPrecisionSignalPrefix(signals []PrecisionSignal, prefix string) bool {
	for _, signal := range signals {
		if strings.HasPrefix(signal.Key, prefix) {
			return true
		}
	}
	return false
}

func precisionIncidentID(ip string, signals []PrecisionSignal) string {
	parts := []string{strings.TrimSpace(ip), primaryPrecisionTaxonomy(signals)}
	parts = append(parts, precisionTaxonomies(signals)...)
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return "inc_" + hex.EncodeToString(sum[:])[:12]
}

func precisionDecisionPolicy() PrecisionDecisionPolicy {
	return PrecisionDecisionPolicy{
		Version:       "precision-v1-rule-based",
		IncidentModel: "one aggregate incident per local device, promoted from observation, context, and correlation signals",
		StateThresholds: []PrecisionThreshold{
			{Name: "risky", Condition: "score >= 65 OR taxonomy in {credential_exposure,insecure_service}", Description: "High-priority incident eligible for mitigation planning."},
			{Name: "suspicious", Condition: "score >= 30 OR at least two promoted signals OR correlation taxonomy", Description: "Needs review or additional observation before mitigation."},
			{Name: "observe", Condition: "score >= 14 and below suspicious threshold after final suppression", Description: "Recorded for trend analysis but not a mitigation trigger by itself."},
		},
		SeverityThresholds: []PrecisionThreshold{
			{Name: "HIGH", Condition: "score >= 75", Description: "Strong or multiple risk signals."},
			{Name: "MEDIUM", Condition: "score >= 50", Description: "Moderate risk signal set."},
			{Name: "WARNING", Condition: "score >= 30", Description: "Review-worthy weak or contextual signal set."},
			{Name: "INFO", Condition: "score < 30", Description: "Low-strength observation retained for continuity."},
		},
		ConfidencePolicy: []PrecisionThreshold{
			{Name: "high", Condition: "score >= 50 AND at least two signals", Description: "Independent or correlated evidence supports the incident."},
			{Name: "medium", Condition: "score >= 30 OR at least two signals", Description: "Enough context for review, but not strong enough alone."},
			{Name: "low", Condition: "otherwise", Description: "Weak signal retained for observation."},
		},
		SignalTaxonomy: []PrecisionTaxonomyPolicy{
			{Key: "credential_exposure", Layer: "observation", Description: "Credential, token, secret, or authorization material exposed in plaintext or URLs."},
			{Key: "insecure_service", Layer: "observation", Description: "Plaintext or risky management/service protocol such as Telnet, FTP, MQTT, RTSP, or CoAP."},
			{Key: "plaintext_transport", Layer: "observation", Description: "Plaintext transport risk without confirmed credential exposure."},
			{Key: "baseline_novelty", Layer: "context", Description: "Destination, protocol, or port differs from learned baseline."},
			{Key: "category_deviation", Layer: "context", Description: "Behavior differs from expected device category profile."},
			{Key: "unknown_udp", Layer: "context", Description: "UDP traffic without decoded application context after noise filtering."},
			{Key: "attack_like", Layer: "correlation", Description: "Repeated inbound blocks, router-boundary port scans, host sweeps, sensitive-service probes, suspicious TCP flags, or other activity consistent with scanning or probing."},
			{Key: "correlation", Layer: "correlation", Description: "Multiple weaker signals reinforce each other."},
		},
		SuppressionPolicy: []PrecisionSuppressionPolicy{
			{Key: "dns_only", Layer: "observation", Description: "DNS observations remain context unless paired with flow, novelty, or risk evidence."},
			{Key: "single_firewall_block", Layer: "observation", Description: "A lone inbound block is treated as internet noise unless it repeats or spans ports."},
			{Key: "single_baseline_novelty", Layer: "context", Description: "One new baseline item is monitored but not promoted alone."},
			{Key: "single_unknown_udp", Layer: "context", Description: "One undecoded UDP port is suppressed unless it repeats or aligns with other context."},
			{Key: "weak_plaintext_only", Layer: "observation", Description: "Plaintext transport without credential, service, baseline, or correlation context is retained as evidence but not promoted."},
			{Key: "single_weak_context", Layer: "context", Description: "One weak context signal below the suspicious threshold is retained in baseline history but not promoted."},
			{Key: "low_value_event", Layer: "observation", Description: "Discovery, housekeeping, and debug-like events are not incidents."},
			{Key: "weak_event", Layer: "observation", Description: "Events below the precision weight threshold are counted but not promoted."},
		},
		Limitations: []string{
			"Scores are deterministic heuristics for research evaluation, not proof of compromise.",
			"Incident IDs are stable for device and taxonomy sets, but may change when the taxonomy model changes.",
			"Suppression reduces false positives at the cost of potentially delaying weak early signals.",
		},
	}
}

func precisionDecision(score int, state, severity, confidence string, signals []PrecisionSignal) PrecisionDecision {
	return PrecisionDecision{
		StateReason:      precisionStateReason(score, state, signals),
		SeverityReason:   precisionSeverityReason(score, severity),
		ConfidenceReason: precisionConfidenceReason(score, confidence, signals),
		PromotedBy:       promotedPrecisionSignals(signals),
	}
}

func precisionStateReason(score int, state string, signals []PrecisionSignal) string {
	switch state {
	case "risky":
		if hasPrecisionTaxonomy(signals, "credential_exposure") {
			return "credential exposure taxonomy is always promoted to risky"
		}
		if hasPrecisionTaxonomy(signals, "insecure_service") {
			return "insecure service taxonomy is always promoted to risky"
		}
		return fmt.Sprintf("score %d reached risky threshold >= %d", score, precisionRiskyScoreThreshold)
	case "suspicious":
		if score >= precisionSuspiciousScoreThreshold {
			return fmt.Sprintf("score %d reached suspicious threshold >= %d", score, precisionSuspiciousScoreThreshold)
		}
		if hasPrecisionTaxonomy(signals, "correlation") {
			return "correlation taxonomy promoted the incident for review"
		}
		return "multiple promoted signals reached suspicious state"
	default:
		return fmt.Sprintf("score %d retained for observation", score)
	}
}

func precisionSeverityReason(score int, severity string) string {
	switch severity {
	case "HIGH":
		return fmt.Sprintf("score %d reached HIGH threshold >= %d", score, precisionHighSeverityThreshold)
	case "MEDIUM":
		return fmt.Sprintf("score %d reached MEDIUM threshold >= %d", score, precisionMediumSeverityThreshold)
	case "WARNING":
		return fmt.Sprintf("score %d reached WARNING threshold >= %d", score, precisionWarningSeverityThreshold)
	default:
		return fmt.Sprintf("score %d remains informational", score)
	}
}

func precisionConfidenceReason(score int, confidence string, signals []PrecisionSignal) string {
	switch confidence {
	case "high":
		return fmt.Sprintf("score %d with %d promoted signals", score, len(signals))
	case "medium":
		return fmt.Sprintf("score %d or %d promoted signals reached review confidence", score, len(signals))
	default:
		return "single or weak signal retained with low confidence"
	}
}

func precisionScoreBand(score int) string {
	switch {
	case score >= precisionHighSeverityThreshold:
		return "75-100"
	case score >= precisionMediumSeverityThreshold:
		return "50-74"
	case score >= precisionWarningSeverityThreshold:
		return "30-49"
	case score >= precisionMinIncidentScore:
		return "14-29"
	default:
		return "0-13"
	}
}

func promotedPrecisionSignals(signals []PrecisionSignal) []string {
	out := make([]string, 0, len(signals))
	for _, signal := range signals {
		if strings.TrimSpace(signal.Key) != "" {
			out = append(out, signal.Key)
		}
	}
	sort.Strings(out)
	return out
}

func precisionTaxonomy(signal PrecisionSignal) string {
	value := strings.ToLower(strings.TrimSpace(signal.Taxonomy))
	if value != "" {
		return value
	}
	key := strings.ToLower(strings.TrimSpace(signal.Key))
	label := strings.ToLower(signal.Label + " " + signal.Detail)
	switch {
	case strings.Contains(key, "http_auth") || strings.Contains(key, "http_token") || strings.Contains(key, "body_secret") || strings.Contains(key, "auth_token") || strings.Contains(label, "credential") || strings.Contains(label, "token"):
		return "credential_exposure"
	case strings.Contains(key, "telnet") || strings.Contains(key, "ftp") || strings.Contains(key, "mqtt") || strings.Contains(key, "rtsp") || strings.Contains(key, "coap") || strings.Contains(key, "insecure_service"):
		return "insecure_service"
	case strings.Contains(key, "plaintext"):
		return "plaintext_transport"
	case key == "baseline_novelty":
		return "baseline_novelty"
	case key == "category_deviation":
		return "category_deviation"
	case key == "unknown_udp":
		return "unknown_udp"
	case key == "attack_like_inbound_blocks" || strings.HasPrefix(key, "attack_evidence_"):
		return "attack_like"
	case strings.HasPrefix(key, "correlation_"):
		return "correlation"
	default:
		return "other"
	}
}

func precisionTaxonomies(signals []PrecisionSignal) []string {
	values := make([]string, 0, len(signals))
	for _, signal := range signals {
		values = append(values, precisionTaxonomy(signal))
	}
	return uniqueSortedStrings(values)
}

func primaryPrecisionTaxonomy(signals []PrecisionSignal) string {
	priority := []string{
		"credential_exposure",
		"insecure_service",
		"attack_like",
		"category_deviation",
		"baseline_novelty",
		"plaintext_transport",
		"unknown_udp",
		"correlation",
		"other",
	}
	set := map[string]bool{}
	for _, taxonomy := range precisionTaxonomies(signals) {
		set[taxonomy] = true
	}
	for _, taxonomy := range priority {
		if set[taxonomy] {
			return taxonomy
		}
	}
	return "other"
}

func hasPrecisionTaxonomy(signals []PrecisionSignal, taxonomy string) bool {
	taxonomy = strings.ToLower(strings.TrimSpace(taxonomy))
	for _, signal := range signals {
		if precisionTaxonomy(signal) == taxonomy {
			return true
		}
	}
	return false
}

func shouldSuppressUnknownUDP(ctx *precisionDeviceContext) bool {
	if ctx == nil || len(ctx.unknownUDPPorts) != 1 {
		return false
	}
	if ctx.baseline == nil {
		return true
	}
	novelCount := len(ctx.baseline.NovelDestinations) + len(ctx.baseline.NovelProtocols) + len(ctx.baseline.NovelPorts)
	deviationCount := len(ctx.baseline.UnexpectedProtocols) + len(ctx.baseline.UnexpectedPorts)
	return novelCount == 0 && deviationCount == 0 && !ctx.baseline.PlaintextConcern
}

func observePrecisionBounds(ctx *precisionDeviceContext, ts time.Time) {
	if ctx == nil || ts.IsZero() {
		return
	}
	if ctx.first.IsZero() || ts.Before(ctx.first) {
		ctx.first = ts
	}
	if ts.After(ctx.last) {
		ctx.last = ts
	}
}

func securityEventSweepSources(events []SecurityEvent) map[string]bool {
	targetsBySource := map[string]map[string]bool{}
	for _, event := range events {
		if !isInboundSecurityEvent(event) {
			continue
		}
		src := strings.TrimSpace(event.SrcIP)
		target := firstLocalIP(event.DeviceIP, event.DstIP)
		if src == "" || target == "" {
			continue
		}
		if targetsBySource[src] == nil {
			targetsBySource[src] = map[string]bool{}
		}
		targetsBySource[src][target] = true
	}
	out := map[string]bool{}
	for src, targets := range targetsBySource {
		if len(targets) >= 3 {
			out[src] = true
		}
	}
	return out
}

func attackEvidencePrecisionDetail(ctx *precisionDeviceContext) string {
	if ctx == nil {
		return ""
	}
	return fmt.Sprintf(
		"observed=%d blocked=%d accepted=%d exposed_service_attempts=%d sources=%d ports=%d sensitive_ports=%s techniques=%s taxonomy=%s.",
		ctx.attackEvidenceCount,
		ctx.attackEvidenceBlocked,
		ctx.attackEvidenceAccepted,
		ctx.attackEvidenceExposed,
		len(ctx.attackEvidenceSources),
		len(ctx.attackEvidencePorts),
		joinPorts(sortedPortSet(ctx.attackEvidenceSensitivePorts)),
		strings.Join(sortedStringSet(ctx.attackEvidenceTechniques), ","),
		strings.Join(sortedStringSet(ctx.attackEvidenceTaxonomies), ","),
	)
}

func attackEvidencePrecisionWeight(ctx *precisionDeviceContext, base int) int {
	if ctx == nil {
		return base
	}
	weight := base + minInt(ctx.attackEvidenceCount, 8) + len(ctx.attackEvidencePorts)*2
	if ctx.attackEvidenceAccepted > 0 || ctx.attackEvidenceExposed > 0 {
		weight += 12
	}
	if len(ctx.attackEvidenceSensitivePorts) > 0 {
		weight += 6
	}
	if ctx.attackEvidenceSuspiciousFlags > 0 {
		weight += 8
	}
	return minInt(46, weight)
}

func firstLocalIP(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && isLocalDeviceIP(value) {
			return value
		}
	}
	return ""
}

func addStringBool(set map[string]bool, value string) {
	value = strings.TrimSpace(value)
	if value != "" {
		set[value] = true
	}
}

func parseTimeOrZero(value string) time.Time {
	t, _ := time.Parse(time.RFC3339, strings.TrimSpace(value))
	return t
}
