package reportapi

import (
	"fmt"
	"sort"
	"strings"
)

const (
	judgmentNormal     = "normal"
	judgmentSuspicious = "suspicious"
	judgmentRisky      = "risky"
	judgmentUnknown    = "unknown"

	evidenceEnough       = "enough"
	evidencePartial      = "partial"
	evidenceInsufficient = "insufficient"
)

type DeviceJudgment struct {
	State               string                  `json:"state"`
	Confidence          string                  `json:"confidence"`
	EvidenceReadiness   string                  `json:"evidence_readiness"`
	Summary             string                  `json:"summary,omitempty"`
	Findings            []JudgmentFinding       `json:"findings,omitempty"`
	RecommendedControls []ControlRecommendation `json:"recommended_controls,omitempty"`
	DeferredDecisions   []DeferredDecision      `json:"deferred_decisions,omitempty"`
}

type JudgmentFinding struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Detail     string `json:"detail,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

type ControlRecommendation struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Decision   string `json:"decision"`
	Detail     string `json:"detail,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

type DeferredDecision struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Reason    string `json:"reason,omitempty"`
	BlindSpot string `json:"blind_spot,omitempty"`
}

func BuildDeviceJudgment(profile DeviceEvidenceProfile) DeviceJudgment {
	readiness := judgmentEvidenceReadiness(profile)
	findings := buildJudgmentFindings(profile)
	state := judgmentState(profile, readiness, findings)

	judgment := DeviceJudgment{
		State:               state,
		Confidence:          judgmentConfidence(profile, readiness, state),
		EvidenceReadiness:   readiness,
		Findings:            findings,
		RecommendedControls: buildControlRecommendations(profile, state),
		DeferredDecisions:   buildDeferredDecisions(profile),
	}
	judgment.Summary = judgmentSummary(profile, judgment)
	return judgment
}

func judgmentEvidenceReadiness(profile DeviceEvidenceProfile) string {
	hasNamedDestination := len(profile.ObservedEvidence.DNSQueries) > 0 ||
		len(profile.ObservedEvidence.TLSSNI) > 0 ||
		len(profile.ObservedEvidence.HTTPHosts) > 0 ||
		len(profile.ObservedEvidence.ExternalDestinations) > 0
	hasObservedEvidence := len(profile.ObservedEvidence.Protocols) > 0 ||
		len(profile.ObservedEvidence.Ports) > 0 ||
		len(profile.ObservedEvidence.LocalDestinations) > 0 ||
		len(profile.ObservedEvidence.DiscoveryProtocols) > 0 ||
		len(profile.ObservedEvidence.UnknownUDPPorts) > 0

	if hasNamedDestination && (profile.FlowCount >= 2 || profile.ObservationCount >= 3) {
		return evidenceEnough
	}
	if profile.FlowCount > 0 || profile.ObservationCount > 0 || profile.EventCount > 0 || hasObservedEvidence || hasNamedDestination {
		return evidencePartial
	}
	return evidenceInsufficient
}

func judgmentState(profile DeviceEvidenceProfile, readiness string, findings []JudgmentFinding) string {
	if readiness == evidenceInsufficient {
		return judgmentUnknown
	}
	if hasCriticalOrHighRisk(profile) || hasPlaintextSecretOrAuth(profile) || hasInsecureManagement(profile) {
		return judgmentRisky
	}
	for _, finding := range findings {
		if finding.Severity == "warning" {
			return judgmentSuspicious
		}
	}
	return judgmentNormal
}

func judgmentConfidence(profile DeviceEvidenceProfile, readiness, state string) string {
	if readiness == evidenceInsufficient || state == judgmentUnknown {
		return "low"
	}
	if state == judgmentRisky {
		if readiness == evidenceEnough || hasHighConfidenceRisk(profile) {
			return "high"
		}
		return "medium"
	}
	if state == judgmentSuspicious {
		if readiness == evidenceEnough {
			return "medium"
		}
		return "low"
	}
	if readiness == evidenceEnough {
		return "medium"
	}
	return "low"
}

func buildJudgmentFindings(profile DeviceEvidenceProfile) []JudgmentFinding {
	seen := map[string]JudgmentFinding{}
	add := func(item JudgmentFinding) {
		if item.Key == "" {
			return
		}
		if existing, ok := seen[item.Key]; ok && severityRank(item.Severity) <= severityRank(existing.Severity) {
			return
		}
		seen[item.Key] = item
	}

	for _, signal := range profile.RiskSignals {
		if severityRank(signal.Severity) >= severityRank("HIGH") {
			add(JudgmentFinding{
				Key:        "high_risk_signal",
				Label:      "High-risk signal observed",
				Detail:     riskSignalDetail(signal),
				Severity:   normalizedJudgmentSeverity(signal.Severity),
				Confidence: signal.Confidence,
			})
		}
	}
	if hasPlaintextSecretOrAuth(profile) {
		add(JudgmentFinding{
			Key:        "plaintext_secret_or_auth",
			Label:      "Plaintext credential or token exposure",
			Detail:     "HTTP authentication, token, or secret-like payload was observed without transport encryption.",
			Severity:   "critical",
			Confidence: "high",
		})
	}
	if hasInsecureManagement(profile) {
		add(JudgmentFinding{
			Key:        "insecure_management",
			Label:      "Insecure management path",
			Detail:     "Telnet, FTP, or a related legacy management signal was observed.",
			Severity:   "critical",
			Confidence: "high",
		})
	}
	if len(profile.ObservedEvidence.UnknownUDPPorts) > 0 {
		add(JudgmentFinding{
			Key:        "unknown_udp",
			Label:      "Unknown UDP behavior",
			Detail:     "UDP ports " + joinPorts(profile.ObservedEvidence.UnknownUDPPorts) + " were observed without decoded application context.",
			Severity:   "warning",
			Confidence: "medium",
		})
	}
	if len(profile.ObservedEvidence.ExternalDestinations) > 0 {
		add(JudgmentFinding{
			Key:        "external_dependency",
			Label:      "External dependency observed",
			Detail:     strings.Join(limitEvidenceStrings(profile.ObservedEvidence.ExternalDestinations, 3), ", "),
			Severity:   "info",
			Confidence: "medium",
		})
	}
	if hasEncryptedPayloadBlindSpot(profile) {
		add(JudgmentFinding{
			Key:        "encrypted_payload_blind_spot",
			Label:      "Encrypted payload blind spot",
			Detail:     "TLS/HTTPS metadata is visible, but application payload cannot be judged passively.",
			Severity:   "info",
			Confidence: "high",
		})
	}

	return sortedJudgmentFindings(seen)
}

func buildControlRecommendations(profile DeviceEvidenceProfile, state string) []ControlRecommendation {
	seen := map[string]ControlRecommendation{}
	add := func(item ControlRecommendation) {
		if item.Key != "" {
			seen[item.Key] = item
		}
	}

	if state == judgmentRisky || state == judgmentSuspicious {
		decision := "needs_review"
		confidence := "medium"
		if state == judgmentRisky {
			decision = "safe_to_recommend"
			confidence = "high"
		}
		add(ControlRecommendation{
			Key:        "isolate_iot_segment",
			Label:      "Isolate IoT segment",
			Decision:   decision,
			Detail:     "Limit lateral access from this device to other home assets.",
			Confidence: confidence,
		})
	}
	if hasInsecureManagement(profile) {
		add(ControlRecommendation{
			Key:        "block_insecure_management",
			Label:      "Block insecure management",
			Decision:   "safe_to_recommend",
			Detail:     "Block Telnet/FTP-style management traffic except from explicitly trusted administration paths.",
			Confidence: "high",
		})
	}
	if hasPlaintextSecretOrAuth(profile) || hasRisk(profile, "I7_HTTP_PLAINTEXT") {
		add(ControlRecommendation{
			Key:        "restrict_plaintext_http",
			Label:      "Restrict plaintext HTTP",
			Decision:   "needs_review",
			Detail:     "Move to HTTPS where possible, then block nonessential plaintext HTTP after confirming device functions.",
			Confidence: "high",
		})
	}
	if len(profile.ObservedEvidence.ExternalDestinations) > 0 {
		add(ControlRecommendation{
			Key:        "review_outbound_allowlist",
			Label:      "Review outbound allowlist",
			Decision:   "needs_review",
			Detail:     "Use the observed destinations as a candidate allowlist, but verify cloud update and notification behavior first.",
			Confidence: "medium",
		})
	}

	return sortedControlRecommendations(seen)
}

func buildDeferredDecisions(profile DeviceEvidenceProfile) []DeferredDecision {
	seen := map[string]DeferredDecision{}
	add := func(item DeferredDecision) {
		if item.Key != "" {
			seen[item.Key] = item
		}
	}

	if len(profile.ObservedEvidence.UnknownUDPPorts) > 0 {
		add(DeferredDecision{
			Key:       "defer_unknown_udp_block",
			Label:     "Do not block unknown UDP yet",
			Reason:    "The port is observable, but its purpose is not known from passive metadata alone.",
			BlindSpot: "unknown_udp_purpose",
		})
	}
	if hasEncryptedPayloadBlindSpot(profile) {
		add(DeferredDecision{
			Key:       "defer_tls_payload_assessment",
			Label:     "Do not judge encrypted payload content",
			Reason:    "TLS/HTTPS metadata does not reveal the application payload.",
			BlindSpot: "encrypted_payload_not_visible",
		})
	}
	add(DeferredDecision{
		Key:       "defer_firmware_assessment",
		Label:     "Do not infer firmware safety",
		Reason:    "Network observation cannot inspect firmware code, device storage, or local process state.",
		BlindSpot: "firmware_internals_not_visible",
	})

	return sortedDeferredDecisions(seen)
}

func judgmentSummary(profile DeviceEvidenceProfile, judgment DeviceJudgment) string {
	target := firstNonEmpty(profile.Label, profile.Family, profile.Vendor, profile.Category, profile.IP)
	switch judgment.State {
	case judgmentRisky:
		return fmt.Sprintf("%s has passive evidence strong enough to treat it as risky.", target)
	case judgmentSuspicious:
		return fmt.Sprintf("%s shows behavior that should be reviewed before applying blocking controls.", target)
	case judgmentNormal:
		return fmt.Sprintf("%s has no current passive risk signal in the observed window.", target)
	default:
		return fmt.Sprintf("%s does not have enough passive evidence for a security judgment yet.", target)
	}
}

func hasCriticalOrHighRisk(profile DeviceEvidenceProfile) bool {
	for _, signal := range profile.RiskSignals {
		if severityRank(signal.Severity) >= severityRank("HIGH") {
			return true
		}
	}
	return false
}

func hasHighConfidenceRisk(profile DeviceEvidenceProfile) bool {
	for _, signal := range profile.RiskSignals {
		if confidenceRank(signal.Confidence) >= confidenceRank("high") {
			return true
		}
	}
	return false
}

func hasPlaintextSecretOrAuth(profile DeviceEvidenceProfile) bool {
	return hasRisk(profile, "I7_HTTP_AUTH") ||
		hasRisk(profile, "I7_HTTP_BODY_SECRET") ||
		hasRisk(profile, "I7_HTTP_TOKEN")
}

func hasInsecureManagement(profile DeviceEvidenceProfile) bool {
	return hasRiskPrefix(profile, "I2_") ||
		containsPort(profile.ObservedEvidence.Ports, 23) ||
		containsPort(profile.ObservedEvidence.Ports, 21)
}

func hasEncryptedPayloadBlindSpot(profile DeviceEvidenceProfile) bool {
	return hasAny(profile.ObservedEvidence.TLSSNI) ||
		containsEvidenceString(profile.ObservedEvidence.Protocols, "tls") ||
		containsEvidenceString(profile.ObservedEvidence.Protocols, "https")
}

func riskSignalDetail(signal DeviceRiskSignal) string {
	if signal.ObservedFact != "" {
		return signal.ObservedFact
	}
	if signal.Inference != "" {
		return signal.Inference
	}
	if signal.RuleID != "" {
		return signal.RuleID
	}
	return "Risk signal observed."
}

func normalizedJudgmentSeverity(value string) string {
	switch {
	case severityRank(value) >= severityRank("CRITICAL"):
		return "critical"
	case severityRank(value) >= severityRank("HIGH"):
		return "high"
	case severityRank(value) >= severityRank("WARNING"):
		return "warning"
	default:
		return "info"
	}
}

func sortedJudgmentFindings(items map[string]JudgmentFinding) []JudgmentFinding {
	out := make([]JudgmentFinding, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sortJudgmentFindings(out)
	return out
}

func sortJudgmentFindings(items []JudgmentFinding) {
	severityOrder := map[string]int{"critical": 4, "high": 3, "warning": 2, "info": 1}
	sort.SliceStable(items, func(i, j int) bool {
		if severityOrder[items[i].Severity] == severityOrder[items[j].Severity] {
			return items[i].Key < items[j].Key
		}
		return severityOrder[items[i].Severity] > severityOrder[items[j].Severity]
	})
}

func sortedControlRecommendations(items map[string]ControlRecommendation) []ControlRecommendation {
	out := make([]ControlRecommendation, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func sortedDeferredDecisions(items map[string]DeferredDecision) []DeferredDecision {
	out := make([]DeferredDecision, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
