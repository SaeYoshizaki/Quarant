package analyzer

import (
	"regexp"
	"strings"

	"quarant/analyzer/rules"
)

// Evidence basis values. Every event states what its detection rests on:
//
//   - observed: the triggering fact was seen directly in traffic (a
//     plaintext password field, a TLS 1.0 handshake, a Telnet prompt). The
//     risk statement may still be an interpretation, but the trigger is not.
//   - inferred: the trigger is a judgement over observations (port-number
//     based service guesses, keyword heuristics, statistics over many
//     connections, device-category policies).
//   - reference_match: the trigger is a match of observed data against an
//     external or curated reference (vulnerability lists, EOL lists, cloud
//     endpoint lists, threat intelligence). Its correctness depends on the
//     reference's accuracy and freshness, and applicability to this device
//     is unconfirmed unless stated otherwise.
const (
	BasisObserved       = "observed"
	BasisInferred       = "inferred"
	BasisReferenceMatch = "reference_match"
)

// eventBasis classifies built-in event types. Unknown types default to
// inferred, the conservative choice.
func eventBasis(eventType string) string {
	switch {
	case strings.HasPrefix(eventType, "I5_"),
		eventType == "I4_I5_COMBINED_RISK",
		eventType == "I4_FIRMWARE_RISK_ENRICHMENT",
		strings.HasSuffix(eventType, "_EOL_DEVICE"),
		eventType == "I3_UNEXPECTED_CLOUD_ENDPOINT",
		strings.HasPrefix(eventType, "THREAT_INTEL_"):
		return BasisReferenceMatch

	case strings.HasPrefix(eventType, "INSECURE_"),
		strings.HasPrefix(eventType, "I2_") && strings.HasSuffix(eventType, "_PROTOCOL_EVIDENCE"),
		strings.HasPrefix(eventType, "I7_TLS_"),
		eventType == "TLS_CLIENT_HELLO",
		eventType == "I3_AUTH_TOKEN_IN_URL",
		eventType == "I9_UPNP_PORT_MAPPING_REQUESTED",
		eventType == "I8_NEW_DEVICE_OBSERVED",
		eventType == "I8_UNREGISTERED_DEVICE_ACTIVE",
		eventType == "IP_MAC_BINDING_CHANGED":
		return BasisObserved

	default:
		return BasisInferred
	}
}

// deviceScopedTypes are findings about a device rather than about one flow.
var deviceScopedTypes = map[string]bool{
	"I5_KNOWN_VULNERABLE_COMPONENT":  true,
	"I4_I5_COMBINED_RISK":            true,
	"I4_FIRMWARE_RISK_ENRICHMENT":    true,
	"I4_WEAK_UPDATE_VISIBILITY":      true,
	"I4_MAYBE_EOL_DEVICE":            true,
	"I4_LIKELY_EOL_DEVICE":           true,
	"R1_COMPOSITE_RISK":              true,
	"I6_TLS_UNEXPECTED_SNI_OBSERVED": true,
	"I3_UNEXPECTED_CLOUD_ENDPOINT":   true,
}

var evidenceKeyRe = regexp.MustCompile(`(?:knowledge_id|matched_component_id|sni|host|risk_level)=(\S+)`)

// deviceScopedKey returns the de-duplication key for device-level findings,
// or "" for per-flow findings. The key keeps the matched entity (knowledge
// entry, SNI, host) so that a different match is still reported.
func deviceScopedKey(m rules.Match, deviceIP string) string {
	if deviceIP == "" || !deviceScopedTypes[m.Type] {
		return ""
	}
	key := deviceIP + "|" + m.Type
	if sub := evidenceKeyRe.FindStringSubmatch(m.Evidence); sub != nil {
		key += "|" + sub[1]
	}
	return key
}
