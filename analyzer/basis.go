package analyzer

import "strings"

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
		eventType == "I8_NEW_DEVICE_OBSERVED",
		eventType == "I8_UNREGISTERED_DEVICE_ACTIVE",
		eventType == "IP_MAC_BINDING_CHANGED":
		return BasisObserved

	default:
		return BasisInferred
	}
}
