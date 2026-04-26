package rules

import (
	"fmt"
	"strings"
)

type I2InsecureServiceRule struct{}

func (r *I2InsecureServiceRule) ID() string         { return "I2_INSECURE_SERVICE" }
func (r *I2InsecureServiceRule) Category() string   { return "I2" }
func (r *I2InsecureServiceRule) Severity() Severity { return SeverityWarning }
func (r *I2InsecureServiceRule) Type() string       { return "I2_INSECURE_SERVICE" }

func (r *I2InsecureServiceRule) Apply(ctx *Context) (Match, bool) {
	service, ok := InsecureServiceNameByPort(ctx.DstPort)
	if !ok {
		return Match{}, false
	}

	upper := strings.ToUpper(service)
	indicators := DetectServiceIndicators(service, ctx.Payload)
	display := serviceDisplayName(service)
	recommendation := i2ServiceRecommendation(service)
	inference := i2ServiceRiskText(service)

	if len(indicators) > 0 {
		return Match{
			RuleID:         "I2_" + upper + "_PROTOCOL_EVIDENCE",
			Type:           "I2_" + upper + "_PROTOCOL_EVIDENCE",
			Category:       "I2",
			Severity:       SeverityWarning,
			Message:        display + " service traffic was observed on the local network.",
			Evidence:       fmt.Sprintf("service=%s port=%d indicators=[%s]", service, ctx.DstPort, strings.Join(indicators, ",")),
			OWASPTags:      uniqueTags("I2", "I7"),
			Confidence:     "high",
			ObservedFact:   display + " protocol evidence was observed in traffic.",
			Inference:      inference,
			Limitation:     "Passive monitoring confirms the protocol was observed, but it does not confirm how the service is configured or whether access controls are adequate.",
			Recommendation: recommendation,
		}, true
	}

	return Match{
		RuleID:         "I2_" + upper + "_SERVICE_OBSERVED",
		Type:           "I2_" + upper + "_SERVICE_OBSERVED",
		Category:       "I2",
		Severity:       SeverityWarning,
		Message:        display + " service was observed on the local network.",
		Evidence:       fmt.Sprintf("service=%s port=%d", service, ctx.DstPort),
		OWASPTags:      uniqueTags("I2", "I7"),
		Confidence:     "high",
		ObservedFact:   display + " service traffic was observed.",
		Inference:      inference,
		Limitation:     "Passive monitoring does not confirm whether the service is intentionally exposed or limited to trusted clients.",
		Recommendation: recommendation,
	}, true
}

func init() {
	Register(&I2InsecureServiceRule{})
}
