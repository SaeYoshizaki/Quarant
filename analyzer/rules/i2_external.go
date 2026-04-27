package rules

import "fmt"

type I2ExternalExposureRule struct{}

func (r *I2ExternalExposureRule) ID() string         { return "I2_EXTERNAL_EXPOSURE" }
func (r *I2ExternalExposureRule) Category() string   { return "I2" }
func (r *I2ExternalExposureRule) Severity() Severity { return SeverityHigh }
func (r *I2ExternalExposureRule) Type() string       { return "I2_EXTERNAL_EXPOSURE" }

func (r *I2ExternalExposureRule) Apply(ctx *Context) (Match, bool) {
	if !IsPublicIP(ctx.DstIP) {
		return Match{}, false
	}

	if service, ok := InsecureServiceNameByPort(ctx.DstPort); ok {
		display := serviceDisplayName(service)
		return Match{
			RuleID:         "I2_EXTERNAL_" + service,
			Type:           "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK",
			Severity:       SeverityHigh,
			Message:        fmt.Sprintf("%s service was observed toward a public network destination.", display),
			Evidence:       fmt.Sprintf("service=%s dst_ip=%s dst_port=%d", service, ctx.DstIP, ctx.DstPort),
			OWASPTags:      uniqueTags("I2", "I7"),
			Confidence:     "high",
			ObservedFact:   fmt.Sprintf("%s traffic was observed toward public IP %s.", display, ctx.DstIP),
			Inference:      i2ServiceRiskText(service) + " Exposure beyond the trusted local network increases the likelihood of unauthorized access or interception.",
			Limitation:     "Passive monitoring does not prove that the service is intentionally Internet-exposed or reachable from every external network path.",
			Recommendation: i2ServiceRecommendation(service),
		}, true
	}

	if ctx.HTTP != nil {
		if indicators, ok := DetectHTTPAdminIndicators(ctx.HTTP); ok {
			return Match{
				RuleID:         "I2_HTTP_ADMIN_EXTERNAL",
				Type:           "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED",
				Severity:       SeverityHigh,
				Message:        "HTTP management-like access was observed toward a public network destination.",
				Evidence:       fmt.Sprintf("dst_ip=%s indicators=%v", ctx.DstIP, indicators),
				OWASPTags:      uniqueTags("I2", "I3", "I7"),
				Confidence:     "medium",
				ObservedFact:   "HTTP management indicators were observed toward a public IP destination.",
				Inference:      "HTTP management endpoints may expose configuration or administrative functions without transport encryption.",
				Limitation:     "Passive monitoring cannot confirm the exact administrative capability behind the endpoint or whether additional authentication controls are present.",
				Recommendation: "Use HTTPS if supported and confirm that the interface is not exposed outside the trusted network.",
			}, true
		}
	}

	return Match{}, false
}

func init() {
	Register(&I2ExternalExposureRule{})
}
