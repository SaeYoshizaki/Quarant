package rules

import "strings"

type I2HTTPAdminRule struct{}

func (r *I2HTTPAdminRule) ID() string         { return "I2_HTTP_ADMIN_INTERFACE" }
func (r *I2HTTPAdminRule) Category() string   { return "I2" }
func (r *I2HTTPAdminRule) Severity() Severity { return SeverityWarning }
func (r *I2HTTPAdminRule) Type() string       { return "I2_HTTP_ADMIN_INTERFACE_SUSPECTED" }

func (r *I2HTTPAdminRule) Apply(ctx *Context) (Match, bool) {
	if ctx.HTTP == nil {
		return Match{}, false
	}

	indicators, ok := DetectHTTPAdminIndicators(ctx.HTTP)
	if !ok {
		return Match{}, false
	}

	evidence := strings.Join(indicators, ",")
	if evidence == "" {
		evidence = ctx.HTTP.Method + " " + ctx.HTTP.Path
	}

	return Match{
		RuleID:         "I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		Type:           "I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		Category:       "I2",
		Severity:       SeverityWarning,
		Message:        "HTTP management-like interface was observed on the local network.",
		Evidence:       evidence,
		OWASPTags:      uniqueTags("I2", "I3", "I7"),
		Confidence:     "medium",
		ObservedFact:   "HTTP management indicators were observed in traffic.",
		Inference:      "HTTP management endpoints may expose configuration or administrative functions without transport encryption.",
		Limitation:     "Passive monitoring cannot confirm the exact management features behind the endpoint or whether HTTPS is available elsewhere.",
		Recommendation: "Use HTTPS if supported and confirm that the interface is not exposed outside the trusted network.",
	}, true
}

func init() {
	Register(&I2HTTPAdminRule{})
}
