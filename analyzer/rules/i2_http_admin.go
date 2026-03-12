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
		RuleID:   "I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		Type:     "I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		Category: "I2",
		Severity: SeverityWarning,
		Message:  "HTTP admin interface suspected",
		Evidence: evidence,
	}, true
}

func init() {
	Register(&I2HTTPAdminRule{})
}