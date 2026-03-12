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

	return Match{
		RuleID:   "I2_" + upper + "_SERVICE_OBSERVED",
		Type:     "I2_" + upper + "_SERVICE_OBSERVED",
		Message:  upper + " service observed",
		Evidence: fmt.Sprintf("service=%s dst_port=%d", service, ctx.DstPort),
	}, true
}

func init() {
	Register(&I2InsecureServiceRule{})
}
