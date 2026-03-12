package rules

import "fmt"

type I2ExternalExposureRule struct{}

func (r *I2ExternalExposureRule) ID() string         { return "I2_EXTERNAL_EXPOSURE" }
func (r *I2ExternalExposureRule) Category() string   { return "I2" }
func (r *I2ExternalExposureRule) Severity() Severity { return SeverityCritical }
func (r *I2ExternalExposureRule) Type() string       { return "I2_EXTERNAL_EXPOSURE" }

func (r *I2ExternalExposureRule) Apply(ctx *Context) (Match, bool) {
	if !IsPublicIPv4(ctx.DstIP) {
		return Match{}, false
	}

	if service, ok := InsecureServiceNameByPort(ctx.DstPort); ok {
		return Match{
			RuleID:   "I2_EXTERNAL_" + service,
			Type:     "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK",
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("Insecure %s service observed toward public network", service),
			Evidence: fmt.Sprintf("service=%s dst_ip=%s dst_port=%d", service, ctx.DstIP, ctx.DstPort),
		}, true
	}

	if ctx.HTTP != nil {
		if indicators, ok := DetectHTTPAdminIndicators(ctx.HTTP); ok {
			return Match{
				RuleID:   "I2_HTTP_ADMIN_EXTERNAL",
				Type:     "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED",
				Severity: SeverityCritical,
				Message:  "HTTP admin interface suspected over public network",
				Evidence: fmt.Sprintf("dst_ip=%s indicators=%v", ctx.DstIP, indicators),
			}, true
		}
	}

	return Match{}, false
}

func init() {
	Register(&I2ExternalExposureRule{})
}
