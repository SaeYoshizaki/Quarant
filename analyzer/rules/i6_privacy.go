package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I6PrivacyRule struct {
	db *knowledge.DB
}

func NewI6PrivacyRule(db *knowledge.DB) *I6PrivacyRule {
	return &I6PrivacyRule{db: db}
}

func (r *I6PrivacyRule) ID() string         { return "I6_PRIVACY" }
func (r *I6PrivacyRule) Category() string   { return "I6" }
func (r *I6PrivacyRule) Severity() Severity { return SeverityWarning }
func (r *I6PrivacyRule) Type() string       { return "I6_PRIVACY" }

func (r *I6PrivacyRule) Apply(ctx *Context) (Match, bool) {
	if r.db == nil || ctx == nil || ctx.HTTP == nil {
		return Match{}, false
	}

	commType := DetectCommunicationType(ctx.HTTP)
	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = "unknown"
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		if m, ok := r.applyBehaviorBaseline(ctx, category, commType); ok {
			return m, true
		}
	}

	if commType == "" {
		return Match{}, false
	}

	hits := DetectPIIHits(ctx.HTTP, ctx.Payload)
	if len(hits) == 0 {
		return Match{}, false
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		for _, hit := range hits {
			if r.db.IsSuspiciousCombination(category, commType, hit.Type) {
				return Match{
					RuleID:   "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Type:     "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Privacy-related information violates device category policy",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				}, true
			}
		}

		if !r.db.IsAllowedCommunicationType(category, commType) {
			hit := hits[0]
			return Match{
				RuleID:   "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Type:     "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in unexpected communication type",
				Evidence: fmt.Sprintf(
					"category=%s comm_type=%s pii_type=%s source=%s %s",
					category, commType, hit.Type, hit.Source, hit.Evidence,
				),
			}, true
		}

		for _, hit := range hits {
			if !r.db.IsAllowedPIIType(category, hit.Type) {
				return Match{
					RuleID:   "I6_HTTP_UNEXPECTED_PII",
					Type:     "I6_HTTP_UNEXPECTED_PII",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Unexpected privacy-related information observed for device category",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				}, true
			}
		}

		return Match{}, false
	}

	for _, hit := range hits {
		if commType == "analytics" || commType == "tracking" {
			return Match{
				RuleID:   "I6_HTTP_PRIVACY_EXPOSURE",
				Type:     "I6_HTTP_PRIVACY_EXPOSURE",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in suspicious HTTP communication",
				Evidence: fmt.Sprintf(
					"comm_type=%s pii_type=%s source=%s %s category=%s",
					commType, hit.Type, hit.Source, hit.Evidence, category,
				),
			}, true
		}
	}

	return Match{}, false
}

func (r *I6PrivacyRule) applyBehaviorBaseline(ctx *Context, category, commType string) (Match, bool) {
	baseline, ok := r.db.GetBehaviorBaseline(category)
	if !ok {
		return Match{}, false
	}

	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	path := strings.ToLower(strings.TrimSpace(ctx.HTTP.Path))
	isExternal := IsPublicIPv4(ctx.DstIP)
	suspicious := suspiciousPatternSummary(baseline.SuspiciousPatterns)
	inference, hasInference := r.db.GetCategoryInference(category)
	var representativeDomains []string
	if hasInference {
		representativeDomains = inference.RepresentativeDomains
	}
	riskSignals := collectRiskSignals(baseline, ctx, commType, host, path, isExternal, representativeDomains)
	riskSummary := strings.Join(riskSignals, ",")

	if isExternal && !ctx.TLS && baseline.PlaintextTolerance == "low" {
		return Match{
			RuleID:   "I6_HTTP_BASELINE_PLAINTEXT",
			Type:     "I6_HTTP_BASELINE_PLAINTEXT",
			Category: "I6",
			Severity: SeverityWarning,
			Message: formatBaselineMessage(
				"Category baseline expects encrypted external communication",
				suspicious,
				riskSummary,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_ip=%s dst_port=%d suspicious_patterns=%s risk_signals=%s",
				category, host, ctx.DstIP, ctx.DstPort, suspicious, riskSummary,
			),
		}, true
	}

	if indicators, hasAdmin := DetectHTTPAdminIndicators(ctx.HTTP); hasAdmin && isExternal && !baseline.LocalAdminExpected {
		return Match{
			RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
			Type:     "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
			Category: "I6",
			Severity: SeverityWarning,
			Message: formatBaselineMessage(
				"Category baseline does not expect external admin-style HTTP access",
				suspicious,
				riskSummary,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s path=%s indicators=%s suspicious_patterns=%s risk_signals=%s",
				category, host, path, strings.Join(indicators, ","), suspicious, riskSummary,
			),
		}, true
	}

	if commType != "" && isExternal && !matchesExpectedProtocol(baseline.ExpectedProtocols, ctx) {
		return Match{
			RuleID:   "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Type:     "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Category: "I6",
			Severity: SeverityWarning,
			Message: formatBaselineMessage(
				"Observed protocol usage does not fit the category baseline",
				suspicious,
				riskSummary,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_port=%d expected_protocols=%s suspicious_patterns=%s risk_signals=%s",
				category, host, ctx.DstPort, strings.Join(baseline.ExpectedProtocols, ","), suspicious, riskSummary,
			),
		}, true
	}

	if commType == "analytics" || commType == "tracking" || commType == "cloud_api" {
		if hasInference && host != "" && isExternal && !hostMatchesRepresentativeDomains(host, representativeDomains) {
			return Match{
				RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Type:     "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Category: "I6",
				Severity: SeverityWarning,
				Message: formatBaselineMessage(
					"Observed external domain does not fit the category baseline",
					suspicious,
					riskSummary,
				),
				Evidence: fmt.Sprintf(
					"category=%s host=%s representative_domains=%s suspicious_patterns=%s risk_signals=%s",
					category, host, strings.Join(inference.RepresentativeDomains, ","), suspicious, riskSummary,
				),
			}, true
		}
	}

	return Match{}, false
}

func DetectCommunicationType(http *HTTPInfo) string {
	if http == nil {
		return ""
	}

	path := strings.ToLower(http.Path)
	host := strings.ToLower(http.Headers["host"])
	combined := host + " " + path

	switch {
	case containsAny(combined, "analytics", "metrics", "measure", "stat", "stats"):
		return "analytics"
	case containsAny(combined, "track", "tracking", "collect", "telemetry", "report"):
		return "tracking"
	case containsAny(combined, "/api/", "/v1/", "/v2/", "cloud"):
		return "cloud_api"
	default:
		return ""
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func hostMatchesRepresentativeDomains(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func matchesExpectedProtocol(expected []string, ctx *Context) bool {
	observed := observedProtocols(ctx)
	for _, candidate := range observed {
		for _, allowed := range expected {
			if candidate == strings.ToLower(strings.TrimSpace(allowed)) {
				return true
			}
		}
	}
	return false
}

func observedProtocols(ctx *Context) []string {
	values := make([]string, 0, 3)
	if ctx.TLS {
		values = append(values, "https", "tls")
	} else if ctx.HTTP != nil {
		values = append(values, "http")
	}

	switch ctx.DstPort {
	case 554:
		values = append(values, "rtsp")
	case 8883:
		values = append(values, "mqtt", "tls")
	case 1883:
		values = append(values, "mqtt")
	case 5683:
		values = append(values, "coap")
	}

	return values
}

func suspiciousPatternSummary(patterns []string) string {
	if len(patterns) == 0 {
		return ""
	}

	const limit = 2
	if len(patterns) > limit {
		patterns = patterns[:limit]
	}
	return strings.Join(patterns, " | ")
}

func formatBaselineMessage(base, suspicious, riskSignals string) string {
	msg := base
	if suspicious != "" {
		msg += " | suspicious: " + suspicious
	}
	if riskSignals != "" {
		msg += " | risk: " + riskSignals
	}
	return msg
}

func collectRiskSignals(baseline knowledge.CategoryBehaviorBaseline, ctx *Context, commType, host, path string, isExternal bool, representativeDomains []string) []string {
	signals := make([]string, 0, 4)

	if isExternal && !ctx.TLS && baseline.PlaintextTolerance == "low" {
		signals = append(signals, "plaintext_external")
	}

	if indicators, hasAdmin := DetectHTTPAdminIndicators(ctx.HTTP); hasAdmin && isExternal && !baseline.LocalAdminExpected {
		_ = indicators
		signals = append(signals, "unexpected_external_admin")
	}

	if commType != "" && isExternal && !matchesExpectedProtocol(baseline.ExpectedProtocols, ctx) {
		signals = append(signals, "protocol_mismatch")
	}

	if (commType == "analytics" || commType == "tracking" || commType == "cloud_api") && host != "" && isExternal {
		if len(representativeDomains) > 0 && !hostMatchesRepresentativeDomains(host, representativeDomains) {
			signals = append(signals, "unexpected_domain")
		}
	}

	if path != "" && (strings.Contains(path, "/admin") || strings.Contains(path, "/login") || strings.Contains(path, "/setup")) {
		signals = append(signals, "admin_like_path")
	}

	return uniqueStrings(signals)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
