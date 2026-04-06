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
	matches := r.ApplyAll(ctx)
	if len(matches) == 0 {
		return Match{}, false
	}
	return matches[0], true
}

func (r *I6PrivacyRule) ApplyAll(ctx *Context) []Match {
	if r.db == nil || ctx == nil || ctx.HTTP == nil {
		return nil
	}

	commType := DetectCommunicationType(ctx.HTTP)
	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = "unknown"
	}

	out := make([]Match, 0, 4)

	if mismatch := r.applyCategoryMismatch(ctx); mismatch != nil {
		out = append(out, *mismatch)
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		out = append(out, r.applyBehaviorBaselineAll(ctx, category, commType)...)
	}

	if commType == "" {
		return out
	}

	hits := DetectPIIHits(ctx.HTTP, ctx.Payload)
	if len(hits) == 0 {
		return out
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		for _, hit := range hits {
			if r.db.IsSuspiciousCombination(category, commType, hit.Type) {
				out = append(out, Match{
					RuleID:   "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Type:     "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Privacy-related information violates device category policy",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				})
			}
		}

		if !r.db.IsAllowedCommunicationType(category, commType) {
			hit := hits[0]
			out = append(out, Match{
				RuleID:   "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Type:     "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in unexpected communication type",
				Evidence: fmt.Sprintf(
					"category=%s comm_type=%s pii_type=%s source=%s %s",
					category, commType, hit.Type, hit.Source, hit.Evidence,
				),
			})
		}

		for _, hit := range hits {
			if !r.db.IsAllowedPIIType(category, hit.Type) {
				out = append(out, Match{
					RuleID:   "I6_HTTP_UNEXPECTED_PII",
					Type:     "I6_HTTP_UNEXPECTED_PII",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Unexpected privacy-related information observed for device category",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				})
			}
		}

		return dedupeMatches(out)
	}

	for _, hit := range hits {
		if commType == "analytics" || commType == "tracking" {
			out = append(out, Match{
				RuleID:   "I6_HTTP_PRIVACY_EXPOSURE",
				Type:     "I6_HTTP_PRIVACY_EXPOSURE",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in suspicious HTTP communication",
				Evidence: fmt.Sprintf(
					"comm_type=%s pii_type=%s source=%s %s category=%s",
					commType, hit.Type, hit.Source, hit.Evidence, category,
				),
			})
		}
	}

	return dedupeMatches(out)
}

func (r *I6PrivacyRule) applyCategoryMismatch(ctx *Context) *Match {
	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)

	if localCategory == "" || flowCategory == "" {
		return nil
	}
	if localCategory == "GenericIoT" || flowCategory == "GenericIoT" {
		return nil
	}
	if localCategory == flowCategory {
		return nil
	}
	if !r.db.IsKnownCategory(localCategory) || !r.db.IsKnownCategory(flowCategory) {
		return nil
	}

	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	commType := DetectCommunicationType(ctx.HTTP)
	if commType == "" {
		commType = "unknown"
	}
	isExternal := IsPublicIPv4(ctx.DstIP)
	riskSignals := []string{"category_mismatch"}
	riskScoreHint := 15
	if isExternal {
		riskSignals = append(riskSignals, "external_comm")
		riskScoreHint = 25
	}

	localConfidence := ""
	if inference, ok := r.db.GetCategoryInference(localCategory); ok {
		localConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
	}

	flowConfidence := ""
	if inference, ok := r.db.GetCategoryInference(flowCategory); ok {
		flowConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
	}

	return &Match{
		RuleID:   "I6_DEVICE_FLOW_CATEGORY_MISMATCH",
		Type:     "I6_DEVICE_FLOW_CATEGORY_MISMATCH",
		Category: "I6",
		Severity: SeverityWarning,
		Message: fmt.Sprintf(
			"Observed flow category does not match the learned device category | local=%s | flow=%s | comm_type=%s | risk=%s",
			localCategory,
			flowCategory,
			commType,
			strings.Join(riskSignals, ","),
		),
		Evidence: fmt.Sprintf(
			"host=%s local_category=%s flow_category=%s local_confidence=%s flow_confidence=%s path=%s risk_signals=%s risk_score_hint=%d",
			host,
			localCategory,
			flowCategory,
			localConfidence,
			flowConfidence,
			strings.ToLower(strings.TrimSpace(ctx.HTTP.Path)),
			strings.Join(riskSignals, ","),
			riskScoreHint,
		),
	}
}

func (r *I6PrivacyRule) applyBehaviorBaselineAll(ctx *Context, category, commType string) []Match {
	baseline, ok := r.db.GetBehaviorBaseline(category)
	if !ok {
		return nil
	}

	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	path := strings.ToLower(strings.TrimSpace(ctx.HTTP.Path))
	isExternal := IsPublicIPv4(ctx.DstIP)
	suspicious := suspiciousPatternSummary(baseline.SuspiciousPatterns)
	inference, hasInference := r.db.GetCategoryInference(category)
	var representativeDomains []string
	var ecosystemDomains []string
	categoryConfidence := ""
	categoryConfidenceLevel := ""
	if hasInference {
		representativeDomains = inference.RepresentativeDomains
		ecosystemDomains = inference.EcosystemDomains
		categoryConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
		categoryConfidenceLevel = strings.ToLower(strings.TrimSpace(inference.ConfidenceLevel))
	}
	riskSignals := collectRiskSignals(baseline, ctx, commType, host, path, isExternal, representativeDomains, ecosystemDomains, categoryConfidenceLevel)
	riskSummary := strings.Join(riskSignals, ",")
	baselineSeverity, riskScoreHint := classifyBaselineRisk(riskSignals, isExternal)
	out := make([]Match, 0, 4)

	if isExternal && !ctx.TLS && baseline.PlaintextTolerance == "low" {
		out = append(out, Match{
			RuleID:   "I6_HTTP_BASELINE_PLAINTEXT",
			Type:     "I6_HTTP_BASELINE_PLAINTEXT",
			Category: "I6",
			Severity: baselineSeverity,
			Message: formatBaselineMessage(
				"Category baseline expects encrypted external communication",
				suspicious,
				riskSummary,
				categoryConfidence,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_ip=%s dst_port=%d suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
				category, host, ctx.DstIP, ctx.DstPort, suspicious, riskSummary, riskScoreHint, categoryConfidence,
			),
		})
	}

	if indicators, hasAdmin := DetectHTTPAdminIndicators(ctx.HTTP); hasAdmin && isExternal && !baseline.LocalAdminExpected {
		out = append(out, Match{
			RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
			Type:     "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
			Category: "I6",
			Severity: baselineSeverity,
			Message: formatBaselineMessage(
				"Category baseline does not expect external admin-style HTTP access",
				suspicious,
				riskSummary,
				categoryConfidence,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s path=%s indicators=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
				category, host, path, strings.Join(indicators, ","), suspicious, riskSummary, riskScoreHint, categoryConfidence,
			),
		})
	}

	if commType != "" && isExternal && !matchesExpectedProtocol(baseline.ExpectedProtocols, ctx) {
		out = append(out, Match{
			RuleID:   "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Type:     "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Category: "I6",
			Severity: baselineSeverity,
			Message: formatBaselineMessage(
				"Observed protocol usage does not fit the category baseline",
				suspicious,
				riskSummary,
				categoryConfidence,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_port=%d expected_protocols=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
				category, host, ctx.DstPort, strings.Join(baseline.ExpectedProtocols, ","), suspicious, riskSummary, riskScoreHint, categoryConfidence,
			),
		})
	}

	if commType == "analytics" || commType == "tracking" || commType == "cloud_api" {
		if hasInference && host != "" && isExternal && !hostMatchesExpectedDomains(host, representativeDomains, ecosystemDomains) {
			out = append(out, Match{
				RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Type:     "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Category: "I6",
				Severity: baselineSeverity,
				Message: formatBaselineMessage(
					"Observed external domain does not fit the category baseline",
					suspicious,
					riskSummary,
					categoryConfidence,
				),
				Evidence: fmt.Sprintf(
					"category=%s host=%s representative_domains=%s ecosystem_domains=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
					category, host, strings.Join(inference.RepresentativeDomains, ","), strings.Join(inference.EcosystemDomains, ","), suspicious, riskSummary, riskScoreHint, categoryConfidence,
				),
			})
		}
	}

	return dedupeMatches(out)
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

func formatBaselineMessage(base, suspicious, riskSignals, categoryConfidence string) string {
	msg := base
	if suspicious != "" {
		msg += " | suspicious: " + suspicious
	}
	if riskSignals != "" {
		msg += " | risk: " + riskSignals
	}
	if categoryConfidence != "" {
		msg += " | category confidence: " + categoryConfidence
	}
	return msg
}

func collectRiskSignals(baseline knowledge.CategoryBehaviorBaseline, ctx *Context, commType, host, path string, isExternal bool, representativeDomains []string, ecosystemDomains []string, categoryConfidenceLevel string) []string {
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
		if !hostMatchesExpectedDomains(host, representativeDomains, ecosystemDomains) {
			signals = append(signals, "unexpected_domain")
		}
	}

	if path != "" && (strings.Contains(path, "/admin") || strings.Contains(path, "/login") || strings.Contains(path, "/setup")) {
		signals = append(signals, "admin_like_path")
	}

	if categoryConfidenceLevel == "low" {
		signals = append(signals, "category_confidence_low")
	}

	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)
	if localCategory != "" &&
		flowCategory != "" &&
		localCategory != "GenericIoT" &&
		flowCategory != "GenericIoT" &&
		localCategory != flowCategory {
		signals = append(signals, "category_mismatch")
	}

	return uniqueStrings(signals)
}

func hostMatchesExpectedDomains(host string, representativeDomains []string, ecosystemDomains []string) bool {
	if hostMatchesRepresentativeDomains(host, representativeDomains) {
		return true
	}
	if hostMatchesRepresentativeDomains(host, ecosystemDomains) {
		return true
	}
	return false
}

func classifyBaselineRisk(signals []string, isExternal bool) (Severity, int) {
	score := 10
	has := make(map[string]bool, len(signals))
	for _, signal := range signals {
		has[signal] = true
		switch signal {
		case "plaintext_external":
			score += 20
		case "unexpected_external_admin":
			score += 20
		case "unexpected_domain":
			score += 15
		case "category_mismatch":
			score += 15
		case "protocol_mismatch":
			score += 10
		case "admin_like_path":
			score += 10
		case "external_comm":
			score += 5
		case "category_confidence_low":
			score += 5
		}
	}
	if score > 90 {
		score = 90
	}

	critical := false
	if has["unexpected_external_admin"] {
		critical = true
	}
	if has["plaintext_external"] && has["unexpected_domain"] {
		critical = true
	}
	if has["unexpected_domain"] && has["category_mismatch"] && isExternal {
		critical = true
	}
	if score >= 50 {
		critical = true
	}

	if critical {
		return SeverityCritical, score
	}
	return SeverityWarning, score
}

func formatConfidence(score float64, level string) string {
	if level == "" {
		level = "unknown"
	}
	return fmt.Sprintf("%s(%.2f)", level, score)
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

func dedupeMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	seen := make(map[string]struct{}, len(matches))
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		key := m.RuleID + "|" + m.Type + "|" + m.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}
