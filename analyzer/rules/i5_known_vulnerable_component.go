package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I5KnownVulnerableComponentRule struct {
	db *knowledge.DB
}

func NewI5KnownVulnerableComponentRule(db *knowledge.DB) *I5KnownVulnerableComponentRule {
	return &I5KnownVulnerableComponentRule{db: db}
}

func (r *I5KnownVulnerableComponentRule) ID() string {
	return "I5_KNOWN_VULNERABLE_COMPONENT"
}
func (r *I5KnownVulnerableComponentRule) Category() string   { return "I5" }
func (r *I5KnownVulnerableComponentRule) Severity() Severity { return SeverityWarning }
func (r *I5KnownVulnerableComponentRule) Type() string {
	return "I5_KNOWN_VULNERABLE_COMPONENT"
}

func (r *I5KnownVulnerableComponentRule) Apply(ctx *Context) (Match, bool) {
	matches := r.ApplyAll(ctx)
	if len(matches) == 0 {
		return Match{}, false
	}
	return matches[0], true
}

func (r *I5KnownVulnerableComponentRule) ApplyAll(ctx *Context) []Match {
	if r == nil || r.db == nil || r.db.I5Vulnerable == nil || ctx == nil {
		return nil
	}

	for _, component := range *r.db.I5Vulnerable {
		signals := matchI5VulnerableComponent(ctx, component)
		if len(signals) == 0 {
			continue
		}

		return []Match{formatI5KnownVulnerableComponentMatch(ctx, component, signals)}
	}

	return nil
}

func matchI5VulnerableComponent(ctx *Context, component knowledge.I5VulnerableComponent) []string {
	if ctx == nil {
		return nil
	}

	signals := make([]string, 0, 6)

	categoryMatched := i5CategoryMatches(ctx, component.Category)
	if categoryMatched {
		signals = append(signals, "category="+strings.TrimSpace(component.Category))
	}

	vendorMatched := i5VendorMatches(ctx.VendorCandidate, component)
	if vendorMatched {
		signals = append(signals, "vendor_candidate="+strings.TrimSpace(ctx.VendorCandidate))
	}

	familyMatched := i5FamilyMatches(ctx.FamilyCandidate, component.Family)
	if familyMatched {
		signals = append(signals, "family_candidate="+strings.TrimSpace(ctx.FamilyCandidate))
	}

	host := i5HTTPHeader(ctx.HTTP, "host")
	if i5AnyKeywordContains(host, component.MatchSignals.HostKeywords) {
		signals = append(signals, "http_host="+strings.TrimSpace(host))
	}

	ua := i5HTTPHeader(ctx.HTTP, "user-agent")
	if i5AnyKeywordContains(ua, component.MatchSignals.UAKeywords) {
		signals = append(signals, "http_user_agent="+strings.TrimSpace(ua))
	}

	sni := ""
	if ctx.TLSInfo != nil {
		sni = ctx.TLSInfo.SNI
	}
	if i5AnyKeywordContains(sni, component.MatchSignals.SNIKeywords) {
		signals = append(signals, "tls_sni="+strings.TrimSpace(sni))
	}

	networkMatched := len(signals) > 0 && i5HasNetworkSignal(signals)
	switch {
	case familyMatched && (categoryMatched || vendorMatched || networkMatched):
		return signals
	case vendorMatched && categoryMatched && networkMatched:
		return signals
	case categoryMatched && i5NetworkSignalCount(signals) >= 2:
		return signals
	default:
		return nil
	}
}

func i5CategoryMatches(ctx *Context, category string) bool {
	want := i5NormalizeValue(category)
	if want == "" {
		return false
	}
	for _, candidate := range []string{
		ctx.LocalDeviceCategory,
		ctx.FlowDeviceCategory,
		ctx.DeviceCategory,
	} {
		if i5NormalizeValue(candidate) == want {
			return true
		}
	}
	return false
}

func i5VendorMatches(vendorCandidate string, component knowledge.I5VulnerableComponent) bool {
	candidate := i5NormalizeValue(vendorCandidate)
	if candidate == "" {
		return false
	}

	if i5NormalizeValue(component.Vendor) == candidate {
		return true
	}
	return i5AnyKeywordContains(vendorCandidate, component.MatchSignals.VendorKeywords)
}

func i5FamilyMatches(familyCandidate, family string) bool {
	candidate := i5NormalizeValue(familyCandidate)
	want := i5NormalizeValue(family)
	if candidate == "" || want == "" {
		return false
	}

	return candidate == want || strings.Contains(candidate, want)
}

func i5HTTPHeader(info *HTTPInfo, name string) string {
	if info == nil || info.Headers == nil {
		return ""
	}
	return info.Headers[strings.ToLower(name)]
}

func i5AnyKeywordContains(value string, keywords []string) bool {
	normalizedValue := i5NormalizeValue(value)
	if normalizedValue == "" {
		return false
	}
	for _, keyword := range keywords {
		normalizedKeyword := i5NormalizeValue(keyword)
		if normalizedKeyword != "" && strings.Contains(normalizedValue, normalizedKeyword) {
			return true
		}
	}
	return false
}

func i5HasNetworkSignal(signals []string) bool {
	return i5NetworkSignalCount(signals) > 0
}

func i5NetworkSignalCount(signals []string) int {
	count := 0
	for _, signal := range signals {
		if strings.HasPrefix(signal, "http_host=") ||
			strings.HasPrefix(signal, "http_user_agent=") ||
			strings.HasPrefix(signal, "tls_sni=") {
			count++
		}
	}
	return count
}

func i5NormalizeValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func formatI5KnownVulnerableComponentMatch(ctx *Context, component knowledge.I5VulnerableComponent, signals []string) Match {
	recommendation := strings.Join(component.Recommendation, " | ")
	if recommendation == "" {
		recommendation = "review component version and vendor support status"
	}

	knownIssues := strings.Join(component.KnownIssues, " | ")
	if knownIssues == "" {
		knownIssues = "known vulnerable component family match"
	}

	return Match{
		RuleID:   "I5_KNOWN_VULNERABLE_COMPONENT",
		Type:     "I5_KNOWN_VULNERABLE_COMPONENT",
		Category: "I5",
		Severity: i5Severity(component.Severity),
		Message:  "Device appears to match a known vulnerable component family in local knowledge",
		Evidence: fmt.Sprintf(
			"knowledge_id=%s category=%s vendor=%s family=%s context_category=%s vendor_candidate=%s family_candidate=%s matched_signals=%s known_issues=%s representative_cves=%s knowledge_severity=%s recommendation=%s applicability=unconfirmed",
			strings.TrimSpace(component.ID),
			strings.TrimSpace(component.Category),
			strings.TrimSpace(component.Vendor),
			strings.TrimSpace(component.Family),
			i5BestContextCategory(ctx),
			strings.TrimSpace(ctx.VendorCandidate),
			strings.TrimSpace(ctx.FamilyCandidate),
			strings.Join(signals, ","),
			knownIssues,
			strings.Join(component.RepresentativeCVEs, ","),
			strings.TrimSpace(component.Severity),
			recommendation,
		),
	}
}

func i5Severity(severity string) Severity {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return SeverityCritical
	default:
		return SeverityWarning
	}
}

func i5BestContextCategory(ctx *Context) string {
	if ctx == nil {
		return ""
	}
	for _, category := range []string{
		ctx.LocalDeviceCategory,
		ctx.FlowDeviceCategory,
		ctx.DeviceCategory,
	} {
		if strings.TrimSpace(category) != "" {
			return strings.TrimSpace(category)
		}
	}
	return ""
}
