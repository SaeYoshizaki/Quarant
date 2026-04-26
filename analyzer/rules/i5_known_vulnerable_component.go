package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I5KnownVulnerableComponentRule struct {
	db *knowledge.DB
}

type i5ComponentMatch struct {
	component   knowledge.I5VulnerableComponent
	signals     []string
	matchBasis  []string
	score       int
	keywordHits int
}

func NewI5KnownVulnerableComponentRule(db *knowledge.DB) *I5KnownVulnerableComponentRule {
	return &I5KnownVulnerableComponentRule{db: db}
}

func (r *I5KnownVulnerableComponentRule) ID() string {
	return "I5_KNOWN_VULNERABLE_COMPONENT"
}

func (r *I5KnownVulnerableComponentRule) Category() string { return "I5" }

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

	best := findBestI5VulnerableComponent(r.db, ctx)
	if best == nil {
		return nil
	}

	return []Match{
		formatI5KnownVulnerableComponentMatch(
			ctx,
			best.component,
			best.signals,
			best.matchBasis,
		),
	}
}

func findBestI5VulnerableComponent(db *knowledge.DB, ctx *Context) *i5ComponentMatch {
	if db == nil || db.I5Vulnerable == nil || ctx == nil {
		return nil
	}

	var best *i5ComponentMatch
	for _, component := range *db.I5Vulnerable {
		match, ok := matchI5VulnerableComponent(ctx, component)
		if !ok {
			continue
		}
		if best == nil || i5BetterMatch(match, *best) {
			best = &match
		}
	}

	return best
}

func matchI5VulnerableComponent(ctx *Context, component knowledge.I5VulnerableComponent) (i5ComponentMatch, bool) {
	if ctx == nil {
		return i5ComponentMatch{}, false
	}

	signals := make([]string, 0, 8)
	basis := make([]string, 0, 4)
	keywordHits := 0

	categoryMatched := i5CategoryMatches(ctx, component.Category)
	if categoryMatched {
		signals = append(signals, "category="+strings.TrimSpace(component.Category))
	}

	vendorMatched := i5VendorMatches(ctx.VendorCandidate, component.Vendor)
	if vendorMatched {
		signals = append(signals, "vendor_candidate="+strings.TrimSpace(ctx.VendorCandidate))
	}

	familyMatched := i5FamilyMatches(ctx.FamilyCandidate, component.Family)
	if familyMatched {
		signals = append(signals, "family_candidate="+strings.TrimSpace(ctx.FamilyCandidate))
	}

	host, hostMatched := i5FirstKeywordMatch(i5HostValues(ctx), component.MatchSignals.HostKeywords)
	if hostMatched {
		signals = append(signals, "http_host="+strings.TrimSpace(host))
		basis = append(basis, "vendor+category+host_keyword")
		keywordHits++
	}

	ua, uaMatched := i5FirstKeywordMatch(i5UserAgentValues(ctx), component.MatchSignals.UAKeywords)
	if uaMatched {
		signals = append(signals, "http_user_agent="+strings.TrimSpace(ua))
		basis = append(basis, "vendor+category+ua_keyword")
		keywordHits++
	}

	sni, sniMatched := i5FirstKeywordMatch(i5SNIValues(ctx), component.MatchSignals.SNIKeywords)
	if sniMatched {
		signals = append(signals, "tls_sni="+strings.TrimSpace(sni))
		basis = append(basis, "vendor+category+sni_keyword")
		keywordHits++
	}

	vendorKeywordValue, vendorKeywordMatched := i5VendorKeywordMatches(ctx, component.MatchSignals.VendorKeywords)
	if vendorKeywordMatched {
		signals = append(signals, "vendor_keyword="+strings.TrimSpace(vendorKeywordValue))
		basis = append(basis, "vendor+category+vendor_keyword")
		keywordHits++
	}

	keywordMatched := keywordHits > 0

	if familyMatched && (categoryMatched || vendorMatched || keywordMatched) {
		return i5ComponentMatch{
			component:   component,
			signals:     signals,
			matchBasis:  []string{"family"},
			score:       1000 + keywordHits,
			keywordHits: keywordHits,
		}, true
	}

	if categoryMatched && vendorMatched && keywordMatched {
		return i5ComponentMatch{
			component:   component,
			signals:     signals,
			matchBasis:  i5PrimaryMatchBasis(basis),
			score:       500 + keywordHits,
			keywordHits: keywordHits,
		}, true
	}

	return i5ComponentMatch{}, false
}

func i5BetterMatch(candidate, current i5ComponentMatch) bool {
	if candidate.score != current.score {
		return candidate.score > current.score
	}
	return candidate.keywordHits > current.keywordHits
}

func i5PrimaryMatchBasis(basis []string) []string {
	if len(basis) == 0 {
		return nil
	}
	return []string{basis[0]}
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

func i5VendorMatches(vendorCandidate, vendor string) bool {
	candidate := i5NormalizeValue(vendorCandidate)
	want := i5NormalizeValue(vendor)
	if candidate == "" || want == "" {
		return false
	}

	return candidate == want || strings.Contains(candidate, want) || strings.Contains(want, candidate)
}

func i5FamilyMatches(familyCandidate, family string) bool {
	candidate := i5NormalizeValue(familyCandidate)
	want := i5NormalizeValue(family)
	if candidate == "" || want == "" {
		return false
	}

	return candidate == want
}

func i5HTTPHeader(info *HTTPInfo, name string) string {
	if info == nil || info.Headers == nil {
		return ""
	}

	key := strings.ToLower(name)
	if value, ok := info.Headers[key]; ok {
		return value
	}

	for headerName, value := range info.Headers {
		if strings.EqualFold(headerName, name) {
			return value
		}
	}

	return ""
}

func i5HTTPHost(info *HTTPInfo) string {
	return i5HTTPHeader(info, "host")
}

func i5HTTPUserAgent(info *HTTPInfo) string {
	return i5HTTPHeader(info, "user-agent")
}

func i5HostValues(ctx *Context) []string {
	if ctx == nil {
		return nil
	}

	values := []string{
		i5HTTPHost(ctx.HTTP),
	}
	values = append(values, ctx.ObservedHosts...)

	return i5CompactValues(values)
}

func i5UserAgentValues(ctx *Context) []string {
	if ctx == nil {
		return nil
	}

	values := []string{
		i5HTTPUserAgent(ctx.HTTP),
	}
	values = append(values, ctx.ObservedUserAgents...)

	return i5CompactValues(values)
}

func i5SNIValues(ctx *Context) []string {
	if ctx == nil {
		return nil
	}

	values := make([]string, 0, 1+len(ctx.ObservedSNIValues))
	if ctx.TLSInfo != nil {
		values = append(values, ctx.TLSInfo.SNI)
	}
	values = append(values, ctx.ObservedSNIValues...)

	return i5CompactValues(values)
}

func i5CompactValues(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}

	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		normalized := i5NormalizeValue(trimmed)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, trimmed)
	}

	return out
}

func i5FirstKeywordMatch(values []string, keywords []string) (string, bool) {
	for _, value := range values {
		if i5AnyKeywordContains(value, keywords) {
			return value, true
		}
	}
	return "", false
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

func i5VendorKeywordMatches(ctx *Context, keywords []string) (string, bool) {
	if ctx == nil {
		return "", false
	}

	for _, value := range []string{
		ctx.VendorCandidate,
		ctx.FamilyCandidate,
	} {
		if i5AnyKeywordContains(value, keywords) {
			return value, true
		}
	}

	if value, ok := i5FirstKeywordMatch(i5HostValues(ctx), keywords); ok {
		return value, true
	}
	if value, ok := i5FirstKeywordMatch(i5UserAgentValues(ctx), keywords); ok {
		return value, true
	}
	if value, ok := i5FirstKeywordMatch(i5SNIValues(ctx), keywords); ok {
		return value, true
	}

	return "", false
}

func i5NormalizeValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func formatI5KnownVulnerableComponentMatch(
	ctx *Context,
	component knowledge.I5VulnerableComponent,
	signals []string,
	matchBasis []string,
) Match {
	recommendation := strings.Join(component.Recommendation, " | ")
	if recommendation == "" {
		recommendation = "Confirm the exact model and firmware version. Check vendor advisories and apply firmware updates."
	}

	knownIssues := strings.Join(component.KnownIssues, " | ")
	if knownIssues == "" {
		knownIssues = "known vulnerable family candidate in local knowledge"
	}

	matchLevel := strings.TrimSpace(component.MatchLevel)
	if matchLevel == "" {
		matchLevel = "family_candidate"
	}

	return Match{
		RuleID:   "I5_KNOWN_VULNERABLE_COMPONENT",
		Type:     "I5_KNOWN_VULNERABLE_COMPONENT",
		Category: "I5",
		Severity: i5Severity(component.Severity),
		Message:  "Traffic characteristics match a known vulnerable family or component candidate in local knowledge.",
		Evidence: fmt.Sprintf(
			"knowledge_id=%s matched_component_id=%s match_basis=%s match_level=%s category=%s vendor=%s family=%s context_category=%s vendor_candidate=%s family_candidate=%s matched_signals=%s known_issues=%s representative_cves=%s knowledge_severity=%s source=%s last_reviewed=%s recommendation=%s applicability=unconfirmed",
			strings.TrimSpace(component.ID),
			strings.TrimSpace(component.ID),
			strings.Join(matchBasis, ","),
			matchLevel,
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
			strings.TrimSpace(component.Source),
			strings.TrimSpace(component.LastReviewed),
			recommendation,
		),
		OWASPTags:      uniqueTags("I5"),
		Confidence:     "low",
		ObservedFact:   "Observed identification signals matched a device family or component candidate in the local vulnerability knowledge base.",
		Inference:      "The device may belong to a family with known historical vulnerabilities, so firmware and support status should be reviewed.",
		Limitation:     "Passive monitoring cannot confirm the exact model, firmware version, internal component list, or whether a specific CVE applies.",
		Recommendation: strings.ReplaceAll(recommendation, " | ", " "),
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
