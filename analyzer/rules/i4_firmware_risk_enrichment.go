package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I4FirmwareRiskEnrichmentRule struct {
	db *knowledge.DB
}

func NewI4FirmwareRiskEnrichmentRule(db *knowledge.DB) *I4FirmwareRiskEnrichmentRule {
	return &I4FirmwareRiskEnrichmentRule{db: db}
}

func (r *I4FirmwareRiskEnrichmentRule) ID() string         { return "I4_FIRMWARE_RISK_ENRICHMENT" }
func (r *I4FirmwareRiskEnrichmentRule) Category() string   { return "I4" }
func (r *I4FirmwareRiskEnrichmentRule) Severity() Severity { return SeverityInfo }
func (r *I4FirmwareRiskEnrichmentRule) Type() string       { return "I4_FIRMWARE_RISK_ENRICHMENT" }

func (r *I4FirmwareRiskEnrichmentRule) Apply(ctx *Context) (Match, bool) {
	matches := r.ApplyAll(ctx)
	if len(matches) == 0 {
		return Match{}, false
	}
	return matches[0], true
}

func (r *I4FirmwareRiskEnrichmentRule) ApplyAll(ctx *Context) []Match {
	if r.db == nil || r.db.I4KnownVuln == nil || ctx == nil {
		return nil
	}
	if ctx.HTTP == nil && ctx.TLSInfo == nil {
		return nil
	}
	if !isI4EnrichmentCategory(ctx.LocalDeviceCategory) {
		return nil
	}
	if !isI4HighConfidenceLocalFingerprint(ctx) {
		return nil
	}

	vendorCandidate := strings.TrimSpace(ctx.VendorCandidate)
	familyCandidate := strings.TrimSpace(ctx.FamilyCandidate)
	if vendorCandidate == "" || familyCandidate == "" {
		return nil
	}

	match, ok := matchI4KnownVulnCandidate(
		r.db.I4KnownVuln.Candidates,
		ctx.LocalDeviceCategory,
		vendorCandidate,
		familyCandidate,
	)
	if !ok {
		return nil
	}

	recommendedChecks := strings.Join(match.RecommendedChecks, " | ")
	if strings.TrimSpace(recommendedChecks) == "" {
		recommendedChecks = "review firmware version and vendor support status"
	}

	return []Match{
		{
			RuleID:   "I4_FIRMWARE_RISK_ENRICHMENT",
			Type:     "I4_FIRMWARE_RISK_ENRICHMENT",
			Category: "I4",
			Severity: SeverityInfo,
			Message:  "Known issues have been reported in this device family; example CVEs are provided for review, but firmware version is unknown and applicability is unconfirmed",
			Evidence: fmt.Sprintf(
				"category=%s vendor_candidate=%s family_candidate=%s matched_family=%s example_cves=%s kev=%t version_status=unknown applicability=unconfirmed recommended_checks=%s notes=%s",
				ctx.LocalDeviceCategory,
				vendorCandidate,
				familyCandidate,
				match.Family,
				strings.Join(match.ExampleCVEs, ","),
				match.KEV,
				recommendedChecks,
				strings.TrimSpace(match.Notes),
			),
		},
	}
}

func isI4EnrichmentCategory(category string) bool {
	switch strings.TrimSpace(category) {
	case "Camera", "Hub", "Router", "Appliance", "NAS", "NVR":
		return true
	default:
		return false
	}
}

func isI4HighConfidenceLocalFingerprint(ctx *Context) bool {
	if ctx == nil {
		return false
	}
	if strings.TrimSpace(ctx.LocalInferenceSource) != "known" {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(ctx.LocalInferenceConfidence), "strong(")
}

func matchI4KnownVulnCandidate(candidates []knowledge.I4KnownVulnCandidate, category, vendorCandidate, familyCandidate string) (*knowledge.I4KnownVulnCandidate, bool) {
	normalizedCategory := normalizeI4MatchValue(category)
	normalizedVendor := normalizeI4MatchValue(vendorCandidate)
	normalizedFamily := normalizeI4MatchValue(familyCandidate)

	for _, candidate := range candidates {
		if !containsNormalizedI4Value(candidate.Categories, normalizedCategory) {
			continue
		}
		if !matchesI4Vendor(candidate, normalizedVendor) {
			continue
		}
		if !matchesI4Family(candidate, normalizedFamily) {
			continue
		}

		matched := candidate
		return &matched, true
	}

	return nil, false
}

func matchesI4Vendor(candidate knowledge.I4KnownVulnCandidate, vendor string) bool {
	if vendor == "" {
		return false
	}

	values := make([]string, 0, 1+len(candidate.VendorAliases))
	values = append(values, candidate.Vendor)
	values = append(values, candidate.VendorAliases...)
	return containsNormalizedI4Value(values, vendor)
}

func matchesI4Family(candidate knowledge.I4KnownVulnCandidate, family string) bool {
	if family == "" {
		return false
	}

	values := make([]string, 0, 1+len(candidate.Aliases))
	values = append(values, candidate.Family)
	values = append(values, candidate.Aliases...)
	return containsNormalizedI4Value(values, family)
}

func containsNormalizedI4Value(values []string, want string) bool {
	if want == "" {
		return false
	}
	for _, value := range values {
		if normalizeI4MatchValue(value) == want {
			return true
		}
	}
	return false
}

func normalizeI4MatchValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
