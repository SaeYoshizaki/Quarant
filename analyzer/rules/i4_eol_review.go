package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I4EOLReviewRule struct {
	db *knowledge.DB
}

func NewI4EOLReviewRule(db *knowledge.DB) *I4EOLReviewRule {
	return &I4EOLReviewRule{db: db}
}

func (r *I4EOLReviewRule) ApplyAll(ctx *Context) []Match {
	if r.db == nil || ctx == nil {
		return nil
	}

	eol := evaluateI4EOL(r.db, ctx)
	if !eol.valid {
		return nil
	}

	if !eol.likely {
		return []Match{{
			RuleID:         "I4_MAYBE_EOL_DEVICE",
			Type:           "I4_MAYBE_EOL_DEVICE",
			Category:       "I4",
			Severity:       SeverityInfo,
			Message:        "This device may be beyond a typical support lifecycle; review firmware support status and update availability.",
			Evidence:       formatI4EOLEvidence(ctx, eol.updateVisibility, eol.legacySignals, eol.basis),
			OWASPTags:      uniqueTags("I4"),
			Confidence:     "low",
			ObservedFact:   "Lifecycle-related update visibility signals were weak or incomplete.",
			Inference:      "The device may be approaching the end of normal support, which can increase update risk.",
			Limitation:     "Passive monitoring does not confirm the actual support contract, release policy, or installed firmware version.",
			Recommendation: "Review firmware version and vendor lifecycle notices for the exact device model.",
		}}
	}

	return []Match{{
		RuleID:         "I4_LIKELY_EOL_DEVICE",
		Type:           "I4_LIKELY_EOL_DEVICE",
		Category:       "I4",
		Severity:       SeverityWarning,
		Message:        "This device appears likely to be beyond a typical support lifecycle; review vendor support status and firmware update availability.",
		Evidence:       formatI4EOLEvidence(ctx, eol.updateVisibility, eol.legacySignals, eol.basis),
		OWASPTags:      uniqueTags("I4"),
		Confidence:     "medium",
		ObservedFact:   "Update visibility was absent or weak while lifecycle-related legacy signals were present.",
		Inference:      "The device may have reduced update support, which can increase the chance that known issues remain unpatched.",
		Limitation:     "Passive monitoring does not prove that the device is end-of-life or that no updates remain available.",
		Recommendation: "Review firmware version, vendor lifecycle notices, and replacement planning for the exact model.",
	}}
}

type i4EOLEvaluation struct {
	valid            bool
	likely           bool
	updateVisibility string
	legacySignals    []string
	basis            []string
}

func evaluateI4EOL(db *knowledge.DB, ctx *Context) i4EOLEvaluation {
	if db == nil || ctx == nil {
		return i4EOLEvaluation{}
	}
	if !isI4EnrichmentCategory(ctx.LocalDeviceCategory) {
		return i4EOLEvaluation{}
	}
	if !isI4HighConfidenceLocalFingerprint(ctx) {
		return i4EOLEvaluation{}
	}

	updateVisibility := strings.TrimSpace(ctx.UpdateVisibility)
	if updateVisibility == "" {
		updateVisibility = "unknown"
	}
	if updateVisibility == "seen" {
		return i4EOLEvaluation{}
	}

	legacySignals := normalizedNonEmptyStrings(ctx.LegacySignals)
	if matchedFamilyForI4KnownIssues(db, ctx) {
		legacySignals = append(legacySignals, "known_issues_family")
	}
	legacySignals = dedupeOrderedStrings(legacySignals)
	if len(legacySignals) == 0 {
		return i4EOLEvaluation{}
	}

	basis := []string{
		"high_confidence_local_fingerprint",
		"support_lifecycle_hint=5-7y",
		"update_visibility=" + updateVisibility,
	}

	likely := shouldEmitLikelyEOL(updateVisibility, legacySignals)
	if likely {
		basis = append(basis, classifyI4EOLBasis(updateVisibility, legacySignals, true)...)
	} else {
		basis = append(basis, classifyI4EOLBasis(updateVisibility, legacySignals, false)...)
	}

	return i4EOLEvaluation{
		valid:            true,
		likely:           likely,
		updateVisibility: updateVisibility,
		legacySignals:    legacySignals,
		basis:            basis,
	}
}

func matchedFamilyForI4KnownIssues(db *knowledge.DB, ctx *Context) bool {
	if db == nil || db.I4KnownVuln == nil || ctx == nil {
		return false
	}
	_, ok := matchI4KnownVulnCandidate(
		db.I4KnownVuln.Candidates,
		ctx.LocalDeviceCategory,
		strings.TrimSpace(ctx.VendorCandidate),
		strings.TrimSpace(ctx.FamilyCandidate),
	)
	return ok
}

func shouldEmitLikelyEOL(updateVisibility string, legacySignals []string) bool {
	if updateVisibility != "not_seen" {
		return false
	}
	return hasStrongI4LegacySignal(legacySignals) || len(legacySignals) >= 2
}

func hasStrongI4LegacySignal(signals []string) bool {
	for _, signal := range signals {
		switch signal {
		case "telnet_observed", "ftp_observed", "external_exposure":
			return true
		}
	}
	return false
}

func classifyI4EOLBasis(updateVisibility string, legacySignals []string, likely bool) []string {
	if likely {
		if hasStrongI4LegacySignal(legacySignals) {
			return []string{"strong_legacy_signal"}
		}
		return []string{"multiple_legacy_signals"}
	}
	if updateVisibility == "unknown" {
		return []string{"legacy_signal_present_with_unknown_update_visibility"}
	}
	return []string{"legacy_signal_present_with_no_update_visibility"}
}

func formatI4EOLEvidence(ctx *Context, updateVisibility string, legacySignals, basis []string) string {
	recommendedChecks := []string{
		"review firmware version and latest available update",
		"review vendor support status and lifecycle notice",
	}
	if strings.TrimSpace(ctx.FamilyCandidate) != "" {
		recommendedChecks = append(recommendedChecks, "confirm exact model generation in the admin interface")
	}

	return fmt.Sprintf(
		"category=%s vendor_candidate=%s family_candidate=%s support_lifecycle_hint=5-7y update_visibility=%s legacy_signals=%s basis=%s recommended_checks=%s",
		ctx.LocalDeviceCategory,
		strings.TrimSpace(ctx.VendorCandidate),
		strings.TrimSpace(ctx.FamilyCandidate),
		updateVisibility,
		strings.Join(legacySignals, ","),
		strings.Join(basis, ","),
		strings.Join(recommendedChecks, " | "),
	)
}

func normalizedNonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

func dedupeOrderedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
