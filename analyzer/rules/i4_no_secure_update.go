package rules

import (
	"fmt"
	"strings"
)

type I4LikelyNoSecureUpdateMechanismRule struct{}

func (r *I4LikelyNoSecureUpdateMechanismRule) ID() string {
	return "I4_WEAK_UPDATE_VISIBILITY"
}
func (r *I4LikelyNoSecureUpdateMechanismRule) Category() string   { return "I4" }
func (r *I4LikelyNoSecureUpdateMechanismRule) Severity() Severity { return SeverityWarning }
func (r *I4LikelyNoSecureUpdateMechanismRule) Type() string {
	return "I4_WEAK_UPDATE_VISIBILITY"
}

func (r *I4LikelyNoSecureUpdateMechanismRule) Apply(ctx *Context) (Match, bool) {
	evaluation := evaluateI4NoSecureUpdate(ctx)
	if !evaluation.likely {
		return Match{}, false
	}

	return Match{
		RuleID:         "I4_WEAK_UPDATE_VISIBILITY",
		Type:           "I4_WEAK_UPDATE_VISIBILITY",
		Category:       "I4",
		Severity:       SeverityWarning,
		Message:        "No update signal was observed, and legacy network signals suggest update-mechanism risk.",
		Evidence:       formatI4NoSecureUpdateEvidence(ctx, evaluation.legacySignals, evaluation.basis),
		OWASPTags:      uniqueTags("I4"),
		Confidence:     "low",
		ObservedFact:   "No update activity was observed for this device context, while legacy service signals were present.",
		Inference:      "This may indicate weak update visibility or a higher chance that secure update practices are absent or difficult to verify.",
		Limitation:     "Passive monitoring does not prove that the device lacks signature verification, rollback protection, or any secure update mechanism.",
		Recommendation: "Review vendor documentation, firmware menus, and support advisories to confirm how updates are delivered and verified.",
	}, true
}

type i4NoSecureUpdateEvaluation struct {
	likely        bool
	legacySignals []string
	basis         []string
	score         int
}

func evaluateI4NoSecureUpdate(ctx *Context) i4NoSecureUpdateEvaluation {
	if ctx == nil {
		return i4NoSecureUpdateEvaluation{}
	}
	if strings.TrimSpace(ctx.UpdateVisibility) != "not_seen" {
		return i4NoSecureUpdateEvaluation{}
	}

	legacySignals := dedupeOrderedStrings(normalizeI4LegacySignals(ctx.LegacySignals))
	if len(legacySignals) == 0 {
		return i4NoSecureUpdateEvaluation{}
	}

	score, basis := scoreI4NoSecureUpdateSignals(legacySignals)
	return i4NoSecureUpdateEvaluation{
		likely:        score >= 2,
		legacySignals: legacySignals,
		basis:         basis,
		score:         score,
	}
}

func normalizeI4LegacySignals(signals []string) []string {
	out := normalizedNonEmptyStrings(signals)
	for i := range out {
		out[i] = strings.ToLower(out[i])
	}
	return out
}

func scoreI4NoSecureUpdateSignals(signals []string) (int, []string) {
	score := 0
	basis := make([]string, 0, len(signals)+1)
	for _, signal := range signals {
		switch signal {
		case "telnet_observed", "ftp_observed", "external_exposure", "http_only_management":
			score += 2
			basis = append(basis, "strong_legacy_signal="+signal)
		case "admin_interface":
			score++
			basis = append(basis, "supporting_legacy_signal="+signal)
		}
	}
	if score > 0 {
		basis = append(basis, fmt.Sprintf("score=%d", score))
	}
	return score, basis
}

func formatI4NoSecureUpdateEvidence(ctx *Context, legacySignals, basis []string) string {
	recommendedChecks := []string{
		"review admin interface for firmware update controls",
		"review vendor documentation for secure update support",
		"confirm whether updates are delivered only via cloud-managed channels",
	}

	return fmt.Sprintf(
		"category=%s vendor_candidate=%s family_candidate=%s legacy_signals=%s basis=%s recommended_checks=%s",
		i4NoSecureUpdateCategory(ctx),
		strings.TrimSpace(ctx.VendorCandidate),
		strings.TrimSpace(ctx.FamilyCandidate),
		strings.Join(legacySignals, ","),
		strings.Join(basis, ","),
		strings.Join(recommendedChecks, " | "),
	)
}

func i4NoSecureUpdateCategory(ctx *Context) string {
	if ctx == nil {
		return ""
	}
	for _, category := range []string{ctx.LocalDeviceCategory, ctx.DeviceCategory, ctx.FlowDeviceCategory} {
		category = strings.TrimSpace(category)
		if category != "" {
			return category
		}
	}
	return ""
}

func init() {
	Register(&I4LikelyNoSecureUpdateMechanismRule{})
}
