package rules

import (
	"fmt"
	"strings"
)

type I4LikelyNoSecureUpdateMechanismRule struct{}

func (r *I4LikelyNoSecureUpdateMechanismRule) ID() string {
	return "I4_LIKELY_NO_SECURE_UPDATE_MECHANISM"
}
func (r *I4LikelyNoSecureUpdateMechanismRule) Category() string   { return "I4" }
func (r *I4LikelyNoSecureUpdateMechanismRule) Severity() Severity { return SeverityWarning }
func (r *I4LikelyNoSecureUpdateMechanismRule) Type() string {
	return "I4_LIKELY_NO_SECURE_UPDATE_MECHANISM"
}

func (r *I4LikelyNoSecureUpdateMechanismRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil {
		return Match{}, false
	}
	if strings.TrimSpace(ctx.UpdateVisibility) != "not_seen" {
		return Match{}, false
	}

	legacySignals := dedupeOrderedStrings(normalizeI4LegacySignals(ctx.LegacySignals))
	if len(legacySignals) == 0 {
		return Match{}, false
	}

	score, basis := scoreI4NoSecureUpdateSignals(legacySignals)
	if score < 2 {
		return Match{}, false
	}

	return Match{
		Message:  "This device likely lacks a secure update mechanism or shows no observable evidence of one",
		Evidence: formatI4NoSecureUpdateEvidence(ctx, legacySignals, basis),
	}, true
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
