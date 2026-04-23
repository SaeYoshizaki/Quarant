package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

const (
	I4I5CombinedRiskRuleID = "I4_I5_COMBINED_RISK"

	i4I5BasisKnownVulnerableOnly      = "known_vulnerable_component_only"
	i4I5BasisKnownVulnerableLikelyEOL = "known_vulnerable_component+likely_eol"
	i4I5BasisKnownVulnerableNoUpdate  = "known_vulnerable_component+likely_no_secure_update_mechanism"
	i4I5SignalLikelyEOL               = "likely_eol"
	i4I5SignalNoSecureUpdateMechanism = "likely_no_secure_update_mechanism"
)

type I4I5CombinedRiskRule struct {
	db *knowledge.DB
}

func NewI4I5CombinedRiskRule(db *knowledge.DB) *I4I5CombinedRiskRule {
	return &I4I5CombinedRiskRule{db: db}
}

func (r *I4I5CombinedRiskRule) ID() string         { return I4I5CombinedRiskRuleID }
func (r *I4I5CombinedRiskRule) Category() string   { return "I4_I5" }
func (r *I4I5CombinedRiskRule) Severity() Severity { return SeverityWarning }
func (r *I4I5CombinedRiskRule) Type() string       { return I4I5CombinedRiskRuleID }

func (r *I4I5CombinedRiskRule) Apply(ctx *Context) (Match, bool) {
	if r == nil || r.db == nil || ctx == nil {
		return Match{}, false
	}

	i5Match := findBestI5VulnerableComponent(r.db, ctx)
	if i5Match == nil {
		return Match{}, false
	}

	eol := evaluateI4EOL(r.db, ctx)
	noSecureUpdate := evaluateI4NoSecureUpdate(ctx)

	i4Signals := make([]string, 0, 2)
	if eol.likely {
		i4Signals = append(i4Signals, i4I5SignalLikelyEOL)
	}
	if noSecureUpdate.likely {
		i4Signals = append(i4Signals, i4I5SignalNoSecureUpdateMechanism)
	}

	severity := SeverityWarning
	combinedBasis := i4I5BasisKnownVulnerableOnly
	message := "Device appears to belong to a known vulnerable family; applicability is still unconfirmed, so review exact model, firmware version, and support status"
	recommendedChecks := []string{
		"review model and firmware version",
		"review vendor support status",
	}

	switch {
	case eol.likely:
		severity = SeverityCritical
		combinedBasis = i4I5BasisKnownVulnerableLikelyEOL
		message = "Device appears to belong to a known vulnerable family and is likely beyond its support lifecycle; known issues may remain unpatched, so review firmware, support status, and replacement necessity"
		recommendedChecks = []string{
			"review firmware version",
			"confirm vendor support status",
			"consider replacement if unsupported",
		}
	case noSecureUpdate.likely:
		severity = SeverityHigh
		combinedBasis = i4I5BasisKnownVulnerableNoUpdate
		message = "Device appears to belong to a known vulnerable family and has weak or unobservable secure update mechanisms; known issues may remain unpatched, so review update method and current firmware state"
		recommendedChecks = []string{
			"review update method",
			"review current firmware state",
			"confirm secure update support",
		}
	default:
		recommendedChecks = append(recommendedChecks, "confirm applicability of representative CVEs")
	}

	return Match{
		RuleID:   I4I5CombinedRiskRuleID,
		Type:     I4I5CombinedRiskRuleID,
		Category: "I4_I5",
		Severity: severity,
		Message:  message,
		Evidence: formatI4I5CombinedRiskEvidence(
			ctx,
			i5Match.component,
			combinedBasis,
			i4Signals,
			recommendedChecks,
		),
	}, true
}

func formatI4I5CombinedRiskEvidence(ctx *Context, component knowledge.I5VulnerableComponent, combinedBasis string, i4Signals, recommendedChecks []string) string {
	return fmt.Sprintf(
		"combined_basis=%s context_category=%s vendor_candidate=%s family_candidate=%s matched_component_id=%s representative_cves=%s i5_severity=%s i4_signals=%s recommended_checks=%s",
		combinedBasis,
		i5BestContextCategory(ctx),
		strings.TrimSpace(ctx.VendorCandidate),
		strings.TrimSpace(ctx.FamilyCandidate),
		strings.TrimSpace(component.ID),
		strings.Join(component.RepresentativeCVEs, ","),
		strings.ToLower(strings.TrimSpace(component.Severity)),
		strings.Join(i4Signals, ","),
		strings.Join(recommendedChecks, " | "),
	)
}
