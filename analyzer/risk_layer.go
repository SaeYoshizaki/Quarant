package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"quarant/analyzer/rules"
)

func buildCompositeRiskMatch(ctx *rules.Context, matches []rules.Match) *rules.Match {
	signals := collectI6RiskSignals(matches)
	if len(signals) == 0 {
		return nil
	}

	score, level, severity, action := classifyCompositeRisk(signals)
	sourceTypes := collectI6SourceTypes(matches)

	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = "GenericIoT"
	}

	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	if localCategory == "" {
		localCategory = "GenericIoT"
	}

	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)
	if flowCategory == "" {
		flowCategory = "GenericIoT"
	}

	return &rules.Match{
		RuleID:   "R1_COMPOSITE_RISK",
		Type:     "R1_COMPOSITE_RISK",
		Category: "R1",
		Severity: rules.Severity(severity),
		Message: fmt.Sprintf(
			"Composite risk derived from I6 signals | level=%s | score=%d | action=%s | category=%s | local=%s | flow=%s | risk=%s",
			level,
			score,
			action,
			category,
			localCategory,
			flowCategory,
			strings.Join(signals, ","),
		),
		Evidence: fmt.Sprintf(
			"risk_level=%s risk_score=%d recommended_action=%s category=%s local_category=%s flow_category=%s risk_signals=%s source_types=%s",
			level,
			score,
			action,
			category,
			localCategory,
			flowCategory,
			strings.Join(signals, ","),
			strings.Join(sourceTypes, ","),
		),
	}
}

func collectI6RiskSignals(matches []rules.Match) []string {
	set := map[string]struct{}{}
	for _, m := range matches {
		if m.Category != "I6" {
			continue
		}
		for _, signal := range parseDelimitedEvidenceField(m.Evidence, "risk_signals") {
			if signal == "" {
				continue
			}
			set[signal] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for signal := range set {
		out = append(out, signal)
	}
	sort.Strings(out)
	return out
}

func collectI6SourceTypes(matches []rules.Match) []string {
	set := map[string]struct{}{}
	for _, m := range matches {
		if m.Category != "I6" || strings.TrimSpace(m.Type) == "" {
			continue
		}
		set[m.Type] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for eventType := range set {
		out = append(out, eventType)
	}
	sort.Strings(out)
	return out
}

func parseDelimitedEvidenceField(evidence, key string) []string {
	marker := key + "="
	idx := strings.Index(evidence, marker)
	if idx == -1 {
		return nil
	}
	value := evidence[idx+len(marker):]
	if end := strings.IndexByte(value, ' '); end != -1 {
		value = value[:end]
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func classifyCompositeRisk(signals []string) (int, string, Severity, string) {
	score := 0
	has := make(map[string]bool, len(signals))
	for _, signal := range signals {
		has[signal] = true
		switch signal {
		case "unexpected_external_admin":
			score += 30
		case "plaintext_external":
			score += 25
		case "unexpected_domain":
			score += 20
		case "category_mismatch":
			score += 20
		case "protocol_mismatch":
			score += 15
		case "tls_ecosystem_mismatch":
			score += 15
		case "category_mismatch_over_tls":
			score += 10
		case "external_tls_unknown":
			score += 10
		case "external_comm":
			score += 10
		case "admin_like_path":
			score += 10
		case "category_confidence_low":
			score += 5
		default:
			score += 5
		}
	}

	if len(signals) >= 3 {
		score += 10
	}

	if has["unexpected_external_admin"] && has["plaintext_external"] {
		score += 10
	}
	if has["unexpected_domain"] && has["category_mismatch"] {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	level := "low"
	severity := SeverityWarning
	action := "monitor"
	switch {
	case score >= 60:
		level = "high"
		severity = SeverityCritical
		action = "isolate_or_block"
	case score >= 35:
		level = "medium"
		action = "investigate"
	default:
		level = "low"
		action = "monitor"
	}

	return score, level, severity, action
}
