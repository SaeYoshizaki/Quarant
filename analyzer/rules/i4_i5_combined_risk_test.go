package rules

import (
	"strings"
	"testing"
)

func TestI4I5CombinedRiskLikelyEOLWins(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory:         "Camera",
		VendorCandidate:             "Hikvision",
		FamilyCandidate:             "hikvision_camera",
		UpdateVisibility:            "not_seen",
		LegacySignals:               []string{"telnet_observed", "admin_interface"},
		LocalInferenceSource:        "known",
		LocalInferenceConfidence:    "strong(vendor+family)",
		ObservedHosts:               []string{"hikvision.com"},
		DeviceInferenceConfidence:   "weak",
		FlowInferenceConfidence:     "weak",
		DeviceInferenceSource:       "observed",
		FlowInferenceSource:         "observed",
		DeviceInferenceReasons:      []string{"test"},
		LocalInferenceReasons:       []string{"test"},
		FlowInferenceReasons:        []string{"test"},
		ContextClassification:       InferenceView{Category: "Camera"},
		LocalClassification:         InferenceView{Category: "Camera"},
		FlowClassification:          InferenceView{Category: "Camera"},
		StableIdentifierRepeatCount: 1,
	}

	match, ok := NewI4I5CombinedRiskRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected combined risk match")
	}
	if match.RuleID != "I4_I5_COMBINED_RISK" {
		t.Fatalf("unexpected rule id: %s", match.RuleID)
	}
	if match.Category != "I4_I5" {
		t.Fatalf("unexpected category: %s", match.Category)
	}
	if match.Type != "I4_I5_COMBINED_RISK" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityCritical {
		t.Fatalf("unexpected severity: %s", match.Severity)
	}
	for _, want := range []string{
		"combined_basis=known_vulnerable_component+likely_eol",
		"context_category=Camera",
		"vendor_candidate=Hikvision",
		"family_candidate=hikvision_camera",
		"matched_component_id=hikvision_camera",
		"representative_cves=CVE-2021-36260",
		"i5_severity=critical",
		"i4_signals=likely_eol,likely_no_secure_update_mechanism",
		"recommended_checks=review firmware version | confirm vendor support status | consider replacement if unsupported",
	} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("missing evidence %q in %s", want, match.Evidence)
		}
	}
}

func TestI4I5CombinedRiskNoSecureUpdateWhenNotEOL(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory:      "Camera",
		VendorCandidate:          "Hikvision",
		FamilyCandidate:          "hikvision_camera",
		UpdateVisibility:         "not_seen",
		LegacySignals:            []string{"http_only_management"},
		LocalInferenceSource:     "known",
		LocalInferenceConfidence: "strong(vendor+family)",
		ObservedHosts:            []string{"hikvision.com"},
	}

	match, ok := NewI4I5CombinedRiskRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected combined risk match")
	}
	if match.Severity != SeverityHigh {
		t.Fatalf("unexpected severity: %s", match.Severity)
	}
	if !strings.Contains(match.Evidence, "combined_basis=known_vulnerable_component+likely_no_secure_update_mechanism") {
		t.Fatalf("missing no-secure-update basis: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "i4_signals=likely_no_secure_update_mechanism") {
		t.Fatalf("missing i4 signal: %s", match.Evidence)
	}
}

func TestI4I5CombinedRiskKnownVulnerableOnly(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Camera",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "hikvision_camera",
		ObservedHosts:       []string{"hikvision.com"},
	}

	match, ok := NewI4I5CombinedRiskRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected combined risk match")
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("unexpected severity: %s", match.Severity)
	}
	if !strings.Contains(match.Evidence, "combined_basis=known_vulnerable_component_only") {
		t.Fatalf("missing i5-only basis: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "i4_signals=") {
		t.Fatalf("missing i4 signal key: %s", match.Evidence)
	}
	if strings.Contains(match.Evidence, "i4_signals=none") {
		t.Fatalf("unexpected none i4 signal: %s", match.Evidence)
	}
}

func TestI4I5CombinedRiskDoesNotMatchWithoutI5(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Speaker",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "IP Camera",
		UpdateVisibility:    "not_seen",
		LegacySignals:       []string{"telnet_observed", "admin_interface"},
	}

	if _, ok := NewI4I5CombinedRiskRule(db).Apply(ctx); ok {
		t.Fatal("expected no combined risk without I5 match")
	}
}
