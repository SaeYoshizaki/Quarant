package rules

import (
	"strings"
	"testing"

	"quarant/analyzer/knowledge"
)

func TestI5KnownVulnerableComponentMatchesFamilyCandidate(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Hub",
		VendorCandidate:     "Philips",
		FamilyCandidate:     "philips_hue_hub",
	}

	match, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected I5 match")
	}
	if match.RuleID != "I5_KNOWN_VULNERABLE_COMPONENT" {
		t.Fatalf("unexpected rule id: %s", match.RuleID)
	}
	if match.Category != "I5" {
		t.Fatalf("unexpected category: %s", match.Category)
	}
	if !strings.Contains(match.Evidence, "knowledge_id=philips_hue_hub") {
		t.Fatalf("missing knowledge evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "family_candidate=philips_hue_hub") {
		t.Fatalf("missing family evidence: %s", match.Evidence)
	}
}

func TestI5KnownVulnerableComponentMatchesVendorCategoryAndHost(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Hub",
		VendorCandidate:     "Samsung",
		FamilyCandidate:     "Hub",
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"host": "api.smartthings.example",
			},
		},
	}

	match, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected I5 match")
	}
	if !strings.Contains(match.Evidence, "knowledge_id=smartthings_hub") {
		t.Fatalf("missing smartthings evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "http_host=api.smartthings.example") {
		t.Fatalf("missing host evidence: %s", match.Evidence)
	}
}

func TestI5KnownVulnerableComponentDoesNotMatchSingleNetworkSignal(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"host": "api.smartthings.example",
			},
		},
	}

	if _, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx); ok {
		t.Fatal("expected no I5 match from a single network signal")
	}
}

func testI5DB() *knowledge.DB {
	components := knowledge.I5VulnerableComponents{
		{
			ID:       "philips_hue_hub",
			Category: "Hub",
			Vendor:   "Philips",
			Family:   "philips_hue_hub",
			MatchSignals: knowledge.I5MatchSignals{
				VendorKeywords: []string{"philips", "hue"},
				HostKeywords:   []string{"meethue", "hue"},
				UAKeywords:     []string{"hue"},
				SNIKeywords:    []string{"meethue", "hue"},
			},
			KnownIssues:        []string{"Known history of hub-side issues."},
			RepresentativeCVEs: []string{"CVE-2018-7580"},
			Severity:           "medium",
			Recommendation:     []string{"Review hub firmware version."},
		},
		{
			ID:       "smartthings_hub",
			Category: "Hub",
			Vendor:   "Samsung",
			Family:   "smartthings_hub",
			MatchSignals: knowledge.I5MatchSignals{
				VendorKeywords: []string{"samsung", "smartthings"},
				HostKeywords:   []string{"smartthings"},
				UAKeywords:     []string{"smartthings", "samsung"},
				SNIKeywords:    []string{"smartthings"},
			},
			KnownIssues:        []string{"Known history of authentication bypass."},
			RepresentativeCVEs: []string{"CVE-2025-2233"},
			Severity:           "high",
			Recommendation:     []string{"Review software versions."},
		},
	}

	return &knowledge.DB{I5Vulnerable: &components}
}
