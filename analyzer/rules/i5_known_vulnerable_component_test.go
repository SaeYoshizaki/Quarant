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
	if !strings.Contains(match.Evidence, "match_basis=family") {
		t.Fatalf("missing match_basis evidence: %s", match.Evidence)
	}
}

func TestI5KnownVulnerableComponentMatchesVendorCategoryAndHostKeyword(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Camera",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "IP Camera",
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"host": "hikvision.com",
			},
		},
	}

	match, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected I5 match")
	}
	if !strings.Contains(match.Evidence, "matched_component_id=hikvision_camera") {
		t.Fatalf("missing Hikvision component evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "match_basis=vendor+category+host_keyword") {
		t.Fatalf("missing host keyword match_basis evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "http_host=hikvision.com") {
		t.Fatalf("missing host evidence: %s", match.Evidence)
	}
}

func TestI5KnownVulnerableComponentMatchesObservedHostWhenHTTPHeadersMissing(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Camera",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "IP Camera",
		ObservedHosts:       []string{"hikvision.com"},
		ObservedUserAgents:  []string{"curl/8.17.0"},
	}

	match, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx)
	if !ok {
		t.Fatal("expected I5 match from observed host")
	}
	if !strings.Contains(match.Evidence, "matched_component_id=hikvision_camera") {
		t.Fatalf("missing Hikvision component evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "match_basis=vendor+category+host_keyword") {
		t.Fatalf("missing observed host match_basis evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "http_host=hikvision.com") {
		t.Fatalf("missing observed host evidence: %s", match.Evidence)
	}
}

func TestI5KnownVulnerableComponentDoesNotMatchCategoryMismatch(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Speaker",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "IP Camera",
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"host": "hikvision.com",
			},
		},
	}

	if _, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx); ok {
		t.Fatal("expected no I5 match when category does not match")
	}
}

func TestI5KnownVulnerableComponentDoesNotMatchVendorOnly(t *testing.T) {
	db := testI5DBWithoutHikvisionVendorKeywords()
	ctx := &Context{
		LocalDeviceCategory: "Camera",
		VendorCandidate:     "Hikvision",
		FamilyCandidate:     "IP Camera",
	}

	if _, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx); ok {
		t.Fatal("expected no I5 match from vendor and category without keyword")
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

func TestI5KnownVulnerableComponentChoosesFamilyOverAuxiliaryMatch(t *testing.T) {
	db := testI5DB()
	ctx := &Context{
		LocalDeviceCategory: "Hub",
		VendorCandidate:     "Samsung",
		FamilyCandidate:     "philips_hue_hub",
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
	if !strings.Contains(match.Evidence, "matched_component_id=philips_hue_hub") {
		t.Fatalf("expected family match to win over auxiliary match: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "match_basis=family") {
		t.Fatalf("missing family match_basis evidence: %s", match.Evidence)
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
		{
			ID:       "hikvision_camera",
			Category: "Camera",
			Vendor:   "Hikvision",
			Family:   "hikvision_camera",
			MatchSignals: knowledge.I5MatchSignals{
				VendorKeywords: []string{"hikvision"},
				HostKeywords:   []string{"hikvision", "hik-connect"},
				UAKeywords:     []string{"hikvision"},
				SNIKeywords:    []string{"hikvision", "hik-connect"},
			},
			KnownIssues:        []string{"Known history of camera firmware vulnerabilities."},
			RepresentativeCVEs: []string{"CVE-2021-36260"},
			Severity:           "critical",
			Recommendation:     []string{"Review camera firmware version."},
		},
	}

	return &knowledge.DB{I5Vulnerable: &components}
}

func testI5DBWithoutHikvisionVendorKeywords() *knowledge.DB {
	components := knowledge.I5VulnerableComponents{
		{
			ID:       "hikvision_camera",
			Category: "Camera",
			Vendor:   "Hikvision",
			Family:   "hikvision_camera",
			MatchSignals: knowledge.I5MatchSignals{
				HostKeywords: []string{"hikvision", "hik-connect"},
				UAKeywords:   []string{"hikvision"},
				SNIKeywords:  []string{"hikvision", "hik-connect"},
			},
			KnownIssues:        []string{"Known history of camera firmware vulnerabilities."},
			RepresentativeCVEs: []string{"CVE-2021-36260"},
			Severity:           "critical",
			Recommendation:     []string{"Review camera firmware version."},
		},
	}

	return &knowledge.DB{I5Vulnerable: &components}
}
