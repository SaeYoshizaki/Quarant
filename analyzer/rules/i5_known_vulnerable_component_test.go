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
	if !strings.Contains(strings.ToLower(match.Message), "candidate") {
		t.Fatalf("expected candidate wording, got: %s", match.Message)
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
	if !strings.Contains(match.Evidence, "match_level=family_candidate") {
		t.Fatalf("missing match level evidence: %s", match.Evidence)
	}
	if !strings.Contains(match.Evidence, "representative_cves=CVE-2018-7580") {
		t.Fatalf("missing representative cves: %s", match.Evidence)
	}
	if match.Limitation == "" {
		t.Fatalf("expected limitation metadata, got: %+v", match)
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

func testRefs(cve string) []knowledge.I5Reference {
	return []knowledge.I5Reference{{CVE: cve, URL: "https://nvd.nist.gov/vuln/detail/" + cve, AttackVector: "network", Verified: "2026-10-17"}}
}

// An entry without a verified reference must not produce a "known
// vulnerable" claim, whatever matches.
func TestI5InactiveEntryIsNotMatched(t *testing.T) {
	db := testI5DB()
	(*db.I5Vulnerable)[0].References = nil
	(*db.I5Vulnerable)[0].Status = "inactive_no_verified_reference"
	ctx := &Context{LocalDeviceCategory: "Hub", VendorCandidate: "Philips", FamilyCandidate: "philips_hue_hub"}
	if m, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx); ok {
		t.Fatalf("inactive entry matched: %s", m.Evidence)
	}
}

// Keywords match whole tokens: "hue" must not match "huelva", nor a vendor
// keyword a destination name.
func TestI5KeywordsMatchWholeTokens(t *testing.T) {
	cases := []struct {
		value, keyword string
		want           bool
	}{
		{"www.meethue.com", "meethue", true},
		{"bridge.hue.example", "hue", true},
		{"cdn.huelva.example", "hue", false},
		{"api.algolia.net", "lg", false},
		{"events.example.com", "eve", false},
		{"Smart Life", "smart life", true},
		{"tp-link cloud", "tp-link", true},
	}
	for _, c := range cases {
		if got := i5AnyKeywordContains(c.value, []string{c.keyword}); got != c.want {
			t.Errorf("%q vs %q: got %v, want %v", c.value, c.keyword, got, c.want)
		}
	}
	db := testI5DB()
	// A Samsung-vendor hub that only talks to a host containing a vendor
	// keyword of another family must not become that family.
	ctx := &Context{LocalDeviceCategory: "Hub", VendorCandidate: "Generic", ObservedHosts: []string{"philips.example.com"}}
	if m, ok := NewI5KnownVulnerableComponentRule(db).Apply(ctx); ok {
		t.Fatalf("vendor keyword matched a destination: %s", m.Evidence)
	}
}

// The shipped knowledge base: every active entry has an NVD reference, and
// no host/SNI keyword is a shared cloud name.
func TestShippedI5KnowledgeIsSourced(t *testing.T) {
	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	shared := map[string]bool{"google": true, "amazon": true, "apple": true, "icloud": true, "samsung": true, "lg": true}
	active := 0
	for _, c := range *db.I5Vulnerable {
		for _, kw := range append(append([]string{}, c.MatchSignals.HostKeywords...), c.MatchSignals.SNIKeywords...) {
			if shared[strings.ToLower(kw)] {
				t.Errorf("%s: shared cloud keyword %q", c.ID, kw)
			}
		}
		if !c.Active() {
			continue
		}
		active++
		for _, r := range c.References {
			if !strings.HasPrefix(r.URL, "https://nvd.nist.gov/vuln/detail/"+r.CVE) || r.Verified == "" || r.AttackVector == "" {
				t.Errorf("%s: incomplete reference %+v", c.ID, r)
			}
		}
	}
	if active == 0 {
		t.Fatal("no active entries")
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
			References:         testRefs("CVE-2018-7580"),
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
			References:         testRefs("CVE-2025-2233"),
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
			References:         testRefs("CVE-2021-36260"),
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
			References:         testRefs("CVE-2021-36260"),
			Severity:           "critical",
			Recommendation:     []string{"Review camera firmware version."},
		},
	}

	return &knowledge.DB{I5Vulnerable: &components}
}
