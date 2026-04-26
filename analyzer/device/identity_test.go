package device

import (
	"testing"

	"quarant/analyzer/rules"
)

func TestFamilyIdentityFromMultiplePassiveSignals(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		sni        string
		wantFamily string
	}{
		{
			name: "tplink kasa controller",
			headers: map[string]string{
				"host":       "api.tplinkcloud.com",
				"user-agent": "Kasa Android",
			},
			sni:        "n-devs.tplinkcloud.com",
			wantFamily: "tplink_controller",
		},
		{
			name: "philips hue hub",
			headers: map[string]string{
				"host":       "discovery.meethue.com",
				"user-agent": "hue-bridge/1.0",
			},
			wantFamily: "philips_hue_hub",
		},
		{
			name: "hikvision camera",
			headers: map[string]string{
				"host":       "dev.hik-connect.com",
				"user-agent": "Hikvision IPCamera",
			},
			wantFamily: "hikvision_camera",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProfile("10.0.0.10")
			EnrichFromHTTP(p, tt.headers)
			if tt.sni != "" {
				EnrichFromTLS(p, rules.TLSClientHelloInfo{SNI: tt.sni})
			}

			if got := p.Identity.FamilyCandidate; got != tt.wantFamily {
				t.Fatalf("expected family %q, got %q; reasons=%v scores=%v", tt.wantFamily, got, p.Identity.FamilyReasons, p.Identity.FamilyScores)
			}
			if p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
				t.Fatalf("single observation should not produce high confidence, got %s", p.Identity.FamilyConfidence)
			}
			if len(p.Identity.FamilyReasons) == 0 {
				t.Fatalf("expected family reasons")
			}
		})
	}
}

func TestFamilyIdentityVendorOnlyDoesNotOverstateConfidence(t *testing.T) {
	p := NewProfile("10.0.0.11")
	EnrichFromHTTP(p, map[string]string{"host": "api.tplinkcloud.com"})

	if got := p.Identity.FamilyCandidate; got != "tplink_controller" {
		t.Fatalf("expected weak tplink family candidate, got %q", got)
	}
	if p.Identity.FamilyConfidence != "low" {
		t.Fatalf("expected low family confidence for one host signal, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestFamilyIdentitySingleObservationDoesNotBecomeHigh(t *testing.T) {
	p := NewProfile("10.0.0.12")
	EnrichFromHTTP(p, map[string]string{
		"host":       "api.tplinkcloud.com",
		"user-agent": "Kasa Android",
	})

	if got := p.Identity.FamilyCandidate; got != "tplink_controller" {
		t.Fatalf("expected tplink_controller, got %q", got)
	}
	if p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("expected single observation below high, got %s", p.Identity.FamilyConfidence)
	}
}

func TestFamilyIdentityRepeatedObservationRaisesConfidence(t *testing.T) {
	p := NewProfile("10.0.0.13")
	headers := map[string]string{
		"host":       "api.tplinkcloud.com",
		"user-agent": "Kasa Android",
	}

	EnrichFromHTTP(p, headers)
	firstConfidence := p.Identity.FamilyConfidence
	firstScore := p.Identity.FamilyScore

	EnrichFromHTTP(p, headers)

	if got := p.Identity.FamilyCandidate; got != "tplink_controller" {
		t.Fatalf("expected tplink_controller, got %q", got)
	}
	if p.Identity.FamilyScore <= firstScore {
		t.Fatalf("expected repeated observation to raise score from %.2f, got %.2f", firstScore, p.Identity.FamilyScore)
	}
	if p.Identity.FamilyConfidence != "high" && p.Identity.FamilyConfidence != "strong" {
		t.Fatalf("expected repeated observation to reach high or strong, first=%s now=%s reasons=%v", firstConfidence, p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestStrongFamilySupportsVendorConfidence(t *testing.T) {
	p := NewProfile("10.0.0.14")
	headers := map[string]string{
		"host":       "api.tplinkcloud.com",
		"user-agent": "Kasa Android",
	}

	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)

	if p.Identity.FamilyCandidate != "tplink_controller" {
		t.Fatalf("expected tplink_controller, got %q", p.Identity.FamilyCandidate)
	}
	if p.Identity.FamilyConfidence != "high" && p.Identity.FamilyConfidence != "strong" {
		t.Fatalf("expected high or strong family after repeated consistent strong signals, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
	if p.Identity.VendorCandidate != "TP-Link" {
		t.Fatalf("expected TP-Link vendor, got %q", p.Identity.VendorCandidate)
	}
	if p.Identity.VendorConfidence != "high" && p.Identity.VendorConfidence != "strong" {
		t.Fatalf("expected strong family to reinforce vendor to high or strong, got %s reasons=%v", p.Identity.VendorConfidence, p.Identity.VendorReasons)
	}
}

func TestWeakVendorNameDoesNotOverstateVendorOrFamily(t *testing.T) {
	p := NewProfile("10.0.0.15")
	EnrichFromHTTP(p, map[string]string{"host": "www.apple.com"})

	if p.Identity.FamilyConfidence == "medium" || p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("generic Apple host should not imply HomePod family, got family=%q confidence=%s reasons=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
	if p.Identity.VendorConfidence == "high" || p.Identity.VendorConfidence == "strong" {
		t.Fatalf("generic vendor host should not produce high vendor confidence, got %s reasons=%v", p.Identity.VendorConfidence, p.Identity.VendorReasons)
	}
}

func TestGenericKeywordAloneDoesNotRaiseFamily(t *testing.T) {
	p := NewProfile("10.0.0.16")
	EnrichFromHTTP(p, map[string]string{"user-agent": "Generic IPCamera Client"})

	if p.Identity.FamilyCandidate != "" {
		t.Fatalf("generic camera UA should not select a concrete family, got %q reasons=%v", p.Identity.FamilyCandidate, p.Identity.FamilyReasons)
	}
	if p.Identity.FamilyConfidence != "unknown" {
		t.Fatalf("expected unknown family confidence for generic camera UA, got %s", p.Identity.FamilyConfidence)
	}
}

func TestStrongFamilySignalMatchesConservatively(t *testing.T) {
	p := NewProfile("10.0.0.17")
	EnrichFromHTTP(p, map[string]string{
		"host":       "dev.hik-connect.com",
		"user-agent": "Hikvision",
	})

	if p.Identity.FamilyCandidate != "hikvision_camera" {
		t.Fatalf("expected hikvision_camera, got %q scores=%v reasons=%v", p.Identity.FamilyCandidate, p.Identity.FamilyScores, p.Identity.FamilyReasons)
	}
	if p.Identity.FamilyConfidence != "medium" {
		t.Fatalf("expected medium family confidence for non-repeated strong signals, got %s", p.Identity.FamilyConfidence)
	}
}

func TestRepeatedSingleSignalDoesNotBecomeHigh(t *testing.T) {
	p := NewProfile("10.0.0.18")
	headers := map[string]string{"host": "api.tplinkcloud.com"}

	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)

	if p.Identity.FamilyCandidate != "tplink_controller" {
		t.Fatalf("expected weak tplink family candidate, got %q", p.Identity.FamilyCandidate)
	}
	if p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("repeating one signal type should not reach high/strong, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestNoisySingleObservationsDoNotBecomeHigh(t *testing.T) {
	p := NewProfile("10.0.0.19")
	EnrichFromHTTP(p, map[string]string{
		"host":       "api.smartthings.com",
		"user-agent": "Kasa Android",
	})

	if p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("mixed one-off signals should not reach high/strong family confidence, got family=%q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorConfidence == "high" || p.Identity.VendorConfidence == "strong" {
		t.Fatalf("mixed one-off signals should not reach high/strong vendor confidence, got vendor=%q confidence=%s reasons=%v scores=%v", p.Identity.VendorCandidate, p.Identity.VendorConfidence, p.Identity.VendorReasons, p.Identity.VendorScores)
	}
}

func TestRepeatedWeakOnlySignalsDoNotBecomeConcreteFamily(t *testing.T) {
	p := NewProfile("10.0.0.20")
	headers := map[string]string{
		"host":       "nest.example.net",
		"user-agent": "Assistant Client",
	}

	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)

	if p.Identity.FamilyConfidence == "medium" || p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("weak-only repeated signals should not become concrete family, got family=%q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorConfidence == "high" || p.Identity.VendorConfidence == "strong" {
		t.Fatalf("weak-only repeated signals should not produce high/strong vendor, got vendor=%q confidence=%s reasons=%v", p.Identity.VendorCandidate, p.Identity.VendorConfidence, p.Identity.VendorReasons)
	}
}

func TestRepeatedStrongSingleSignalDoesNotBecomeHighFamily(t *testing.T) {
	p := NewProfile("10.0.0.21")
	headers := map[string]string{"host": "api.tplinkcloud.com"}

	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)

	if p.Identity.FamilyCandidate != "tplink_controller" {
		t.Fatalf("expected tplink_controller weak candidate, got %q", p.Identity.FamilyCandidate)
	}
	if p.Identity.FamilyConfidence == "high" || p.Identity.FamilyConfidence == "strong" {
		t.Fatalf("one repeated strong signal type should not become high/strong family, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestStrongSignalRepeatedAcrossSignalTypesReachesHighFamily(t *testing.T) {
	p := NewProfile("10.0.0.22")
	headers := map[string]string{
		"host":       "api.tplinkcloud.com",
		"user-agent": "Kasa Android",
	}

	EnrichFromHTTP(p, headers)
	EnrichFromHTTP(p, headers)

	if p.Identity.FamilyCandidate != "tplink_controller" {
		t.Fatalf("expected tplink_controller, got %q", p.Identity.FamilyCandidate)
	}
	if p.Identity.FamilyConfidence != "high" && p.Identity.FamilyConfidence != "strong" {
		t.Fatalf("repeated strong host+ua should reach high or strong, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestGenericHTTPPathDoesNotImplyPhilipsHueFamily(t *testing.T) {
	p := NewProfile("10.0.0.24")

	EnrichFromHTTP(p, map[string]string{"host": "api.vendor-cloud.test"})
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/api/config"}, 80, false)

	if p.Identity.FamilyCandidate == "philips_hue_hub" {
		t.Fatalf("generic api path should not imply philips hue family, got confidence=%s reasons=%v scores=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorCandidate == "Philips" && confidenceRank(p.Identity.VendorConfidence) > confidenceRank("low") {
		t.Fatalf("generic api path should not raise Philips vendor confidence, got confidence=%s reasons=%v scores=%v", p.Identity.VendorConfidence, p.Identity.VendorReasons, p.Identity.VendorScores)
	}
}

func TestGenericSetupPathDoesNotImplyConcreteVendorOrFamily(t *testing.T) {
	p := NewProfile("10.0.0.25")

	EnrichFromHTTP(p, map[string]string{"host": "device.local"})
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/setup"}, 80, false)

	if p.Identity.FamilyCandidate != "" {
		t.Fatalf("generic setup path should not select a concrete family, got family=%q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorCandidate != "" {
		t.Fatalf("generic setup path should not select a concrete vendor, got vendor=%q confidence=%s reasons=%v scores=%v", p.Identity.VendorCandidate, p.Identity.VendorConfidence, p.Identity.VendorReasons, p.Identity.VendorScores)
	}
}

func TestMeethueHostCanRemainHueCandidate(t *testing.T) {
	p := NewProfile("10.0.0.26")

	EnrichFromHTTP(p, map[string]string{"host": "discovery.meethue.com"})

	if p.Identity.FamilyCandidate != "philips_hue_hub" {
		t.Fatalf("meethue host should remain a hue candidate, got family=%q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.FamilyConfidence != "low" {
		t.Fatalf("single meethue host should stay low confidence, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}

func TestGenericAPIPathAloneIsNotFamilyStrongSignal(t *testing.T) {
	p := NewProfile("10.0.0.27")

	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/api/"}, 80, false)

	if p.Identity.FamilyCandidate != "" {
		t.Fatalf("generic /api/ path alone should not select a concrete family, got family=%q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorCandidate != "" {
		t.Fatalf("generic /api/ path alone should not select a concrete vendor, got vendor=%q confidence=%s reasons=%v", p.Identity.VendorCandidate, p.Identity.VendorConfidence, p.Identity.VendorReasons)
	}
}

func TestUbuntuDemoSignalsDoNotProducePhilipsHueInference(t *testing.T) {
	p := NewProfile("10.0.0.28")

	EnrichFromHTTP(p, map[string]string{"host": "api.vendor-cloud.test"})
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/api/config"}, 80, false)
	EnrichFromHTTP(p, map[string]string{"host": "device.local"})
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/setup"}, 80, false)
	EnrichFromHTTP(p, map[string]string{"host": "example.com"})

	if p.Identity.FamilyCandidate == "philips_hue_hub" {
		t.Fatalf("ubuntu demo signals should not produce philips hue family, got confidence=%s reasons=%v scores=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.VendorCandidate == "Philips" {
		t.Fatalf("ubuntu demo signals should not produce Philips vendor, got confidence=%s reasons=%v scores=%v", p.Identity.VendorConfidence, p.Identity.VendorReasons, p.Identity.VendorScores)
	}
}

func TestAmbiguousFamilyCandidatesRemainUncertain(t *testing.T) {
	p := NewProfile("10.0.0.23")
	EnrichFromHTTP(p, map[string]string{"host": "api.switchbot.net"})
	EnrichFromTLS(p, rules.TLSClientHelloInfo{SNI: "api.switchbot.net"})

	if p.Identity.FamilyCandidate != "" {
		t.Fatalf("ambiguous switchbot sensor/controller evidence should not force a concrete family, got %q confidence=%s reasons=%v scores=%v", p.Identity.FamilyCandidate, p.Identity.FamilyConfidence, p.Identity.FamilyReasons, p.Identity.FamilyScores)
	}
	if p.Identity.FamilyConfidence != "unknown" {
		t.Fatalf("expected unknown confidence for ambiguous family candidates, got %s reasons=%v", p.Identity.FamilyConfidence, p.Identity.FamilyReasons)
	}
}
