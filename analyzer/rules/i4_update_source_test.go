package rules

import (
	"strings"
	"testing"
)

func TestI4SuspiciousUpdateSourceLiteralIPEndpoint(t *testing.T) {
	ctx := &Context{
		DstIP: "203.0.113.10",
		HTTP: &HTTPInfo{
			Path: "/firmware.bin",
			Headers: map[string]string{
				"host": "203.0.113.10",
			},
		},
	}

	match, ok := (&I4SuspiciousUpdateSourceRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected literal IP update source to be detected")
	}
	if !strings.Contains(match.Evidence, "suspicious_signals=literal_ip_endpoint") {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI4SuspiciousUpdateSourceSelfSignedCertificate(t *testing.T) {
	ctx := &Context{
		DstIP: "203.0.113.10",
		TLS:   true,
		TLSInfo: &TLSClientHelloInfo{
			SNI: "firmware.vendor.example",
		},
		TLSServerInfo: &TLSServerInfo{
			Cert: &TLSCertificateInfo{
				Subject:    "firmware.vendor.example",
				SANs:       []string{"firmware.vendor.example"},
				SelfSigned: true,
			},
		},
	}

	match, ok := (&I4SuspiciousUpdateSourceRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected self-signed certificate update source to be detected")
	}
	if !strings.Contains(match.Evidence, "self_signed_cert") {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI4SuspiciousUpdateSourceDoesNotMismatchMixedCaseSNI(t *testing.T) {
	ctx := &Context{
		DstIP: "203.0.113.10",
		TLS:   true,
		TLSInfo: &TLSClientHelloInfo{
			SNI: " Firmware.Vendor.Example ",
		},
		TLSServerInfo: &TLSServerInfo{
			Cert: &TLSCertificateInfo{
				Subject: "firmware.vendor.example",
				SANs:    []string{"firmware.vendor.example"},
			},
		},
	}

	if signals := suspiciousI4UpdateSourceSignals(ctx, i4FirmwareUpdateObservation{}); len(signals) != 0 {
		t.Fatalf("did not expect suspicious signals for mixed-case matching SNI, got: %v", signals)
	}
}

func TestI4LikelyNoSecureUpdateMechanismTelnetObserved(t *testing.T) {
	ctx := &Context{
		LocalDeviceCategory: "Camera",
		VendorCandidate:     "ExampleCam",
		FamilyCandidate:     "X100",
		UpdateVisibility:    "not_seen",
		LegacySignals:       []string{"telnet_observed"},
	}

	match, ok := (&I4LikelyNoSecureUpdateMechanismRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected no secure update mechanism review signal")
	}
	for _, want := range []string{
		"category=Camera",
		"vendor_candidate=ExampleCam",
		"family_candidate=X100",
		"legacy_signals=telnet_observed",
		"review admin interface for firmware update controls",
	} {
		if !strings.Contains(match.Evidence, want) {
			t.Fatalf("expected evidence to contain %q, got: %s", want, match.Evidence)
		}
	}
}

func TestI4LikelyNoSecureUpdateMechanismWeakLegacySignalDoesNotFire(t *testing.T) {
	ctx := &Context{
		UpdateVisibility: "not_seen",
		LegacySignals:    []string{"admin_interface"},
	}

	if _, ok := (&I4LikelyNoSecureUpdateMechanismRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak legacy signal alone to fire")
	}
}
