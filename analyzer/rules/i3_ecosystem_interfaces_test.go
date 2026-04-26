package rules

import (
	"strings"
	"testing"

	"quarant/analyzer/knowledge"
)

func TestI3APIOverPlaintextLogin(t *testing.T) {
	match, ok := (&I3APIOverPlaintextRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/api/login",
			Headers: map[string]string{"host": "example-cloud.test"},
		},
	})
	if !ok {
		t.Fatal("expected API over plaintext match")
	}
	if match.Type != "I3_API_OVER_PLAINTEXT" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
	if match.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", match.Severity)
	}
}

func TestI3APIOverPlaintextConfig(t *testing.T) {
	match, ok := (&I3APIOverPlaintextRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/api/config",
			Headers: map[string]string{"host": "camera.local"},
		},
	})
	if !ok {
		t.Fatal("expected API over plaintext match")
	}
	if match.Type != "I3_API_OVER_PLAINTEXT" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
}

func TestI3AuthTokenInURLMasksValue(t *testing.T) {
	match, ok := (&I3AuthTokenInURLRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"token": {"abc"},
			},
		},
	})
	if !ok {
		t.Fatal("expected auth token in URL match")
	}
	if strings.Contains(match.Evidence, "abc") {
		t.Fatalf("expected evidence to mask token value, got: %s", match.Evidence)
	}
	if match.Evidence != "token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI3AuthTokenInURLRequiresPlaintextHTTP(t *testing.T) {
	if _, ok := (&I3AuthTokenInURLRule{}).Apply(&Context{
		TLS: true,
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"token": {"abc"},
			},
		},
	}); ok {
		t.Fatal("did not expect URL token signal on TLS context")
	}
}

func TestI3ManagementAPIExposed(t *testing.T) {
	match, ok := (&I3ManagementAPIExposedRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/admin/config",
			Headers: map[string]string{"host": "camera.local"},
		},
	})
	if !ok {
		t.Fatal("expected management API match")
	}
	if match.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", match.Severity)
	}
}

func TestI3WeakEcosystemCryptoSignal(t *testing.T) {
	match, ok := (&I3WeakEcosystemCryptoSignalRule{}).Apply(&Context{
		DstIP: "8.8.8.8",
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/oauth/token",
			Headers: map[string]string{"host": "api.example.com"},
		},
	})
	if !ok {
		t.Fatal("expected weak ecosystem crypto signal")
	}
	if match.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", match.Severity)
	}
}

func TestI3MobileAppBackendPatternObserved(t *testing.T) {
	match, ok := (&I3MobileAppBackendPatternObservedRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/mobile/device/register",
			Query:   map[string][]string{"user_id": {"123"}},
			Headers: map[string]string{"host": "api.vendor-cloud.example"},
		},
	})
	if !ok {
		t.Fatal("expected mobile backend pattern")
	}
	if match.Type != "I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED" {
		t.Fatalf("unexpected type: %s", match.Type)
	}
}

func TestI3APIOverPlaintextDoesNotFireOnHostOnlyHint(t *testing.T) {
	if _, ok := (&I3APIOverPlaintextRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/index.html",
			Headers: map[string]string{"host": "device-sync.local"},
		},
	}); ok {
		t.Fatal("did not expect API over plaintext from host-only hint")
	}
}

func TestI3MobileBackendPatternDoesNotFireOnUserAgentOnly(t *testing.T) {
	if _, ok := (&I3MobileAppBackendPatternObservedRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/status",
			Headers: map[string]string{"host": "device.local", "user-agent": "okhttp/4.0"},
		},
	}); ok {
		t.Fatal("did not expect mobile backend signal from user-agent only")
	}
}

func TestI3AuthKeyIsWarningNotHigh(t *testing.T) {
	match, ok := (&I3AuthTokenInURLRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"auth": {"abc"},
			},
		},
	})
	if !ok {
		t.Fatal("expected auth URL signal")
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
}

func TestI3StatusDoesNotEscalateToHigh(t *testing.T) {
	match, ok := (&I3ManagementAPIExposedRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/status",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected management-like status match")
	}
	if match.Severity == SeverityHigh || match.Severity == SeverityCritical {
		t.Fatalf("status should not be escalated too high, got %s", match.Severity)
	}
}

func TestI3PlaintextRulesDoNotFireOnTLSOnly(t *testing.T) {
	ctx := &Context{
		TLS: true,
		TLSInfo: &TLSClientHelloInfo{
			SNI: "api.example.com",
		},
	}

	if _, ok := (&I3APIOverPlaintextRule{}).Apply(ctx); ok {
		t.Fatal("did not expect API over plaintext on TLS flow")
	}
	if _, ok := (&I3WeakEcosystemCryptoSignalRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak crypto plaintext signal on TLS flow")
	}
}

func TestI3UnexpectedCloudEndpointRule(t *testing.T) {
	db := &knowledge.DB{
		CategoryInference: &knowledge.CategoryInferenceDB{
			Categories: map[string]knowledge.CategoryInferenceEntry{
				"Camera": {
					Category:              "Camera",
					RepresentativeDomains: []string{"camera-vendor.example"},
					EcosystemDomains:      []string{"cloud.camera-vendor.example"},
				},
			},
		},
	}

	matches := NewI3UnexpectedCloudEndpointRule(db).ApplyAll(&Context{
		DeviceCategory:  "Camera",
		VendorCandidate: "VendorCam",
		FamilyCandidate: "x1",
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/api/login",
			Query:   map[string][]string{"token": {"abc"}},
			Headers: map[string]string{"host": "api.unexpected-cloud.example"},
		},
	})
	if len(matches) != 1 {
		t.Fatalf("expected one unexpected cloud endpoint match, got %d", len(matches))
	}
	if matches[0].Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", matches[0].Severity)
	}
	if matches[0].Limitation == "" {
		t.Fatalf("expected limitation metadata, got: %+v", matches[0])
	}
}
