package rules

import (
	"strings"
	"testing"
)

func TestI9SetupEndpointStillActiveSetupOverHTTP(t *testing.T) {
	match, ok := (&I9SetupEndpointStillActiveRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/setup",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected setup endpoint signal")
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	if !containsAll(match.OWASPTags, "I3", "I7", "I9") {
		t.Fatalf("expected I3/I7/I9 tags, got %v", match.OWASPTags)
	}
	if !strings.Contains(strings.ToLower(match.Message), "setup or onboarding-like endpoint observed") {
		t.Fatalf("unexpected message: %s", match.Message)
	}
	if !strings.Contains(strings.ToLower(match.Limitation), "cannot determine") || !strings.Contains(strings.ToLower(match.Limitation), "factory-default") {
		t.Fatalf("expected non-assertive limitation, got: %s", match.Limitation)
	}
}

func TestI9SetupEndpointStillActiveWizardOverHTTP(t *testing.T) {
	match, ok := (&I9SetupEndpointStillActiveRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/wizard",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected wizard endpoint signal")
	}
	if !containsAll(match.OWASPTags, "I3", "I7", "I9") {
		t.Fatalf("expected I3/I7/I9 tags, got %v", match.OWASPTags)
	}
}

func TestI9SetupEndpointStillActiveDoesNotFireOnAPIConfigOnly(t *testing.T) {
	if _, ok := (&I9SetupEndpointStillActiveRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/api/config",
			Headers: map[string]string{"host": "camera.local"},
		},
	}); ok {
		t.Fatal("did not expect /api/config alone to trigger setup endpoint signal")
	}
}

func TestI9DefaultHostnamePatternDetectsDeviceLocal(t *testing.T) {
	match, ok := (&I9DefaultHostnamePatternRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/status",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected default hostname-like signal")
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
	if !containsAll(match.OWASPTags, "I9") {
		t.Fatalf("expected I9 tag, got %v", match.OWASPTags)
	}
	if !strings.Contains(strings.ToLower(match.Message), "default hostname-like pattern observed") {
		t.Fatalf("unexpected message: %s", match.Message)
	}
}

func TestI9DefaultHostnamePatternDoesNotFireOnVendorCloudHost(t *testing.T) {
	if _, ok := (&I9DefaultHostnamePatternRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/status",
			Headers: map[string]string{"host": "api.vendor-cloud.test"},
		},
	}); ok {
		t.Fatal("did not expect vendor cloud host to trigger default hostname signal")
	}
}
