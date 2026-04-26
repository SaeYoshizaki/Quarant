package rules

import (
	"strings"
	"testing"
)

func TestIsPublicIPIPv4(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.1.1", false},
		{"169.254.1.1", false},
		{"127.0.0.1", false},
		{"0.0.0.0", false},
	}

	for _, tt := range tests {
		if got := IsPublicIP(tt.ip); got != tt.want {
			t.Fatalf("IsPublicIP(%q)=%t, want %t", tt.ip, got, tt.want)
		}
	}
}

func TestIsPublicIPIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"2001:4860:4860::8888", true},
		{"2606:4700:4700::1111", true},
		{"::1", false},
		{"::", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"fd00::1", false},
		{"ff02::1", false},
		{"2001:db8::1", false},
	}

	for _, tt := range tests {
		if got := IsPublicIP(tt.ip); got != tt.want {
			t.Fatalf("IsPublicIP(%q)=%t, want %t", tt.ip, got, tt.want)
		}
	}
}

func TestIsPublicIPIPv4MappedIPv6(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"::ffff:8.8.8.8", true},
		{"::ffff:192.168.1.1", false},
	}

	for _, tt := range tests {
		if got := IsPublicIP(tt.ip); got != tt.want {
			t.Fatalf("IsPublicIP(%q)=%t, want %t", tt.ip, got, tt.want)
		}
	}
}

func TestI2ExternalExposureRaisesSeverityAndAddsRecommendation(t *testing.T) {
	match, ok := (&I2ExternalExposureRule{}).Apply(&Context{
		DstIP:   "8.8.8.8",
		DstPort: 23,
	})
	if !ok {
		t.Fatal("expected external exposure match")
	}
	if match.Severity != SeverityHigh {
		t.Fatalf("expected HIGH severity, got %s", match.Severity)
	}
	if !strings.Contains(match.Recommendation, "Disable Telnet") {
		t.Fatalf("expected Telnet recommendation, got: %s", match.Recommendation)
	}
	if match.Limitation == "" {
		t.Fatalf("expected limitation metadata, got: %+v", match)
	}
}

func TestI2HTTPAdminIncludesRecommendation(t *testing.T) {
	match, ok := (&I2HTTPAdminRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/admin/login",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected admin interface match")
	}
	if !strings.Contains(match.Recommendation, "Use HTTPS") {
		t.Fatalf("expected HTTPS recommendation, got: %s", match.Recommendation)
	}
	if !containsAll(match.OWASPTags, "I2", "I3", "I9") {
		t.Fatalf("expected I2/I3/I9 tags, got %v", match.OWASPTags)
	}
	if !strings.Contains(strings.ToLower(match.Limitation), "enabled by default") {
		t.Fatalf("expected default-setting limitation, got: %s", match.Limitation)
	}
}

func TestI2InsecureServiceCarriesI9Tag(t *testing.T) {
	match, ok := (&I2InsecureServiceRule{}).Apply(&Context{
		DstPort: 23,
		Payload: []byte("login: "),
	})
	if !ok {
		t.Fatal("expected insecure service match")
	}
	if !containsAll(match.OWASPTags, "I2", "I7", "I9") {
		t.Fatalf("expected I2/I7/I9 tags, got %v", match.OWASPTags)
	}
	if !strings.Contains(strings.ToLower(match.Inference), "remains enabled") {
		t.Fatalf("expected remains-enabled phrasing, got: %s", match.Inference)
	}
}
