package rules

import "testing"

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
