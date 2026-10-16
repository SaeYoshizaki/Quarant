package analyzer

import "testing"

func TestLocalNetworksContains(t *testing.T) {
	ln := DefaultLocalNetworks()
	cases := map[string]bool{
		"192.168.50.20":   true,
		"10.1.2.3":        true,
		"172.20.0.5":      true,
		"fe80::1":         true,
		"fd00::10":        true,
		"8.8.8.8":         false,
		"198.51.100.10":   false,
		"224.0.0.251":     false,
		"239.255.255.250": false,
		"255.255.255.255": false,
		"0.0.0.0":         false,
		"":                false,
		"not-an-ip":       false,
	}
	for ip, want := range cases {
		if got := ln.Contains(ip); got != want {
			t.Errorf("Contains(%q)=%v want %v", ip, got, want)
		}
	}
}

func TestParseLocalNetworksCustom(t *testing.T) {
	ln, err := ParseLocalNetworks([]string{"192.168.50.0/24", "100.64.0.7"})
	if err != nil {
		t.Fatal(err)
	}
	if !ln.Contains("192.168.50.20") || !ln.Contains("100.64.0.7") {
		t.Fatal("expected configured ranges to be local")
	}
	if ln.Contains("192.168.50.255") {
		t.Fatal("subnet broadcast must not be a device")
	}
	if ln.Contains("192.168.1.10") || ln.Contains("100.64.0.8") {
		t.Fatal("addresses outside the configured ranges must not be local")
	}
	if _, err := ParseLocalNetworks([]string{"300.1.1.1/8"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}
