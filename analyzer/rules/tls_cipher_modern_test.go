package rules

import "testing"

func TestHasModernOfferedTLSCipher(t *testing.T) {
	cases := []struct {
		name   string
		suites []uint16
		want   bool
	}{
		{"tls13 suite", []uint16{0x1301}, true},
		{"ecdhe gcm", []uint16{0x000A, 0xC02F}, true},
		{"chacha20", []uint16{0xCCA8}, true},
		{"legacy only", []uint16{0x002F, 0x000A, 0x0005}, false},
		{"grease and scsv are not modern", []uint16{0x0A0A, 0x00FF, 0x002F}, false},
	}
	for _, tc := range cases {
		if got := HasModernOfferedTLSCipher(tc.suites); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestWeakCipherOfferedIgnoresCBCFallbacks(t *testing.T) {
	rule := &I7TLSLegacyCipherOfferedRule{}
	ctx := &Context{TLSInfo: &TLSClientHelloInfo{CipherSuites: []uint16{0x1301, 0xC02F, 0xC013, 0x002F}}}
	if _, ok := rule.Apply(ctx); ok {
		t.Fatal("CBC suites offered alongside AEAD suites must not be reported")
	}
	ctx.TLSInfo.CipherSuites = append(ctx.TLSInfo.CipherSuites, 0x000A)
	if _, ok := rule.Apply(ctx); !ok {
		t.Fatal("3DES offered should still be reported")
	}
}
