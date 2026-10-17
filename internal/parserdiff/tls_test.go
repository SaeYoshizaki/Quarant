package parserdiff

import (
	"crypto/tls"
	"testing"

	"quarant/internal/synth"
)

func seedHellos() [][]byte {
	return [][]byte{
		synth.TLSClientHello("www.example.com", tls.VersionTLS12, tls.VersionTLS13),
		synth.TLSClientHello("ipc-cloud.example-cam.test", tls.VersionTLS10, tls.VersionTLS10),
		synth.TLSClientHello("", tls.VersionTLS12, tls.VersionTLS12),
	}
}

func TestParsersAgreeOnWellFormedHellos(t *testing.T) {
	for i, hello := range seedHellos() {
		res := CompareClientHello(hello)
		if res.Class() != "agree" {
			t.Errorf("seed %d: %s %+v", i, res.Class(), res.Mismatches)
		}
	}
}

// FuzzClientHelloDifferential looks for inputs on which Quarant and
// crypto/tls disagree. Rejections by both are fine; Quarant reporting a hello
// the reference rejects, or reading different fields, is a finding.
//
//	go test ./internal/parserdiff -fuzz FuzzClientHelloDifferential -fuzztime 60s
func FuzzClientHelloDifferential(f *testing.F) {
	for _, h := range seedHellos() {
		f.Add(h)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := CompareClientHello(data)
		switch res.Class() {
		case "agree", "both_reject", "lenient_unparsed_extension", "reference_lenient_rfc_invalid":
		default:
			t.Errorf("%s: %+v", res.Class(), res.Mismatches)
		}
	})
}
