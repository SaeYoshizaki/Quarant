package rules

import "testing"

func TestParseExtensionsSupportedVersions(t *testing.T) {
	info := &TLSClientHelloInfo{}
	exts := []byte{
		0x00, 0x2b, // extension type 43
		0x00, 0x05, // length
		0x04,       // vector length
		0x03, 0x04, // TLS1.3
		0x03, 0x03, // TLS1.2
	}

	parseExtensions(exts, info)

	if len(info.SupportedVersions) != 2 {
		t.Fatalf("expected 2 supported versions, got %d", len(info.SupportedVersions))
	}
	if info.SupportedVersions[0] != 0x0304 || info.SupportedVersions[1] != 0x0303 {
		t.Fatalf("unexpected supported versions: %#v", info.SupportedVersions)
	}
}
