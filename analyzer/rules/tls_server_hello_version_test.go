package rules

import "testing"

func TestParseServerHelloExtensionsSelectedVersion(t *testing.T) {
	info := &TLSServerInfo{}
	exts := []byte{
		0x00, 0x2b, // extension type 43
		0x00, 0x02, // length
		0x03, 0x04, // TLS1.3
	}

	parseServerHelloExtensions(exts, info)

	if info.SelectedVersion != 0x0304 {
		t.Fatalf("unexpected selected version: %#04x", info.SelectedVersion)
	}
}

func TestObservedTLSVersionPrefersServerHelloSelectedVersion(t *testing.T) {
	ctx := &Context{
		TLSInfo: &TLSClientHelloInfo{
			ClientVersion:     0x0303,
			SupportedVersions: []uint16{0x0304, 0x0303},
		},
		TLSServerInfo: &TLSServerInfo{
			ServerVersion:   0x0303,
			SelectedVersion: 0x0304,
		},
	}

	if got := ObservedTLSVersion(ctx); got != 0x0304 {
		t.Fatalf("ObservedTLSVersion=%#04x, want %#04x", got, 0x0304)
	}
}

func TestObservedTLSVersionFallsBackInPriorityOrder(t *testing.T) {
	tests := []struct {
		name string
		ctx  *Context
		want uint16
	}{
		{
			name: "client supported versions",
			ctx: &Context{
				TLSInfo: &TLSClientHelloInfo{
					ClientVersion:     0x0303,
					SupportedVersions: []uint16{0x0304, 0x0303},
				},
			},
			want: 0x0304,
		},
		{
			name: "server legacy version",
			ctx: &Context{
				TLSServerInfo: &TLSServerInfo{
					ServerVersion: 0x0303,
				},
			},
			want: 0x0303,
		},
		{
			name: "client legacy version",
			ctx: &Context{
				TLSInfo: &TLSClientHelloInfo{
					ClientVersion: 0x0301,
				},
			},
			want: 0x0301,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ObservedTLSVersion(tt.ctx); got != tt.want {
				t.Fatalf("ObservedTLSVersion=%#04x, want %#04x", got, tt.want)
			}
		})
	}
}

func TestObservedTLSVersionUsesServerLegacyVersionOverClientOffer(t *testing.T) {
	// A client offering TLS 1.3 in supported_versions, answered by a server
	// that does not know the extension and selects TLS 1.0.
	ctx := &Context{
		TLSInfo:       &TLSClientHelloInfo{ClientVersion: 0x0303, SupportedVersions: []uint16{0x0304, 0x0303}},
		TLSServerInfo: &TLSServerInfo{ServerVersion: 0x0301},
	}
	if got := ObservedTLSVersion(ctx); got != 0x0301 {
		t.Fatalf("ObservedTLSVersion=%#04x, want %#04x", got, 0x0301)
	}
}

func TestServerChoseWeakerTLS(t *testing.T) {
	tests := []struct {
		name   string
		client *TLSClientHelloInfo
		server *TLSServerInfo
		want   bool
	}{
		{"client offered 1.2, server chose 1.0", &TLSClientHelloInfo{ClientVersion: 0x0303}, &TLSServerInfo{ServerVersion: 0x0301}, true},
		{"client offered only 1.0", &TLSClientHelloInfo{ClientVersion: 0x0301}, &TLSServerInfo{ServerVersion: 0x0301}, false},
		{"server chose 1.2", &TLSClientHelloInfo{ClientVersion: 0x0303}, &TLSServerInfo{ServerVersion: 0x0303}, false},
		{"no ServerHello", &TLSClientHelloInfo{ClientVersion: 0x0303}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ServerChoseWeakerTLS(tt.client, tt.server); got != tt.want {
				t.Fatalf("ServerChoseWeakerTLS=%v, want %v", got, tt.want)
			}
		})
	}
}
