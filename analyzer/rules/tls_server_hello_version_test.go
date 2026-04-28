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
