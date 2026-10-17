package device

import (
	"testing"
	"time"
)

var linkTime = time.Date(2016, 9, 24, 10, 0, 0, 0, time.UTC)

func viaOf(p *DeviceProfile, attribute, value string) (string, bool) {
	for _, e := range p.IdentityEvidenceList() {
		if e.Attribute == attribute && e.Value == value {
			return e.Via, true
		}
	}
	return "", false
}

func TestSameMACSharesSelfDescriptions(t *testing.T) {
	s := NewStore()
	v4 := s.GetOrCreate("192.168.1.249")
	v6 := s.GetOrCreate("fe80::216:6cff:feab:6b88")
	s.LinkMAC(v4, "00:16:6c:ab:6b:88")
	s.LinkMAC(v6, "00:16:6c:ab:6b:88")

	// The camera announces RTSP only from its IPv6 link-local address.
	v6.AddIdentityEvidence(linkTime, "mdns_service", "_rtsp._tcp.local", "observed", "mdns")

	if got := v4.Classification.NormalizedCategory(); got != "Camera" {
		t.Fatalf("IPv4 profile category = %q, want Camera from the shared announcement", got)
	}
	if via, ok := viaOf(v4, "mdns_service", "_rtsp._tcp.local"); !ok || via != ViaSameMAC {
		t.Fatalf("shared evidence via = %q (present %v), want %q", via, ok, ViaSameMAC)
	}
	if via, ok := viaOf(v6, "mdns_service", "_rtsp._tcp.local"); !ok || via != "" {
		t.Fatalf("own evidence via = %q (present %v), want empty", via, ok)
	}
}

func TestSharingLinksEvidenceRecordedBeforeBinding(t *testing.T) {
	s := NewStore()
	a := s.GetOrCreate("192.168.1.10")
	a.AddIdentityEvidence(linkTime, "ssdp_device_type", "urn:Belkin:device:sensor:1", "observed", "ssdp")
	s.LinkMAC(a, "ec:1a:59:83:28:11")
	b := s.GetOrCreate("fe80::1")
	s.LinkMAC(b, "ec:1a:59:83:28:11")
	if got := b.Classification.NormalizedCategory(); got != "Sensor" {
		t.Fatalf("category = %q, want Sensor", got)
	}
}

func TestAlternatingIPv4StopsSharing(t *testing.T) {
	s := NewStore()
	a := s.GetOrCreate("192.168.1.20")
	b := s.GetOrCreate("192.168.1.21")
	mac := "aa:bb:cc:00:00:01"
	s.LinkMAC(a, mac)
	a.AddIdentityEvidence(linkTime, "hostname", "Little Cam", "observed", "dhcp")
	s.LinkMAC(b, mac) // one-way change: DHCP renumbering, still shared
	if got := b.Classification.NormalizedCategory(); got != "Camera" {
		t.Fatalf("after renumbering category = %q, want Camera", got)
	}
	s.LinkMAC(a, mac) // back to the first address: two hosts behind one MAC
	if got := b.Classification.NormalizedCategory(); got == "Camera" {
		t.Fatalf("after alternation the other host still inherits the category")
	}
	if _, ok := viaOf(b, "hostname", "Little Cam"); ok {
		t.Fatalf("after alternation shared evidence is still listed")
	}
	if len(s.ExportIdentityState().Devices) != 0 {
		t.Fatalf("an ambiguous MAC must not be saved")
	}
}

func TestIdentityStateRoundTrip(t *testing.T) {
	first := NewStore()
	p := first.GetOrCreate("192.168.1.30")
	first.LinkMAC(p, "74:c6:3b:29:d7:1d")
	p.AddIdentityEvidence(linkTime, "mdns_service", "_hap._tcp.local", "observed", "mdns")
	p.AddIdentityEvidence(linkTime, "mdns_txt", "c#=2 ci=7", "observed", "mdns")
	p.AddIdentityEvidence(linkTime, "mac", "74:c6:3b:29:d7:1d", "observed", "ethernet")
	state := first.ExportIdentityState()
	for _, e := range state.Devices["74:c6:3b:29:d7:1d"] {
		if e.Attribute == "mac" {
			t.Fatalf("non-self-describing attribute saved: %+v", e)
		}
	}

	// Next day: the plug does not announce itself again.
	next := NewStore()
	next.ImportIdentityState(state)
	q := next.GetOrCreate("192.168.1.30")
	next.LinkMAC(q, "74:C6:3B:29:D7:1D")
	if got := q.Classification.NormalizedCategory(); got != "Controller" {
		t.Fatalf("category = %q, want Controller from the earlier capture", got)
	}
	via, ok := viaOf(q, "mdns_txt", "c#=2 ci=7")
	if !ok || via != ViaEarlierCapture {
		t.Fatalf("via = %q (present %v), want %q", via, ok, ViaEarlierCapture)
	}
	for _, e := range q.IdentityEvidenceList() {
		if e.Attribute == "mdns_txt" && e.FirstSeen != "2016-09-24T10:00:00Z" {
			t.Fatalf("earlier evidence lost its capture time: %+v", e)
		}
	}

	// Seen again in this capture: no longer marked as earlier.
	r := next.GetOrCreate("fe80::76c6:3bff:fe29:d71d")
	next.LinkMAC(r, "74:c6:3b:29:d7:1d")
	r.AddIdentityEvidence(linkTime.Add(24*time.Hour), "mdns_txt", "c#=2 ci=7", "observed", "mdns")
	if via, _ := viaOf(q, "mdns_txt", "c#=2 ci=7"); via != ViaSameMAC {
		t.Fatalf("re-announced evidence via = %q, want %q", via, ViaSameMAC)
	}
}
