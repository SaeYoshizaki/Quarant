package analyzer

import (
	"net"
	"testing"
	"time"

	"quarant/analyzer/device"
	"quarant/analyzer/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestPacketIPStringsIPv4(t *testing.T) {
	packet := gopacket.NewPacket([]byte{
		0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x06, 0x00, 0x00, 0xc0, 0x00, 0x02, 0x0a,
		0x5d, 0xb8, 0xd8, 0x22,
	}, layers.LayerTypeIPv4, gopacket.Default)

	src, dst, ok := packetIPStrings(packet)
	if !ok {
		t.Fatal("expected IPv4 packet IPs")
	}
	if src != "192.0.2.10" || dst != "93.184.216.34" {
		t.Fatalf("unexpected IPs: src=%s dst=%s", src, dst)
	}
}

func TestFlowKeyTCPFormatsIPv6Endpoints(t *testing.T) {
	got := flowKeyTCP("2001:db8::10", 12345, "2001:4860:4860::8888", 443)
	want := "tcp|[2001:4860:4860::8888]:443<->[2001:db8::10]:12345"
	if got != want {
		t.Fatalf("unexpected flow key: %s", got)
	}
}

func TestPacketIPStringsIPv6(t *testing.T) {
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::10"),
		DstIP:      net.ParseIP("2001:4860:4860::8888"),
	}
	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true}, ip); err != nil {
		t.Fatalf("serialize IPv6 packet: %v", err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)

	src, dst, ok := packetIPStrings(packet)
	if !ok {
		t.Fatal("expected IPv6 packet IPs")
	}
	if src != "2001:db8::10" || dst != "2001:4860:4860::8888" {
		t.Fatalf("unexpected IPs: src=%s dst=%s", src, dst)
	}
}

func TestObservedProtocolsForFlow(t *testing.T) {
	got := observedProtocolsForFlow(1883, nil, &rules.MQTTInfo{PacketName: "CONNECT"}, nil, false)
	want := []string{"mqtt"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected protocols: got=%v want=%v", got, want)
	}

	got = observedProtocolsForFlow(443, &rules.HTTPInfo{Path: "/"}, nil, nil, true)
	want = []string{"https", "tls"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("unexpected tls protocols: got=%v want=%v", got, want)
	}
}

func TestFlowHandlerDeviceInventorySnapshot(t *testing.T) {
	h := &FlowHandler{devices: device.NewStore()}
	d := h.devices.GetOrCreate("10.0.1.2")
	observeDeviceFlow(d, time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC), 1883, []string{"mqtt"})
	d.Hosts["api.vendor-cloud.test"] = true
	d.SNIValues["example.com"] = true
	d.RecordRiskEvent(time.Date(2026, 4, 26, 0, 10, 0, 0, time.UTC), "I3_AUTH_TOKEN_IN_URL", "HIGH", []string{"I3", "I7"})

	snapshots := h.DeviceInventory()
	if len(snapshots) != 1 {
		t.Fatalf("expected one snapshot, got %d", len(snapshots))
	}
	if snapshots[0].IP != "10.0.1.2" {
		t.Fatalf("unexpected snapshot ip: %s", snapshots[0].IP)
	}
	if snapshots[0].RiskEventCount != 1 || snapshots[0].OWASPTagCounts["I3"] != 1 {
		t.Fatalf("unexpected risk summary: %+v", snapshots[0])
	}
	if snapshots[0].ObservedProtocols[0] != "mqtt" {
		t.Fatalf("unexpected protocols: %v", snapshots[0].ObservedProtocols)
	}
}

func TestObservedDestinationPriority(t *testing.T) {
	if got := observedDestination("api.example.com", "www.example.com", "34.117.59.81"); got != "api.example.com" {
		t.Fatalf("expected SNI priority, got %q", got)
	}
	if got := observedDestination("", "www.example.com", "34.117.59.81"); got != "www.example.com" {
		t.Fatalf("expected host fallback, got %q", got)
	}
	if got := observedDestination("", "", "34.117.59.81"); got != "34.117.59.81" {
		t.Fatalf("expected dst fallback, got %q", got)
	}
}

func TestFlowDirectionClassification(t *testing.T) {
	cases := []struct {
		dstIP string
		want  string
	}{
		{dstIP: "192.168.1.10", want: "local"},
		{dstIP: "10.0.0.1", want: "local"},
		{dstIP: "127.0.0.1", want: "local"},
		{dstIP: "169.254.10.20", want: "local"},
		{dstIP: "34.117.59.81", want: "external"},
		{dstIP: "", want: "unknown"},
	}
	for _, tt := range cases {
		if got := flowDirection(tt.dstIP); got != tt.want {
			t.Fatalf("flowDirection(%q)=%q, want %q", tt.dstIP, got, tt.want)
		}
	}
}

func TestBuildFlowRecordUsesStateMetadata(t *testing.T) {
	h := &FlowHandler{devices: device.NewStore()}
	d := h.devices.GetOrCreate("192.168.1.10")
	d.Classification = device.Classification{Category: "Camera"}

	st := &FlowState{
		SrcIP:         "192.168.1.10",
		SrcPort:       52344,
		DstIP:         "34.117.59.81",
		DstPort:       443,
		PacketCount:   42,
		ClientBytes:   3210,
		ServerBytes:   15420,
		TLSClientSeen: true,
		TLSClientInfo: &rules.TLSClientHelloInfo{SNI: "api.example.com"},
	}

	record := h.buildFlowRecord(time.Date(2026, 4, 28, 12, 0, 0, 0, time.UTC), flowKeyTCP(st.SrcIP, st.SrcPort, st.DstIP, st.DstPort), st)
	if record.Protocol != "tls" || record.AppProtocol != "https" {
		t.Fatalf("unexpected protocol fields: %+v", record)
	}
	if record.ObservedDestination != "api.example.com" {
		t.Fatalf("unexpected observed destination: %+v", record)
	}
	if record.Direction != "external" {
		t.Fatalf("unexpected direction: %+v", record)
	}
	if record.DeviceCategory != "Camera" {
		t.Fatalf("unexpected device category: %+v", record)
	}
}
