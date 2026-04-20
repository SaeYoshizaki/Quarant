package analyzer

import (
	"net"
	"testing"

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
