package analyzer

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type packetCounter struct {
	count int
}

func (c *packetCounter) HandlePacket(gopacket.Packet) {
	c.count++
}

func TestRunPCAPStream(t *testing.T) {
	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	payload := gopacket.Payload([]byte("quarant-test-payload"))
	eth := &layers.Ethernet{
		SrcMAC:       []byte{0, 1, 2, 3, 4, 5},
		DstMAC:       []byte{6, 7, 8, 9, 10, 11},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    []byte{192, 168, 1, 10},
		DstIP:    []byte{192, 168, 1, 20},
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		SYN:     true,
		Seq:     1,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatalf("set tcp checksum network layer: %v", err)
	}

	packetBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(packetBuf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, eth, ip, tcp, payload); err != nil {
		t.Fatalf("serialize packet: %v", err)
	}

	packetData := packetBuf.Bytes()
	if err := writer.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Unix(0, 0),
		CaptureLength:  len(packetData),
		Length:         len(packetData),
		InterfaceIndex: 0,
	}, packetData); err != nil {
		t.Fatalf("write packet: %v", err)
	}

	counter := &packetCounter{}
	engine := NewEngine(counter)
	if err := engine.RunPCAPStream(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("run pcap stream: %v", err)
	}
	if counter.count != 1 {
		t.Fatalf("expected 1 packet, got %d", counter.count)
	}
}
