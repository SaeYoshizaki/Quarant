package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func TestAnalyzePCAPWritesOutputs(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(repoRoot); err != nil {
		t.Fatalf("chdir repo root: %v", err)
	}
	defer func() {
		_ = os.Chdir(wd)
	}()

	dir := t.TempDir()
	pcapPath := filepath.Join(dir, "sample.pcap")
	eventsPath := filepath.Join(dir, "events.jsonl")
	flowsPath := filepath.Join(dir, "flows.jsonl")

	writeTestPCAP(t, pcapPath)

	err = analyzePCAP(analysisConfig{
		InputPath:         pcapPath,
		EventsOut:         eventsPath,
		FlowsOut:          flowsPath,
		InventoryOut:      "",
		InventoryInterval: time.Second,
		Debug:             false,
	})
	if err != nil {
		t.Fatalf("analyzePCAP: %v", err)
	}

	eventsData, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	flowsData, err := os.ReadFile(flowsPath)
	if err != nil {
		t.Fatalf("read flows: %v", err)
	}
	if len(eventsData) == 0 {
		t.Fatal("expected events output to be non-empty")
	}
	if flowsData == nil {
		t.Fatal("expected flows output file to be readable")
	}
}

func TestNormalizeFlagArgsKeepsPositionalAfterFlags(t *testing.T) {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.String("addr", "127.0.0.1:8080", "")
	fs.Bool("open", false, "")

	got := normalizeFlagArgs(fs, []string{"report.json", "--open", "--addr", "127.0.0.1:18082"})
	want := []string{"--open", "--addr", "127.0.0.1:18082", "report.json"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeFlagArgs=%v, want %v", got, want)
	}
}

func writeTestPCAP(t *testing.T, path string) {
	t.Helper()

	var buf bytes.Buffer
	writer := pcapgo.NewWriter(&buf)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}

	payload := gopacket.Payload([]byte("GET / HTTP/1.1\r\nHost: test.local\r\n\r\n"))
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
		ACK:     true,
		PSH:     true,
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

	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write pcap file: %v", err)
	}
}
