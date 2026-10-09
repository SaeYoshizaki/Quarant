package main

import (
	"bytes"
	"encoding/json"
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

func TestRunCompareOutputsJSON(t *testing.T) {
	dir := t.TempDir()
	beforeDir := filepath.Join(dir, "before")
	afterDir := filepath.Join(dir, "after")
	if err := os.MkdirAll(beforeDir, 0755); err != nil {
		t.Fatalf("mkdir before: %v", err)
	}
	if err := os.MkdirAll(afterDir, 0755); err != nil {
		t.Fatalf("mkdir after: %v", err)
	}

	beforeEvents := filepath.Join(beforeDir, "events.jsonl")
	afterEvents := filepath.Join(afterDir, "events.jsonl")
	if err := os.WriteFile(beforeEvents, []byte(`{"ts":"2026-09-23T00:00:00Z","type":"I7_HTTP_TOKEN","rule_id":"I7_HTTP_TOKEN","category":"I7","severity":"CRITICAL","confidence":"high","src_ip":"192.168.1.10","dst_ip":"8.8.8.8"}`+"\n"), 0644); err != nil {
		t.Fatalf("write before events: %v", err)
	}
	if err := os.WriteFile(afterEvents, []byte(`{"ts":"2026-09-24T00:00:00Z","type":"I8_NEW_DEVICE_OBSERVED","rule_id":"I8_NEW_DEVICE_OBSERVED","category":"I8","severity":"INFO","confidence":"low","device_key":"192.168.1.10"}`+"\n"), 0644); err != nil {
		t.Fatalf("write after events: %v", err)
	}
	if err := os.WriteFile(filepath.Join(beforeDir, "flows.jsonl"), []byte(`{"ts":"2026-09-23T00:00:00Z","flow_key":"tcp|before","src_ip":"192.168.1.10","dst_ip":"8.8.8.8","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","observed_destination":"api.before.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write before flows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(afterDir, "flows.jsonl"), []byte(`{"ts":"2026-09-24T00:00:00Z","flow_key":"tcp|after","src_ip":"192.168.1.10","dst_ip":"8.8.4.4","dst_port":443,"protocol":"tcp","app_protocol":"tls","direction":"external","observed_destination":"api.after.example"}`+"\n"), 0644); err != nil {
		t.Fatalf("write after flows: %v", err)
	}
	if err := os.WriteFile(filepath.Join(beforeDir, "device_inventory.json"), []byte(`{"devices":[{"ip":"192.168.1.10","category_candidate":"Camera"}]}`), 0644); err != nil {
		t.Fatalf("write before inventory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(afterDir, "device_inventory.json"), []byte(`{"devices":[{"ip":"192.168.1.10","category_candidate":"Camera"}]}`), 0644); err != nil {
		t.Fatalf("write after inventory: %v", err)
	}

	var out bytes.Buffer
	err := runCompare([]string{"--before", beforeEvents, "--after", afterEvents, "--format", "json"}, &out)
	if err != nil {
		t.Fatalf("runCompare: %v", err)
	}

	var payload struct {
		Summary string `json:"summary"`
		Deltas  []struct {
			Key   string `json:"key"`
			Delta int    `json:"delta"`
		} `json:"deltas"`
	}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal output: %v\n%s", err, out.String())
	}
	if payload.Summary == "" {
		t.Fatalf("empty summary in output: %s", out.String())
	}
	if len(payload.Deltas) == 0 {
		t.Fatalf("expected deltas in output: %s", out.String())
	}
}

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
	observationsPath := filepath.Join(dir, "observations.jsonl")

	writeTestPCAP(t, pcapPath)

	err = analyzePCAP(analysisConfig{
		InputPath:         pcapPath,
		EventsOut:         eventsPath,
		FlowsOut:          flowsPath,
		ObservationsOut:   observationsPath,
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
	observationsData, err := os.ReadFile(observationsPath)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	if len(eventsData) == 0 {
		t.Fatal("expected events output to be non-empty")
	}
	if flowsData == nil {
		t.Fatal("expected flows output file to be readable")
	}
	if len(observationsData) == 0 {
		t.Fatal("expected observations output to be non-empty")
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
