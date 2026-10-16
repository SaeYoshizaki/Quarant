package devicereport

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/device"
)

func TestBuild(t *testing.T) {
	ts := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	in := Inputs{
		Inventory: []device.InventorySnapshot{
			{IP: "192.168.1.20", MACAddress: "da:00:00:00:00:01", MACRandomized: true, FirstSeen: ts.Format(time.RFC3339)},
			{IP: "192.168.1.30"},
		},
		Flows: []analyzer.FlowRecord{
			{Timestamp: ts, FlowKey: "a", SrcIP: "192.168.1.20", DstIP: "198.51.100.1", Protocol: "tcp", PacketCount: 1},
			{Timestamp: ts.Add(time.Second), FlowKey: "a", SrcIP: "192.168.1.20", DstIP: "198.51.100.1", Protocol: "tls", ObservedDestination: "api.example", BytesOut: 10},
			{Timestamp: ts, FlowKey: "b", SrcIP: "192.168.1.30", DstIP: "192.168.1.20", Protocol: "telnet"},
		},
		Events: []analyzer.Event{
			{Timestamp: ts, Type: "INSECURE_HTTP", Severity: "WARNING", Basis: "observed", DeviceKey: "192.168.1.20"},
			{Timestamp: ts.Add(time.Minute), Type: "INSECURE_HTTP", Severity: "HIGH", Basis: "observed", DeviceKey: "192.168.1.20"},
			{Timestamp: ts, Type: "I5_KNOWN_VULNERABLE_COMPONENT", Severity: "WARNING", Basis: "reference_match", DeviceKey: "192.168.1.20"},
			{Timestamp: ts, Type: "TLS_CLIENT_HELLO", Severity: "INFO", DeviceKey: "192.168.1.20"},
			{Timestamp: ts, Type: "I8_NEW_DEVICE_OBSERVED", Severity: "INFO", DeviceKey: "203.0.113.9"},
		},
	}
	rep := Build(in, ts)
	if len(rep.Devices) != 2 {
		t.Fatalf("devices: %+v", rep.Devices)
	}
	cam := rep.Devices[0]
	if cam.IP != "192.168.1.20" || cam.Activity.Flows != 2 || cam.Activity.EncryptedFlows != 1 {
		t.Fatalf("activity: %+v", cam.Activity)
	}
	if len(cam.Findings) != 2 || cam.Findings[0].Type != "INSECURE_HTTP" || cam.Findings[0].Count != 2 || cam.Findings[0].Severity != "HIGH" {
		t.Fatalf("findings: %+v", cam.Findings)
	}
	if cam.FindingCounts["WARNING"]["reference_match"] != 1 || cam.FindingCounts["HIGH"]["observed"] != 1 {
		t.Fatalf("counts: %+v", cam.FindingCounts)
	}
	joined := strings.Join(cam.Visibility, " ")
	if !strings.Contains(joined, "locally administered") || !strings.Contains(joined, "No DHCP") || !strings.Contains(joined, "TLS-encrypted") {
		t.Fatalf("visibility: %v", cam.Visibility)
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, rep)
	if !strings.Contains(buf.String(), "inbound from 192.168.1.30") {
		t.Fatalf("markdown missing inbound flow:\n%s", buf.String())
	}
}
