package reportapi

import (
	"testing"
	"time"
)

func TestBuildProtectionSummaryScoresHomeAndDevices(t *testing.T) {
	events := []Event{
		{
			Type:       "I7_HTTP_TOKEN",
			RuleID:     "I7_HTTP_TOKEN",
			Category:   "I7",
			Severity:   "CRITICAL",
			Confidence: "high",
			SrcIP:      "192.168.1.10",
			DstIP:      "8.8.8.8",
		},
		{
			Type:       "I2_TELNET_SERVICE_OBSERVED",
			RuleID:     "I2_TELNET_SERVICE_OBSERVED",
			Category:   "I2",
			Severity:   "HIGH",
			Confidence: "high",
			SrcIP:      "192.168.1.10",
			DstIP:      "192.168.1.1",
		},
		{
			Type:       "I8_NEW_DEVICE_OBSERVED",
			RuleID:     "I8_NEW_DEVICE_OBSERVED",
			Category:   "I8",
			Severity:   "INFO",
			Confidence: "medium",
			DeviceKey:  "192.168.1.30",
		},
	}
	flows := []FlowRecord{
		{
			FlowKey:             "tcp|camera",
			SrcIP:               "192.168.1.10",
			DstIP:               "8.8.8.8",
			DstPort:             80,
			Protocol:            "tcp",
			AppProtocol:         "http",
			Direction:           "external",
			ObservedDestination: "api.camera.example",
			Host:                "api.camera.example",
		},
	}
	devices := []InventoryDevice{
		{IP: "192.168.1.10", CategoryCandidate: "Camera"},
		{IP: "192.168.1.30", CategoryCandidate: "Unknown"},
	}

	got := BuildProtectionSummary(events, flows, devices, 0, 0)

	if got.HomeRiskScore < 60 {
		t.Fatalf("HomeRiskScore=%d, want >= 60", got.HomeRiskScore)
	}
	if got.RiskLevel != "high" && got.RiskLevel != "critical" {
		t.Fatalf("RiskLevel=%q, want high or critical", got.RiskLevel)
	}
	if got.Metrics.DeviceCount != 3 {
		t.Fatalf("DeviceCount=%d, want 3", got.Metrics.DeviceCount)
	}
	if got.Metrics.PlaintextTrafficCount != 1 {
		t.Fatalf("PlaintextTrafficCount=%d, want 1", got.Metrics.PlaintextTrafficCount)
	}
	if got.Metrics.InsecureServiceCount != 1 {
		t.Fatalf("InsecureServiceCount=%d, want 1", got.Metrics.InsecureServiceCount)
	}
	if got.Metrics.ExternalDestinationCount != 1 {
		t.Fatalf("ExternalDestinationCount=%d, want 1", got.Metrics.ExternalDestinationCount)
	}
	if len(got.TopDevices) == 0 || got.TopDevices[0].IP != "192.168.1.10" {
		t.Fatalf("unexpected top devices: %+v", got.TopDevices)
	}
	if got.TopDevices[0].RiskScore < 60 {
		t.Fatalf("top device RiskScore=%d, want >= 60", got.TopDevices[0].RiskScore)
	}
	if got.PassiveCoverage.Score == 0 {
		t.Fatalf("PassiveCoverage.Score=%d, want > 0", got.PassiveCoverage.Score)
	}
}

func TestBuildProtectionSummaryDampensSingleLowConfidenceSignal(t *testing.T) {
	events := []Event{
		{
			Type:       "I8_NEW_DEVICE_OBSERVED",
			RuleID:     "I8_NEW_DEVICE_OBSERVED",
			Category:   "I8",
			Severity:   "WARNING",
			Confidence: "low",
			DeviceKey:  "192.168.1.40",
		},
	}

	got := BuildProtectionSummary(events, nil, nil, 0, 0)

	if len(got.TopDevices) != 1 {
		t.Fatalf("TopDevices=%d, want 1", len(got.TopDevices))
	}
	if got.TopDevices[0].RiskScore > 35 {
		t.Fatalf("RiskScore=%d, want dampened <= 35", got.TopDevices[0].RiskScore)
	}
	if got.TopDevices[0].RiskLevel == "high" || got.TopDevices[0].RiskLevel == "critical" {
		t.Fatalf("RiskLevel=%q, want not high/critical", got.TopDevices[0].RiskLevel)
	}
}

func TestBuildProtectionSummaryClassifiesHousekeepingTrafficAsNoise(t *testing.T) {
	flows := []FlowRecord{
		{
			FlowKey:     "udp|mdns",
			SrcIP:       "192.168.1.50",
			DstIP:       "224.0.0.251",
			DstPort:     5353,
			Protocol:    "udp",
			AppProtocol: "mdns",
		},
		{
			FlowKey:     "udp|ssdp",
			SrcIP:       "192.168.1.50",
			DstIP:       "239.255.255.250",
			DstPort:     1900,
			Protocol:    "udp",
			AppProtocol: "ssdp",
		},
		{
			FlowKey:     "udp|dhcp",
			SrcIP:       "192.168.1.50",
			DstIP:       "255.255.255.255",
			DstPort:     67,
			Protocol:    "udp",
			AppProtocol: "dhcp",
		},
		{
			FlowKey:             "tcp|cloud",
			SrcIP:               "192.168.1.50",
			DstIP:               "8.8.8.8",
			DstPort:             443,
			Protocol:            "tcp",
			AppProtocol:         "tls",
			ObservedDestination: "api.vendor.example",
		},
	}

	got := BuildProtectionSummary(nil, flows, nil, 0, 0)

	if got.Metrics.DeviceCount != 1 {
		t.Fatalf("DeviceCount=%d, want 1", got.Metrics.DeviceCount)
	}
	if got.Metrics.TotalFlowCount != 4 {
		t.Fatalf("TotalFlowCount=%d, want 4", got.Metrics.TotalFlowCount)
	}
	if got.Metrics.NoiseFlowCount != 3 {
		t.Fatalf("NoiseFlowCount=%d, want 3", got.Metrics.NoiseFlowCount)
	}
	if got.Metrics.MulticastBroadcastFlows != 3 {
		t.Fatalf("MulticastBroadcastFlows=%d, want 3", got.Metrics.MulticastBroadcastFlows)
	}
	if got.Metrics.ExternalFlowCount != 1 {
		t.Fatalf("ExternalFlowCount=%d, want 1", got.Metrics.ExternalFlowCount)
	}
	if got.Metrics.ExternalDestinationCount != 1 {
		t.Fatalf("ExternalDestinationCount=%d, want 1", got.Metrics.ExternalDestinationCount)
	}
}

func TestBuildProtectionSummaryLearnsDeviceBaselineAndFlagsNovelty(t *testing.T) {
	start := time.Date(2026, 9, 23, 10, 0, 0, 0, time.UTC)
	flows := []FlowRecord{
		{
			Timestamp:           start,
			FlowKey:             "tcp|baseline-a",
			SrcIP:               "192.168.1.60",
			DstIP:               "8.8.4.4",
			DstPort:             443,
			Protocol:            "tcp",
			AppProtocol:         "tls",
			ObservedDestination: "api.vendor.example",
		},
		{
			Timestamp:           start.Add(4 * time.Minute),
			FlowKey:             "tcp|baseline-b",
			SrcIP:               "192.168.1.60",
			DstIP:               "8.8.4.4",
			DstPort:             443,
			Protocol:            "tcp",
			AppProtocol:         "tls",
			ObservedDestination: "api.vendor.example",
		},
		{
			Timestamp:           start.Add(30 * time.Minute),
			FlowKey:             "tcp|novel",
			SrcIP:               "192.168.1.60",
			DstIP:               "1.1.1.1",
			DstPort:             8883,
			Protocol:            "tcp",
			AppProtocol:         "mqtt",
			ObservedDestination: "broker.unexpected.example",
		},
	}

	devices := []InventoryDevice{{IP: "192.168.1.60", CategoryCandidate: "Camera"}}

	got := BuildProtectionSummary(nil, flows, devices, 0, 0)

	if got.Baseline.DeviceCount != 1 {
		t.Fatalf("Baseline.DeviceCount=%d, want 1", got.Baseline.DeviceCount)
	}
	if got.Baseline.ReadyDeviceCount != 1 {
		t.Fatalf("Baseline.ReadyDeviceCount=%d, want 1", got.Baseline.ReadyDeviceCount)
	}
	if got.Metrics.NovelDestinationCount != 1 {
		t.Fatalf("NovelDestinationCount=%d, want 1", got.Metrics.NovelDestinationCount)
	}
	if got.Metrics.NovelProtocolCount != 1 {
		t.Fatalf("NovelProtocolCount=%d, want 1", got.Metrics.NovelProtocolCount)
	}
	if got.Metrics.NovelPortCount != 1 {
		t.Fatalf("NovelPortCount=%d, want 1", got.Metrics.NovelPortCount)
	}
	if got.Metrics.CategoryProfiledDevices != 1 {
		t.Fatalf("CategoryProfiledDevices=%d, want 1", got.Metrics.CategoryProfiledDevices)
	}
	if got.Metrics.CategoryDeviationCount != 2 {
		t.Fatalf("CategoryDeviationCount=%d, want 2", got.Metrics.CategoryDeviationCount)
	}
	if len(got.Baseline.Devices) != 1 || len(got.Baseline.Devices[0].NovelDestinations) != 1 {
		t.Fatalf("unexpected baseline devices: %+v", got.Baseline.Devices)
	}
	if got.Baseline.Devices[0].Category != "Camera" {
		t.Fatalf("Category=%q, want Camera", got.Baseline.Devices[0].Category)
	}
	if len(got.Baseline.Devices[0].UnexpectedProtocols) != 1 || got.Baseline.Devices[0].UnexpectedProtocols[0] != "MQTT" {
		t.Fatalf("UnexpectedProtocols=%+v, want MQTT", got.Baseline.Devices[0].UnexpectedProtocols)
	}
	if len(got.Baseline.Devices[0].UnexpectedPorts) != 1 || got.Baseline.Devices[0].UnexpectedPorts[0] != 8883 {
		t.Fatalf("UnexpectedPorts=%+v, want 8883", got.Baseline.Devices[0].UnexpectedPorts)
	}
	if len(got.TopDevices) == 0 || got.TopDevices[0].NoveltyCount != 3 {
		t.Fatalf("unexpected top device novelty: %+v", got.TopDevices)
	}
	if got.TopDevices[0].CategoryDeviations != 2 {
		t.Fatalf("CategoryDeviations=%d, want 2", got.TopDevices[0].CategoryDeviations)
	}
	if got.TopDevices[0].RiskScore == 0 {
		t.Fatalf("RiskScore=%d, want novelty to contribute risk", got.TopDevices[0].RiskScore)
	}
}
