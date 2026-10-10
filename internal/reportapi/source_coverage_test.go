package reportapi

import "testing"

func TestBuildSourceCoverageReportFromInputsCountsOverlap(t *testing.T) {
	report := BuildSourceCoverageReportFromInputs([]SourceCoverageInput{
		{
			Source:   "openwrt",
			Security: []SecurityEvent{{Source: "openwrt_firewall", DeviceIP: "192.168.8.42", DstIP: "192.168.8.42", DstPort: 80, Protocol: "tcp"}},
		},
		{
			Source:   "suricata",
			Security: []SecurityEvent{{Source: "suricata", Engine: "suricata", DeviceIP: "192.168.8.42", DstIP: "192.168.8.42", DstPort: 80, Protocol: "tcp"}},
		},
		{
			Source: "zeek",
			Flows:  []FlowRecord{{SrcIP: "192.168.8.42", DstIP: "198.51.100.10", DstPort: 80, Protocol: "tcp", AppProtocol: "http"}},
		},
	})
	if report.Metrics.OpenWrtSuricataOverlap != 1 || report.Metrics.MultiSourceServiceCount != 1 {
		t.Fatalf("metrics=%+v, want OpenWrt/Suricata overlap", report.Metrics)
	}
	if len(report.BySource) != 3 {
		t.Fatalf("bySource=%+v, want three sources", report.BySource)
	}
	if len(report.ClaimSupport) == 0 {
		t.Fatalf("ClaimSupport empty, want coverage claims")
	}
}
