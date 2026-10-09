package reportapi

import "testing"

func TestBuildDeviceJudgmentMarksInsufficientEvidenceUnknown(t *testing.T) {
	got := BuildDeviceJudgment(DeviceEvidenceProfile{IP: "192.168.1.40"})

	if got.State != "unknown" {
		t.Fatalf("State=%q, want unknown: %+v", got.State, got)
	}
	if got.EvidenceReadiness != "insufficient" {
		t.Fatalf("EvidenceReadiness=%q, want insufficient", got.EvidenceReadiness)
	}
	if got.Confidence != "low" {
		t.Fatalf("Confidence=%q, want low", got.Confidence)
	}
	if !deferredDecisionKeyExists(got.DeferredDecisions, "defer_firmware_assessment") {
		t.Fatalf("DeferredDecisions=%+v, want firmware deferral", got.DeferredDecisions)
	}
}

func TestBuildDeviceJudgmentMarksUnknownUDPAsSuspiciousAndDeferred(t *testing.T) {
	got := BuildDeviceJudgment(DeviceEvidenceProfile{
		IP:               "192.168.1.41",
		ObservationCount: 1,
		ObservedEvidence: DeviceObservedEvidence{
			Protocols:       []string{"udp"},
			Ports:           []uint16{9001},
			UnknownUDPPorts: []uint16{9001},
		},
	})

	if got.State != "suspicious" {
		t.Fatalf("State=%q, want suspicious: %+v", got.State, got)
	}
	if got.EvidenceReadiness != "partial" {
		t.Fatalf("EvidenceReadiness=%q, want partial", got.EvidenceReadiness)
	}
	if !judgmentFindingKeyExists(got.Findings, "unknown_udp") {
		t.Fatalf("Findings=%+v, want unknown_udp", got.Findings)
	}
	if !deferredDecisionKeyExists(got.DeferredDecisions, "defer_unknown_udp_block") {
		t.Fatalf("DeferredDecisions=%+v, want defer_unknown_udp_block", got.DeferredDecisions)
	}
}
