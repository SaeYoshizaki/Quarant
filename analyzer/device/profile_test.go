package device

import (
	"fmt"
	"testing"
	"time"
)

func TestObservationRepeatExpiresAfterWindow(t *testing.T) {
	p := NewProfile("10.0.0.2")

	if got := p.ObserveStableIdentifierFingerprint("fp-a", 100); got != 1 {
		t.Fatalf("expected first identifier observation count 1, got %d", got)
	}
	if got := p.ObserveStableIdentifierFingerprint("fp-a", 200); got != 2 {
		t.Fatalf("expected second identifier observation count 2, got %d", got)
	}
	if got := p.ObserveStableIdentifierFingerprint("fp-a", 200+ObservationWindowSeconds+1); got != 1 {
		t.Fatalf("expected expired identifier observation to reset to 1, got %d", got)
	}
}

func TestObservationMapPrunesToLimit(t *testing.T) {
	p := NewProfile("10.0.0.3")

	for i := 0; i < MaxObservationKeys+10; i++ {
		p.ObserveStorageSignalEndpoint(fmt.Sprintf("endpoint-%d", i), int64(100+i))
	}

	if len(p.StorageSignalEndpoints) > MaxObservationKeys {
		t.Fatalf("expected storage observation map to be capped at %d, got %d", MaxObservationKeys, len(p.StorageSignalEndpoints))
	}
}

func TestPIIUseDestinationDistinctIgnoresExpiredObservations(t *testing.T) {
	p := NewProfile("10.0.0.4")

	if repeat, distinct := p.ObservePIIUseDestination("email", "one.example", 100); repeat != 1 || distinct != 1 {
		t.Fatalf("expected first destination repeat=1 distinct=1, got repeat=%d distinct=%d", repeat, distinct)
	}
	if repeat, distinct := p.ObservePIIUseDestination("email", "two.example", 200); repeat != 1 || distinct != 2 {
		t.Fatalf("expected second destination repeat=1 distinct=2, got repeat=%d distinct=%d", repeat, distinct)
	}
	if repeat, distinct := p.ObservePIIUseDestination("email", "two.example", 200+ObservationWindowSeconds+1); repeat != 1 || distinct != 1 {
		t.Fatalf("expected old destinations to expire, got repeat=%d distinct=%d", repeat, distinct)
	}
}

func TestInventorySnapshotIncludesObservedStateAndRiskSummary(t *testing.T) {
	p := NewProfile("10.0.0.20")
	now := time.Date(2026, 4, 26, 0, 0, 0, 0, time.UTC)

	p.ObserveActivity(now)
	p.ObserveActivity(now.Add(10 * time.Minute))
	p.Protocols["http"] = true
	p.Protocols["mqtt"] = true
	p.Ports[80] = true
	p.Ports[1883] = true
	p.Hosts["api.vendor-cloud.test"] = true
	p.SNIValues["example.com"] = true
	p.Identity.VendorCandidate = "Philips"
	p.Identity.VendorConfidence = "low"
	p.Identity.FamilyCandidate = "philips_hue_hub"
	p.Identity.FamilyConfidence = "low"
	p.Classification = Classification{
		Category:        "GenericIoT",
		InferenceSource: InferenceSourceUnknown,
		ConfidenceLabel: "very_low",
	}
	p.RecordRiskEvent(now.Add(5*time.Minute), "I3_AUTH_TOKEN_IN_URL", "HIGH", []string{"I3", "I7", "I9"})
	p.RecordRiskEvent(now.Add(10*time.Minute), "I2_HTTP_ADMIN_INTERFACE_SUSPECTED", "WARNING", []string{"I2", "I3", "I9"})

	snapshot := p.Snapshot()
	if snapshot.IP != "10.0.0.20" {
		t.Fatalf("unexpected ip: %s", snapshot.IP)
	}
	if snapshot.FirstSeen != "2026-04-26T00:00:00Z" || snapshot.LastSeen != "2026-04-26T00:10:00Z" {
		t.Fatalf("unexpected seen window: first=%s last=%s", snapshot.FirstSeen, snapshot.LastSeen)
	}
	if !equalStrings(snapshot.ObservedProtocols, []string{"http", "mqtt"}) {
		t.Fatalf("unexpected protocols: %v", snapshot.ObservedProtocols)
	}
	if !equalPorts(snapshot.ObservedPorts, []uint16{80, 1883}) {
		t.Fatalf("unexpected ports: %v", snapshot.ObservedPorts)
	}
	if !equalStrings(snapshot.ObservedHosts, []string{"api.vendor-cloud.test"}) {
		t.Fatalf("unexpected hosts: %v", snapshot.ObservedHosts)
	}
	if !equalStrings(snapshot.ObservedSNI, []string{"example.com"}) {
		t.Fatalf("unexpected sni: %v", snapshot.ObservedSNI)
	}
	if snapshot.CategoryCandidate != "GenericIoT" || snapshot.CategoryConfidence != "very_low" {
		t.Fatalf("unexpected category summary: %+v", snapshot)
	}
	if snapshot.VendorCandidate != "Philips" || snapshot.FamilyCandidate != "philips_hue_hub" {
		t.Fatalf("unexpected identity summary: %+v", snapshot)
	}
	if snapshot.RiskEventCount != 2 {
		t.Fatalf("unexpected risk event count: %d", snapshot.RiskEventCount)
	}
	if snapshot.SeverityCounts["HIGH"] != 1 || snapshot.SeverityCounts["WARNING"] != 1 {
		t.Fatalf("unexpected severity counts: %v", snapshot.SeverityCounts)
	}
	if snapshot.OWASPTagCounts["I3"] != 2 || snapshot.OWASPTagCounts["I7"] != 1 || snapshot.OWASPTagCounts["I9"] != 2 || snapshot.OWASPTagCounts["I2"] != 1 {
		t.Fatalf("unexpected tag counts: %v", snapshot.OWASPTagCounts)
	}
	if snapshot.LastRiskEventType != "I2_HTTP_ADMIN_INTERFACE_SUSPECTED" || snapshot.LastRiskEventTS != "2026-04-26T00:10:00Z" {
		t.Fatalf("unexpected last risk event summary: %+v", snapshot)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func equalPorts(got, want []uint16) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
