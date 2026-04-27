package device

import (
	"fmt"
	"testing"
	"time"

	"quarant/analyzer/rules"
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
	if snapshot.RiskSummary == nil {
		t.Fatalf("expected risk summary: %+v", snapshot)
	}
	if snapshot.RiskSummary.HighestSeverity != "HIGH" {
		t.Fatalf("unexpected highest severity: %+v", snapshot.RiskSummary)
	}
	if !equalStrings(snapshot.RiskSummary.TopOWASPTags, []string{"I3", "I9", "I2", "I7"}) {
		t.Fatalf("unexpected top OWASP tags: %v", snapshot.RiskSummary.TopOWASPTags)
	}
	if !equalStrings(snapshot.RiskSummary.TopSeverities, []string{"HIGH", "WARNING"}) {
		t.Fatalf("unexpected top severities: %v", snapshot.RiskSummary.TopSeverities)
	}
	if snapshot.RiskSummary.RecommendedNextAction != "Review plaintext API usage, token handling, and ecosystem interface transport security." {
		t.Fatalf("unexpected recommended action: %q", snapshot.RiskSummary.RecommendedNextAction)
	}
}

func TestInventorySnapshotRiskSummaryUsesDeterministicOrderingAndLimit(t *testing.T) {
	p := NewProfile("10.0.0.29")
	now := time.Date(2026, 4, 26, 1, 0, 0, 0, time.UTC)

	p.ObserveActivity(now)
	p.RecordRiskEvent(now.Add(time.Minute), "I7_HTTP_AUTH", "WARNING", []string{"I7", "I3", "I9", "I2", "I6", "I5", "I4"})
	p.RecordRiskEvent(now.Add(2*time.Minute), "I5_KNOWN_VULNERABLE_COMPONENT", "CRITICAL", []string{"I7", "I3", "I9", "I2", "I6", "I5"})
	p.RecordRiskEvent(now.Add(3*time.Minute), "I3_AUTH_TOKEN_IN_URL", "HIGH", []string{"I7", "I3", "I9", "I2", "I6"})
	p.RecordRiskEvent(now.Add(4*time.Minute), "I9_DEFAULT_HOSTNAME_PATTERN", "LOW", []string{"I7", "I3", "I9", "I2"})
	p.RecordRiskEvent(now.Add(5*time.Minute), "I2_TELNET_SERVICE_OBSERVED", "MEDIUM", []string{"I7", "I3", "I9"})
	p.RecordRiskEvent(now.Add(6*time.Minute), "I6_PRIVACY_DESTINATION", "INFO", []string{"I7", "I3"})

	snapshot := p.Snapshot()
	if snapshot.RiskSummary == nil {
		t.Fatalf("expected risk summary")
	}
	if snapshot.RiskSummary.HighestSeverity != "CRITICAL" {
		t.Fatalf("expected CRITICAL highest severity, got %+v", snapshot.RiskSummary)
	}
	if !equalStrings(snapshot.RiskSummary.TopOWASPTags, []string{"I3", "I7", "I9", "I2", "I6"}) {
		t.Fatalf("unexpected top OWASP tags ordering/limit: %v", snapshot.RiskSummary.TopOWASPTags)
	}
	if !equalStrings(snapshot.RiskSummary.TopSeverities, []string{"CRITICAL", "HIGH", "MEDIUM", "WARNING", "LOW"}) {
		t.Fatalf("unexpected top severities ordering/limit: %v", snapshot.RiskSummary.TopSeverities)
	}
}

func TestInventorySnapshotRiskSummaryOmittedForInfoOnly(t *testing.T) {
	p := NewProfile("10.0.0.30")
	now := time.Date(2026, 4, 26, 2, 0, 0, 0, time.UTC)

	p.RecordRiskEvent(now, "DEVICE_DEBUG", "INFO", []string{"I6"})

	snapshot := p.Snapshot()
	if snapshot.RiskSummary != nil {
		t.Fatalf("info-only device should not include risk summary: %+v", snapshot.RiskSummary)
	}
}

func TestInventorySnapshotOmitsPhilipsHueForGenericUbuntuDemoSignals(t *testing.T) {
	p := NewProfile("10.0.0.21")

	EnrichFromHTTP(p, map[string]string{"host": "api.vendor-cloud.test"})
	AddHTTPBehaviorHints(p, nil, 80, false)
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/api/config"}, 80, false)
	EnrichFromHTTP(p, map[string]string{"host": "device.local"})
	AddHTTPBehaviorHints(p, &rules.HTTPInfo{Path: "/setup"}, 80, false)
	EnrichFromHTTP(p, map[string]string{"host": "example.com"})

	snapshot := p.Snapshot()
	if snapshot.VendorCandidate != "" || snapshot.FamilyCandidate != "" {
		t.Fatalf("generic ubuntu demo signals should not populate Philips Hue identity in inventory snapshot: %+v", snapshot)
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
