package device

import (
	"fmt"
	"testing"
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
