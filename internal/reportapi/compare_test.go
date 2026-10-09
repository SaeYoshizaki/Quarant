package reportapi

import "testing"

func TestCompareProtectionSnapshotsReportsImprovement(t *testing.T) {
	before := ProtectionSnapshot{
		Label: "before",
		Protection: ProtectionSummary{
			HomeRiskScore:   80,
			PassiveCoverage: PassiveCoverage{Score: 50},
			Metrics: ProtectionMetrics{
				HighRiskDevices:          3,
				DevicesWithRisk:          5,
				UnknownDevices:           2,
				ExternalDestinationCount: 8,
				PlaintextTrafficCount:    4,
				CategoryDeviationCount:   3,
			},
		},
	}
	after := ProtectionSnapshot{
		Label: "after",
		Protection: ProtectionSummary{
			HomeRiskScore:   35,
			PassiveCoverage: PassiveCoverage{Score: 75},
			Metrics: ProtectionMetrics{
				HighRiskDevices:          1,
				DevicesWithRisk:          2,
				UnknownDevices:           0,
				ExternalDestinationCount: 4,
				PlaintextTrafficCount:    1,
				CategoryDeviationCount:   1,
			},
		},
	}

	got := CompareProtectionSnapshots(before, after)

	if got.Summary != "Home Risk Score improved by 45 points." {
		t.Fatalf("Summary=%q", got.Summary)
	}
	if got.ImprovedCount == 0 {
		t.Fatalf("ImprovedCount=%d, want > 0", got.ImprovedCount)
	}
	risk := findDelta(got.Deltas, "home_risk_score")
	if risk == nil || risk.Delta != -45 || !risk.Improved {
		t.Fatalf("unexpected risk delta: %+v", risk)
	}
	coverage := findDelta(got.Deltas, "passive_coverage")
	if coverage == nil || coverage.Delta != 25 || !coverage.Improved {
		t.Fatalf("unexpected coverage delta: %+v", coverage)
	}
}
