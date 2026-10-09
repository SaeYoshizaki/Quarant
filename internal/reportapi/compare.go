package reportapi

import (
	"fmt"
	"path/filepath"
	"strings"
)

type ProtectionSnapshot struct {
	Label         string            `json:"label"`
	EventsPath    string            `json:"events_path"`
	FlowsPath     string            `json:"flows_path"`
	InventoryPath string            `json:"inventory_path"`
	Window        Window            `json:"window"`
	Protection    ProtectionSummary `json:"protection"`
}

type ProtectionComparison struct {
	Before         ProtectionSnapshot `json:"before"`
	After          ProtectionSnapshot `json:"after"`
	Deltas         []MetricDelta      `json:"deltas"`
	ImprovedCount  int                `json:"improved_count"`
	RegressedCount int                `json:"regressed_count"`
	UnchangedCount int                `json:"unchanged_count"`
	Summary        string             `json:"summary"`
}

type MetricDelta struct {
	Key       string `json:"key"`
	Label     string `json:"label"`
	Before    int    `json:"before"`
	After     int    `json:"after"`
	Delta     int    `json:"delta"`
	Direction string `json:"direction"`
	Improved  bool   `json:"improved"`
}

func LoadProtectionSnapshot(label, eventsPath, flowsPath, inventoryPath string) (ProtectionSnapshot, error) {
	if strings.TrimSpace(eventsPath) == "" {
		return ProtectionSnapshot{}, fmt.Errorf("%s events path is required", label)
	}
	dir := filepath.Dir(eventsPath)
	if dir == "." {
		dir = ""
	}
	flowsPath = defaultReportSibling(flowsPath, dir, "flows.jsonl")
	inventoryPath = defaultReportSibling(inventoryPath, dir, "device_inventory.json")

	report, err := LoadReport(eventsPath)
	if err != nil {
		return ProtectionSnapshot{}, err
	}
	inventory, err := LoadInventoryWithFallback(inventoryPath, eventsPath, flowsPath)
	if err != nil {
		return ProtectionSnapshot{}, err
	}
	flows, err := LoadFlows(flowsPath)
	if err != nil {
		return ProtectionSnapshot{}, err
	}
	protection := BuildProtectionSummary(
		report.Events,
		flows,
		inventory.Devices,
		report.UnknownDevices,
		report.QuarantineCandidates,
	)
	return ProtectionSnapshot{
		Label:         strings.TrimSpace(label),
		EventsPath:    eventsPath,
		FlowsPath:     flowsPath,
		InventoryPath: inventoryPath,
		Window:        report.Window,
		Protection:    protection,
	}, nil
}

func CompareProtectionSnapshots(before, after ProtectionSnapshot) ProtectionComparison {
	deltas := []MetricDelta{
		makeDelta("home_risk_score", "Home Risk Score", before.Protection.HomeRiskScore, after.Protection.HomeRiskScore, true),
		makeDelta("high_risk_devices", "High-risk devices", before.Protection.Metrics.HighRiskDevices, after.Protection.Metrics.HighRiskDevices, true),
		makeDelta("devices_with_risk", "Devices with risk", before.Protection.Metrics.DevicesWithRisk, after.Protection.Metrics.DevicesWithRisk, true),
		makeDelta("unknown_devices", "Unknown devices", before.Protection.Metrics.UnknownDevices, after.Protection.Metrics.UnknownDevices, true),
		makeDelta("external_destinations", "External destinations", before.Protection.Metrics.ExternalDestinationCount, after.Protection.Metrics.ExternalDestinationCount, true),
		makeDelta("plaintext_traffic", "Plaintext traffic signals", before.Protection.Metrics.PlaintextTrafficCount, after.Protection.Metrics.PlaintextTrafficCount, true),
		makeDelta("insecure_services", "Insecure service signals", before.Protection.Metrics.InsecureServiceCount, after.Protection.Metrics.InsecureServiceCount, true),
		makeDelta("critical_events", "Critical events", before.Protection.Metrics.CriticalEventCount, after.Protection.Metrics.CriticalEventCount, true),
		makeDelta("quarantine_candidates", "Quarantine candidates", before.Protection.Metrics.QuarantineCandidates, after.Protection.Metrics.QuarantineCandidates, true),
		makeDelta("novel_destinations", "Novel destinations", before.Protection.Metrics.NovelDestinationCount, after.Protection.Metrics.NovelDestinationCount, true),
		makeDelta("category_deviations", "Category deviations", before.Protection.Metrics.CategoryDeviationCount, after.Protection.Metrics.CategoryDeviationCount, true),
		makeDelta("passive_coverage", "Passive coverage", before.Protection.PassiveCoverage.Score, after.Protection.PassiveCoverage.Score, false),
		makeDelta("baseline_ready_devices", "Baseline-ready devices", before.Protection.Metrics.BaselineReadyDevices, after.Protection.Metrics.BaselineReadyDevices, false),
	}

	comparison := ProtectionComparison{
		Before: before,
		After:  after,
		Deltas: deltas,
	}
	for _, delta := range deltas {
		switch {
		case delta.Delta == 0:
			comparison.UnchangedCount++
		case delta.Improved:
			comparison.ImprovedCount++
		default:
			comparison.RegressedCount++
		}
	}
	comparison.Summary = comparisonSummary(comparison)
	return comparison
}

func makeDelta(key, label string, before, after int, lowerIsBetter bool) MetricDelta {
	delta := after - before
	direction := "unchanged"
	if delta > 0 {
		direction = "increased"
	} else if delta < 0 {
		direction = "decreased"
	}
	improved := false
	if delta != 0 {
		if lowerIsBetter {
			improved = delta < 0
		} else {
			improved = delta > 0
		}
	}
	return MetricDelta{
		Key:       key,
		Label:     label,
		Before:    before,
		After:     after,
		Delta:     delta,
		Direction: direction,
		Improved:  improved,
	}
}

func comparisonSummary(comparison ProtectionComparison) string {
	riskDelta := findDelta(comparison.Deltas, "home_risk_score")
	if riskDelta == nil {
		return "No home risk comparison was available."
	}
	switch {
	case riskDelta.Delta < 0:
		return fmt.Sprintf("Home Risk Score improved by %d points.", -riskDelta.Delta)
	case riskDelta.Delta > 0:
		return fmt.Sprintf("Home Risk Score worsened by %d points.", riskDelta.Delta)
	default:
		return "Home Risk Score was unchanged."
	}
}

func findDelta(deltas []MetricDelta, key string) *MetricDelta {
	for i := range deltas {
		if deltas[i].Key == key {
			return &deltas[i]
		}
	}
	return nil
}

func defaultReportSibling(explicit, dir, name string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}
