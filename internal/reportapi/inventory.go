package reportapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type InventoryReport struct {
	GeneratedAt string            `json:"generated_at"`
	Devices     []InventoryDevice `json:"devices"`
}

type InventoryRiskSummary struct {
	RiskEventCount        int      `json:"risk_event_count,omitempty"`
	HighestSeverity       string   `json:"highest_severity,omitempty"`
	TopOWASPTags          []string `json:"top_owasp_tags,omitempty"`
	TopSeverities         []string `json:"top_severities,omitempty"`
	LastRiskEventType     string   `json:"last_risk_event_type,omitempty"`
	LastRiskEventTS       string   `json:"last_risk_event_ts,omitempty"`
	RecommendedNextAction string   `json:"recommended_next_action,omitempty"`
}

type InventoryDevice struct {
	IP                 string                `json:"ip"`
	FirstSeen          string                `json:"first_seen,omitempty"`
	LastSeen           string                `json:"last_seen,omitempty"`
	EventCount         int                   `json:"event_count,omitempty"`
	FlowCount          int                   `json:"flow_count,omitempty"`
	ObservedProtocols  []string              `json:"observed_protocols,omitempty"`
	ObservedPorts      []uint16              `json:"observed_ports,omitempty"`
	ObservedHosts      []string              `json:"observed_hosts,omitempty"`
	ObservedSNI        []string              `json:"observed_sni,omitempty"`
	CategoryCandidate  string                `json:"category_candidate,omitempty"`
	CategoryConfidence string                `json:"category_confidence,omitempty"`
	VendorCandidate    string                `json:"vendor_candidate,omitempty"`
	VendorConfidence   string                `json:"vendor_confidence,omitempty"`
	FamilyCandidate    string                `json:"family_candidate,omitempty"`
	FamilyConfidence   string                `json:"family_confidence,omitempty"`
	RiskEventCount     int                   `json:"risk_event_count,omitempty"`
	SeverityCounts     map[string]int        `json:"severity_counts,omitempty"`
	OWASPTagCounts     map[string]int        `json:"owasp_tag_counts,omitempty"`
	LastRiskEventType  string                `json:"last_risk_event_type,omitempty"`
	LastRiskEventTS    string                `json:"last_risk_event_ts,omitempty"`
	RiskSummary        *InventoryRiskSummary `json:"risk_summary,omitempty"`
}

func LoadInventory(path string) (InventoryReport, error) {
	return loadInventory(path)
}

func LoadInventoryWithFallback(path, eventsPath, flowsPath string) (InventoryReport, error) {
	base, err := loadInventory(path)
	if err != nil {
		return InventoryReport{}, err
	}
	eventsReport, err := loadEventsJSONLReport(eventsPath)
	if err != nil {
		return InventoryReport{}, err
	}
	flows, err := loadFlowRecords(flowsPath)
	if err != nil {
		return InventoryReport{}, err
	}
	return mergeInventoryWithObserved(base, derivedInventoryFromObservations(eventsReport.Events, flows)), nil
}

func loadInventory(path string) (InventoryReport, error) {
	if strings.TrimSpace(path) == "" {
		return InventoryReport{Devices: []InventoryDevice{}}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return InventoryReport{Devices: []InventoryDevice{}}, nil
		}
		return InventoryReport{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return InventoryReport{Devices: []InventoryDevice{}}, nil
	}

	var report InventoryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return InventoryReport{Devices: []InventoryDevice{}}, nil
	}
	if report.Devices == nil {
		report.Devices = []InventoryDevice{}
	}
	return report, nil
}
