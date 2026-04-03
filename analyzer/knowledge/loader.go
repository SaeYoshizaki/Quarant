package knowledge

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const knowledgeDir = "knowledge"

type DeviceCategories struct {
	Categories []string `json:"categories"`
}

type CommunicationTypes struct {
	CommunicationTypes []string `json:"communication_types"`
}

type PIITypes struct {
	PIITypes []string `json:"pii_types"`
}

type SuspiciousCombination struct {
	CommunicationType string `json:"communication_type"`
	PIIType           string `json:"pii_type"`
}

type CategoryPolicyEntry struct {
	AllowedCommunicationTypes []string                `json:"allowed_communication_types"`
	AllowedPIITypes           []string                `json:"allowed_pii_types"`
	SuspiciousCombinations    []SuspiciousCombination `json:"suspicious_combinations"`
}

type CategoryPolicy map[string]CategoryPolicyEntry

type OfficialSource struct {
	Vendor  string `json:"vendor"`
	URL     string `json:"url"`
	Notes   string `json:"notes"`
	NotesEN string `json:"notes_en"`
	NotesJA string `json:"notes_ja"`
}

type CategoryInferenceEntry struct {
	Category                string           `json:"category"`
	RecordCount             int              `json:"record_count"`
	Confidence              float64          `json:"confidence"`
	ConfidenceLevel         string           `json:"confidence_level"`
	VendorCandidates        []string         `json:"vendor_candidates"`
	RepresentativeDomains   []string         `json:"representative_domains"`
	EcosystemDomains        []string         `json:"ecosystem_domains"`
	RepresentativeProtocols []string         `json:"representative_protocols"`
	ObservedDeviceLabels    []string         `json:"observed_device_labels"`
	SourceBreakdown         map[string]int   `json:"source_breakdown"`
	OfficialSources         []OfficialSource `json:"official_sources"`
}

type CategoryInferenceDB struct {
	Categories map[string]CategoryInferenceEntry `json:"categories"`
}

type CategoryBehaviorBaseline struct {
	ExpectedCommunicationTypes []string `json:"expected_communication_types"`
	ExpectedProtocols          []string `json:"expected_protocols"`
	ExpectedDomainPatterns     []string `json:"expected_domain_patterns"`
	CommonPorts                []int    `json:"common_ports"`
	LocalAdminExpected         bool     `json:"local_admin_expected"`
	PlaintextTolerance         string   `json:"plaintext_tolerance"`
	ExpectedFrequency          string   `json:"expected_frequency"`
	SuspiciousPatterns         []string `json:"suspicious_patterns"`
	NotesEN                    string   `json:"notes_en"`
	NotesJA                    string   `json:"notes_ja"`
}

type CategoryBehaviorBaselines map[string]CategoryBehaviorBaseline

func loadJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unmarshal %s: %w", path, err)
	}

	return nil
}

func LoadDeviceCategories() (*DeviceCategories, error) {
	path := filepath.Join(knowledgeDir, "device_categories.json")

	var v DeviceCategories
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadCommunicationTypes() (*CommunicationTypes, error) {
	path := filepath.Join(knowledgeDir, "communication_types.json")

	var v CommunicationTypes
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadPIITypes() (*PIITypes, error) {
	path := filepath.Join(knowledgeDir, "pii_types.json")

	var v PIITypes
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadCategoryPolicy() (CategoryPolicy, error) {
	path := filepath.Join(knowledgeDir, "category_policy.json")

	var v CategoryPolicy
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return v, nil
}

func LoadCategoryInferenceDB() (*CategoryInferenceDB, error) {
	path := filepath.Join(knowledgeDir, "category_inference_db.json")

	var v CategoryInferenceDB
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadCategoryBehaviorBaselines() (CategoryBehaviorBaselines, error) {
	path := filepath.Join(knowledgeDir, "category_behavior_baselines.json")

	var v CategoryBehaviorBaselines
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return v, nil
}

type DB struct {
	DeviceCategories   *DeviceCategories
	CommunicationTypes *CommunicationTypes
	PIITypes           *PIITypes
	CategoryPolicy     CategoryPolicy
	CategoryInference  *CategoryInferenceDB
	BehaviorBaselines  CategoryBehaviorBaselines
}

func LoadAll() (*DB, error) {
	deviceCategories, err := LoadDeviceCategories()
	if err != nil {
		return nil, err
	}

	communicationTypes, err := LoadCommunicationTypes()
	if err != nil {
		return nil, err
	}

	piiTypes, err := LoadPIITypes()
	if err != nil {
		return nil, err
	}

	categoryPolicy, err := LoadCategoryPolicy()
	if err != nil {
		return nil, err
	}

	categoryInference, err := LoadCategoryInferenceDB()
	if err != nil {
		return nil, err
	}

	behaviorBaselines, err := LoadCategoryBehaviorBaselines()
	if err != nil {
		return nil, err
	}

	return &DB{
		DeviceCategories:   deviceCategories,
		CommunicationTypes: communicationTypes,
		PIITypes:           piiTypes,
		CategoryPolicy:     categoryPolicy,
		CategoryInference:  categoryInference,
		BehaviorBaselines:  behaviorBaselines,
	}, nil
}

func (db *DB) IsKnownCategory(category string) bool {
	if db == nil || db.DeviceCategories == nil {
		return false
	}

	for _, c := range db.DeviceCategories.Categories {
		if c == category {
			return true
		}
	}
	return false
}

func (db *DB) IsKnownCommunicationType(commType string) bool {
	if db == nil || db.CommunicationTypes == nil {
		return false
	}

	for _, t := range db.CommunicationTypes.CommunicationTypes {
		if t == commType {
			return true
		}
	}
	return false
}

func (db *DB) IsKnownPIIType(piiType string) bool {
	if db == nil || db.PIITypes == nil {
		return false
	}

	for _, t := range db.PIITypes.PIITypes {
		if t == piiType {
			return true
		}
	}
	return false
}

func (db *DB) IsAllowedCommunicationType(category, commType string) bool {
	if db == nil {
		return false
	}

	entry, ok := db.CategoryPolicy[category]
	if !ok {
		return false
	}

	for _, t := range entry.AllowedCommunicationTypes {
		if t == commType {
			return true
		}
	}
	return false
}

func (db *DB) IsAllowedPIIType(category, piiType string) bool {
	if db == nil {
		return false
	}

	entry, ok := db.CategoryPolicy[category]
	if !ok {
		return false
	}

	for _, t := range entry.AllowedPIITypes {
		if t == piiType {
			return true
		}
	}
	return false
}

func (db *DB) IsSuspiciousCombination(category, commType, piiType string) bool {
	if db == nil {
		return false
	}

	entry, ok := db.CategoryPolicy[category]
	if !ok {
		return false
	}

	for _, comb := range entry.SuspiciousCombinations {
		if comb.CommunicationType == commType && comb.PIIType == piiType {
			return true
		}
	}
	return false
}

func (db *DB) GetBehaviorBaseline(category string) (CategoryBehaviorBaseline, bool) {
	if db == nil {
		return CategoryBehaviorBaseline{}, false
	}

	entry, ok := db.BehaviorBaselines[category]
	return entry, ok
}

func (db *DB) GetCategoryInference(category string) (CategoryInferenceEntry, bool) {
	if db == nil || db.CategoryInference == nil {
		return CategoryInferenceEntry{}, false
	}

	entry, ok := db.CategoryInference.Categories[category]
	return entry, ok
}
