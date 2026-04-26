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

type I4KnownVulnCandidate struct {
	Vendor            string   `json:"vendor"`
	VendorAliases     []string `json:"vendor_aliases,omitempty"`
	Family            string   `json:"family"`
	Aliases           []string `json:"aliases"`
	Categories        []string `json:"categories"`
	ExampleCVEs       []string `json:"example_cves"`
	KEV               bool     `json:"kev"`
	RecommendedChecks []string `json:"recommended_checks"`
	Notes             string   `json:"notes"`
}

type I4KnownVulnCandidates struct {
	Candidates []I4KnownVulnCandidate `json:"candidates"`
}

type I5MatchSignals struct {
	VendorKeywords []string `json:"vendor_keywords"`
	HostKeywords   []string `json:"host_keywords"`
	UAKeywords     []string `json:"ua_keywords"`
	SNIKeywords    []string `json:"sni_keywords"`
}

type I5VulnerableComponent struct {
	ID                 string         `json:"id"`
	Category           string         `json:"category"`
	Vendor             string         `json:"vendor"`
	Family             string         `json:"family"`
	MatchLevel         string         `json:"match_level,omitempty"`
	MatchSignals       I5MatchSignals `json:"match_signals"`
	KnownIssues        []string       `json:"known_issues"`
	RepresentativeCVEs []string       `json:"representative_cves"`
	Source             string         `json:"source,omitempty"`
	LastReviewed       string         `json:"last_reviewed,omitempty"`
	Severity           string         `json:"severity"`
	Recommendation     []string       `json:"recommendation"`
}

type I5VulnerableComponents []I5VulnerableComponent

type DeviceFamilySignature struct {
	Family               string   `json:"family"`
	Vendor               string   `json:"vendor"`
	Category             string   `json:"category"`
	HostKeywords         []string `json:"host_keywords"`
	SNIKeywords          []string `json:"sni_keywords"`
	UAKeywords           []string `json:"ua_keywords"`
	ServerKeywords       []string `json:"server_keywords"`
	PathKeywords         []string `json:"path_keywords"`
	StrongHostKeywords   []string `json:"strong_host_keywords,omitempty"`
	WeakHostKeywords     []string `json:"weak_host_keywords,omitempty"`
	StrongSNIKeywords    []string `json:"strong_sni_keywords,omitempty"`
	WeakSNIKeywords      []string `json:"weak_sni_keywords,omitempty"`
	StrongUAKeywords     []string `json:"strong_ua_keywords,omitempty"`
	WeakUAKeywords       []string `json:"weak_ua_keywords,omitempty"`
	StrongServerKeywords []string `json:"strong_server_keywords,omitempty"`
	WeakServerKeywords   []string `json:"weak_server_keywords,omitempty"`
	StrongPathKeywords   []string `json:"strong_path_keywords,omitempty"`
	WeakPathKeywords     []string `json:"weak_path_keywords,omitempty"`
	JA3Hashes            []string `json:"ja3_hashes,omitempty"`
	Ports                []int    `json:"ports,omitempty"`
	MinScoreForMatch     float64  `json:"min_score_for_match,omitempty"`
}

type DeviceFamilySignatures struct {
	Families []DeviceFamilySignature `json:"families"`
}

type I6StorageSignalPattern struct {
	Signal         string   `json:"signal"`
	Keywords       []string `json:"keywords"`
	Methods        []string `json:"methods"`
	MinUploadBytes int      `json:"min_upload_bytes"`
	RiskSignal     string   `json:"risk_signal"`
	NotesEN        string   `json:"notes_en"`
	NotesJA        string   `json:"notes_ja"`
}

type I6StorageSignalPatterns struct {
	Patterns []I6StorageSignalPattern `json:"patterns"`
}

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

func LoadI4KnownVulnCandidates() (*I4KnownVulnCandidates, error) {
	path := filepath.Join(knowledgeDir, "i4_known_vuln_candidates.json")

	var v I4KnownVulnCandidates
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadI5VulnerableComponents() (*I5VulnerableComponents, error) {
	path := filepath.Join(knowledgeDir, "i5_vulnerable_components.json")

	var v I5VulnerableComponents
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadDeviceFamilySignatures() (*DeviceFamilySignatures, error) {
	path := filepath.Join(knowledgeDir, "device_family_signatures.json")

	var v DeviceFamilySignatures
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

func LoadI6StorageSignalPatterns() (*I6StorageSignalPatterns, error) {
	path := filepath.Join(knowledgeDir, "i6_storage_signal_patterns.json")

	var v I6StorageSignalPatterns
	if err := loadJSON(path, &v); err != nil {
		return nil, err
	}

	return &v, nil
}

type DB struct {
	DeviceCategories   *DeviceCategories
	CommunicationTypes *CommunicationTypes
	PIITypes           *PIITypes
	CategoryPolicy     CategoryPolicy
	CategoryInference  *CategoryInferenceDB
	BehaviorBaselines  CategoryBehaviorBaselines
	I4KnownVuln        *I4KnownVulnCandidates
	I5Vulnerable       *I5VulnerableComponents
	DeviceFamilies     *DeviceFamilySignatures
	I6StorageSignals   *I6StorageSignalPatterns
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

	i4KnownVuln, err := LoadI4KnownVulnCandidates()
	if err != nil {
		return nil, err
	}

	i5Vulnerable, err := LoadI5VulnerableComponents()
	if err != nil {
		return nil, err
	}

	deviceFamilies, err := LoadDeviceFamilySignatures()
	if err != nil {
		return nil, err
	}

	i6StorageSignals, err := LoadI6StorageSignalPatterns()
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
		I4KnownVuln:        i4KnownVuln,
		I5Vulnerable:       i5Vulnerable,
		DeviceFamilies:     deviceFamilies,
		I6StorageSignals:   i6StorageSignals,
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
