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

type DB struct {
	DeviceCategories   *DeviceCategories
	CommunicationTypes *CommunicationTypes
	PIITypes           *PIITypes
	CategoryPolicy     CategoryPolicy
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

	return &DB{
		DeviceCategories:   deviceCategories,
		CommunicationTypes: communicationTypes,
		PIITypes:           piiTypes,
		CategoryPolicy:     categoryPolicy,
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
