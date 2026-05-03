package reportapi

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadInventoryMissingFileReturnsEmptyDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device_inventory.json")

	got, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(got.Devices) != 0 {
		t.Fatalf("Devices=%d, want 0", len(got.Devices))
	}
}

func TestLoadInventoryInvalidJSONReturnsEmptyDevices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "device_inventory.json")
	if err := os.WriteFile(path, []byte("{"), 0644); err != nil {
		t.Fatalf("write inventory json: %v", err)
	}

	got, err := LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(got.Devices) != 0 {
		t.Fatalf("Devices=%d, want 0", len(got.Devices))
	}
}
