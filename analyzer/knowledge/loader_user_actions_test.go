package knowledge

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUserActionCatalog(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	catalog, err := LoadUserActionCatalog()
	if err != nil {
		t.Fatalf("load user action catalog: %v", err)
	}

	action, ok := catalog["CONFIRM_DEVICE_OWNER"]
	if !ok {
		t.Fatal("expected CONFIRM_DEVICE_OWNER to exist")
	}
	if action.Label == "" || action.Description == "" {
		t.Fatalf("expected populated action, got: %+v", action)
	}
}

func TestKnownDevicesLookupReturnsFalseForUnknownDevice(t *testing.T) {
	catalog := &KnownDevicesCatalog{
		Devices: []KnownDeviceRecord{
			{DeviceKey: "10.0.1.2", Label: "Test PC", Trusted: true, Status: "allowed"},
		},
		index: map[string]KnownDeviceRecord{
			"10.0.1.2": {DeviceKey: "10.0.1.2", Label: "Test PC", Trusted: true, Status: "allowed"},
		},
	}

	if _, ok := catalog.Lookup("10.0.1.99"); ok {
		t.Fatal("expected unknown device lookup to fail")
	}
}

func TestLoadUserActionCatalogMissingFileReturnsEmptyCatalog(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	path := filepath.Join("knowledge", "user_actions.json")
	backup := filepath.Join("knowledge", "user_actions.json.bak.test")
	if err := os.Rename(path, backup); err != nil {
		t.Fatalf("rename user_actions.json: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Rename(backup, path)
	})

	catalog, err := LoadUserActionCatalog()
	if err != nil {
		t.Fatalf("expected missing user_actions.json to be tolerated, got: %v", err)
	}
	if len(catalog) != 0 {
		t.Fatalf("expected empty catalog, got: %+v", catalog)
	}
}

func TestLoadKnownDevicesMissingFileReturnsEmptyCatalog(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir to repo root: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(wd)
	})

	path := filepath.Join("knowledge", "known_devices.json")
	backup := filepath.Join("knowledge", "known_devices.json.bak.test")
	if err := os.Rename(path, backup); err != nil {
		t.Fatalf("rename known_devices.json: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Rename(backup, path)
	})

	catalog, err := LoadKnownDevices()
	if err != nil {
		t.Fatalf("expected missing known_devices.json to be tolerated, got: %v", err)
	}
	if catalog == nil {
		t.Fatal("expected non-nil empty catalog")
	}
	if len(catalog.Devices) != 0 {
		t.Fatalf("expected empty device list, got: %+v", catalog.Devices)
	}
	if _, ok := catalog.Lookup("10.0.1.2"); ok {
		t.Fatal("did not expect lookup hit in empty catalog")
	}
}
