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
