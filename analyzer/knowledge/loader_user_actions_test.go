package knowledge

import (
	"testing"
)

func TestLoadUserActionCatalog(t *testing.T) {
	// An empty override directory simulates a missing optional file
	// without touching the repository copy.
	t.Setenv(DirEnv, t.TempDir())

	catalog, err := LoadUserActionCatalog()
	if err != nil {
		t.Fatalf("expected missing user_actions.json to be tolerated, got: %v", err)
	}
	if len(catalog) != 0 {
		t.Fatalf("expected empty catalog, got: %+v", catalog)
	}
}

func TestLoadKnownDevicesMissingFileReturnsEmptyCatalog(t *testing.T) {
	// An empty override directory simulates a missing optional file
	// without touching the repository copy.
	t.Setenv(DirEnv, t.TempDir())

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
