package rules

import (
	"strings"
	"testing"

	"quarant/analyzer/knowledge"
)

func TestI6StoredDataSignalSuppressesPrivacySensitiveCategoryAlone(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "stored_history_upload",
					Keywords:       []string{"history"},
					Methods:        []string{"POST", "PUT", "PATCH"},
					MinUploadBytes: 512,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/history/upload",
			Headers: map[string]string{"host": "api.example.com"},
			RawLine: "POST /v1/history/upload HTTP/1.1",
		},
		UploadBytes: 2048,
	}

	if matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Camera"); len(matches) != 0 {
		t.Fatalf("expected privacy-sensitive category alone to be suppressed, got %d", len(matches))
	}
}

func TestI6StoredDataSignalEmitsForPrivacySensitiveCategoryWithAccumulatedUpload(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "stored_history_upload",
					Keywords:       []string{"history"},
					Methods:        []string{"POST", "PUT", "PATCH"},
					MinUploadBytes: 512,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/history/upload",
			Headers: map[string]string{"host": "api.example.com"},
			RawLine: "POST /v1/history/upload HTTP/1.1",
		},
		UploadBytes: 4096,
	}

	matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Camera")
	if len(matches) != 1 {
		t.Fatalf("expected one storage signal, got %d", len(matches))
	}
	if matches[0].RuleID != "I6_STORED_DATA_SIGNAL_OBSERVED" {
		t.Fatalf("unexpected rule id: %s", matches[0].RuleID)
	}
	if !strings.Contains(matches[0].Evidence, "indirect_at_rest=true") {
		t.Fatalf("expected indirect at-rest evidence, got: %s", matches[0].Evidence)
	}
	if !strings.Contains(matches[0].Evidence, "corroboration=accumulated_upload,privacy_sensitive_category") {
		t.Fatalf("expected combined corroboration, got: %s", matches[0].Evidence)
	}
}

func TestI6StoredDataSignalSuppressesFirstBenignCategoryCandidate(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "backup_sync_upload",
					Keywords:       []string{"sync"},
					Methods:        []string{"POST"},
					MinUploadBytes: 1024,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/sync",
			Headers: map[string]string{"host": "api.example.com"},
			RawLine: "POST /v1/sync HTTP/1.1",
		},
		UploadBytes: 2048,
	}

	if matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Sensor"); len(matches) != 0 {
		t.Fatalf("expected first benign-category candidate to be suppressed, got %d", len(matches))
	}
}

func TestI6StoredDataSignalEmitsForRepeatedEndpoint(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "backup_sync_upload",
					Keywords:       []string{"sync"},
					Methods:        []string{"POST"},
					MinUploadBytes: 1024,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/sync",
			Headers: map[string]string{"host": "api.example.com"},
			RawLine: "POST /v1/sync HTTP/1.1",
		},
		UploadBytes:                2048,
		StorageEndpointRepeatCount: 2,
	}

	matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Sensor")
	if len(matches) != 1 {
		t.Fatalf("expected repeated endpoint to emit one storage signal, got %d", len(matches))
	}
	if !strings.Contains(matches[0].Evidence, "corroboration=repeated_storage_endpoint") {
		t.Fatalf("expected repeated endpoint corroboration, got: %s", matches[0].Evidence)
	}
}

func TestI6StoredDataSignalEmitsForRepeatedStableIdentifier(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "stored_history_upload",
					Keywords:       []string{"history"},
					Methods:        []string{"POST"},
					MinUploadBytes: 512,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/history",
			Headers: map[string]string{"host": "api.example.com", "x-device-id": "device-12345678"},
			RawLine: "POST /v1/history HTTP/1.1",
		},
		UploadBytes:                 1024,
		StableIdentifierRepeatCount: 2,
	}

	matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Appliance")
	if len(matches) != 1 {
		t.Fatalf("expected repeated stable identifier to emit one storage signal, got %d", len(matches))
	}
	if !strings.Contains(matches[0].Evidence, "stable_identifier_repeat_count=2") {
		t.Fatalf("expected stable identifier repeat count evidence, got: %s", matches[0].Evidence)
	}
}

func TestI6StoredDataSignalIgnoresSmallKeywordRequest(t *testing.T) {
	db := &knowledge.DB{
		I6StorageSignals: &knowledge.I6StorageSignalPatterns{
			Patterns: []knowledge.I6StorageSignalPattern{
				{
					Signal:         "backup_sync_upload",
					Keywords:       []string{"sync"},
					Methods:        []string{"POST"},
					MinUploadBytes: 1024,
					RiskSignal:     "stored_data_signal",
				},
			},
		},
	}

	ctx := &Context{
		HTTP: &HTTPInfo{
			Method:  "POST",
			Path:    "/v1/sync/ping",
			Headers: map[string]string{"host": "api.example.com"},
			RawLine: "POST /v1/sync/ping HTTP/1.1",
		},
		UploadBytes: 64,
	}

	if matches := (&I6PrivacyRule{db: db}).applyStorageSignalAll(ctx, "Sensor"); len(matches) != 0 {
		t.Fatalf("expected no storage signal for small upload, got %d", len(matches))
	}
}

func TestStableIdentifierFingerprintsAreStableAndDoNotExposeRawValue(t *testing.T) {
	http := &HTTPInfo{
		Query: map[string][]string{
			"device_id": {"device-12345678"},
		},
	}

	fingerprints := StableIdentifierFingerprints(http)
	if len(fingerprints) != 1 {
		t.Fatalf("expected one fingerprint, got %d", len(fingerprints))
	}
	if strings.Contains(fingerprints[0], "device-12345678") {
		t.Fatalf("fingerprint exposed raw identifier: %s", fingerprints[0])
	}

	again := StableIdentifierFingerprints(http)
	if len(again) != 1 || again[0] != fingerprints[0] {
		t.Fatalf("expected stable fingerprint, got %v then %v", fingerprints, again)
	}
}
