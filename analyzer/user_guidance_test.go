package analyzer

import (
	"testing"
	"time"

	"quarant/analyzer/device"
	"quarant/analyzer/knowledge"
	"quarant/analyzer/rules"
)

func TestAttachUserActionsFromCatalog(t *testing.T) {
	event := &Event{
		ActionIDs: []string{"CONFIRM_DEVICE_OWNER", "ISOLATE_DEVICE"},
	}
	catalog := knowledge.UserActionCatalog{
		"CONFIRM_DEVICE_OWNER": {
			Label:       "Confirm owner",
			Description: "Check whether the device belongs to the household.",
			Difficulty:  "easy",
			Fallback:    "Restrict access if unsure.",
		},
		"ISOLATE_DEVICE": {
			Label:       "Isolate device",
			Description: "Temporarily move it to a guest network.",
			Difficulty:  "medium",
			Fallback:    "Power it off if needed.",
		},
	}

	AttachUserActions(event, catalog)

	if len(event.UserActions) != 2 {
		t.Fatalf("expected 2 user actions, got %d", len(event.UserActions))
	}
	if event.UserActions[0].ID != "CONFIRM_DEVICE_OWNER" {
		t.Fatalf("expected first action to preserve priority order, got %+v", event.UserActions)
	}
}

func TestEnrichUserGuidanceForHTTPPlaintext(t *testing.T) {
	event := &Event{RuleID: "I7_HTTP_PLAINTEXT"}
	catalog := knowledge.UserActionCatalog{
		"ENABLE_HTTPS":    {Label: "HTTPS", Description: "Enable HTTPS", Difficulty: "medium"},
		"UPDATE_FIRMWARE": {Label: "Update", Description: "Update firmware", Difficulty: "easy"},
	}

	EnrichUserGuidance(event, catalog)

	if event.UserTitle == "" || event.UserMessage == "" {
		t.Fatalf("expected user guidance fields to be populated, got %+v", event)
	}
	if len(event.ActionIDs) == 0 {
		t.Fatalf("expected action ids, got %+v", event)
	}
	if len(event.UserActions) == 0 {
		t.Fatalf("expected resolved user actions, got %+v", event)
	}
}

func TestBuildQuarantineRecommendationEventFromCompositeRisk(t *testing.T) {
	handler := &FlowHandler{
		knowledge: &knowledge.DB{
			UserActions: knowledge.UserActionCatalog{
				"CONFIRM_DEVICE_OWNER": {Label: "Confirm"},
				"ISOLATE_DEVICE":       {Label: "Isolate"},
			},
		},
	}
	profile := device.NewProfile("10.0.1.23")
	now := time.Date(2026, 4, 28, 12, 31, 0, 0, time.UTC)

	event := handler.buildQuarantineRecommendationEvent(
		now,
		"tcp|10.0.1.23:1234<->198.51.100.10:80",
		"10.0.1.23",
		"198.51.100.10",
		1234,
		80,
		profile,
		[]rules.Match{
			{
				RuleID:   "R1_COMPOSITE_RISK",
				Type:     "R1_COMPOSITE_RISK",
				Severity: rules.SeverityCritical,
				Evidence: "risk_level=high risk_score=70 recommended_action=isolate_or_block",
			},
		},
	)
	if event == nil {
		t.Fatal("expected quarantine recommendation event")
	}
	if event.RuleID != "R1_QUARANTINE_RECOMMENDATION" {
		t.Fatalf("unexpected rule id: %+v", event)
	}
	if !event.DryRun || event.RecommendedAction != "isolate_or_block" {
		t.Fatalf("expected dry-run recommendation fields, got %+v", event)
	}
	if event.UserTitle == "" {
		t.Fatalf("expected user guidance to be attached, got %+v", event)
	}
}

func TestLookupKnownDeviceFallsBackToUnknownStatus(t *testing.T) {
	handler := &FlowHandler{
		knowledge: &knowledge.DB{
			KnownDevices: &knowledge.KnownDevicesCatalog{
				Devices: []knowledge.KnownDeviceRecord{
					{DeviceKey: "10.0.1.2", Label: "Test PC", Trusted: true, Status: "allowed"},
				},
			},
		},
	}

	ctx := handler.lookupKnownDevice("10.0.1.99", "10.0.1.99")
	if ctx.Known {
		t.Fatalf("expected device to be treated as unregistered, got %+v", ctx)
	}
	if ctx.Status != "unknown" {
		t.Fatalf("expected unknown status for unregistered device, got %+v", ctx)
	}
}
