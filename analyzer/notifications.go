package analyzer

import (
	"fmt"
	"strings"
	"time"

	"quarant/analyzer/device"
	"quarant/analyzer/knowledge"
	"quarant/analyzer/rules"
)

type knownDeviceContext struct {
	DeviceKey string
	Label     string
	Status    string
	Known     bool
}

func (h *FlowHandler) enrichEvent(event *Event) {
	if event == nil {
		return
	}

	ctx := h.lookupKnownDevice(event.DeviceKey, event.SrcIP)
	if event.DeviceKey == "" {
		event.DeviceKey = ctx.DeviceKey
	}
	if event.DeviceLabel == "" {
		event.DeviceLabel = ctx.Label
	}
	if event.DeviceStatus == "" {
		event.DeviceStatus = ctx.Status
	}

	if h != nil && h.knowledge != nil {
		EnrichUserGuidance(event, h.knowledge.UserActions)
	}
}

func (h *FlowHandler) lookupKnownDevice(deviceKey, srcIP string) knownDeviceContext {
	ctx := knownDeviceContext{
		DeviceKey: strings.TrimSpace(deviceKey),
		Status:    "unknown",
	}
	if ctx.DeviceKey == "" {
		ctx.DeviceKey = strings.TrimSpace(srcIP)
	}

	if h == nil || h.knowledge == nil || h.knowledge.KnownDevices == nil {
		return ctx
	}

	record, ok := h.knowledge.KnownDevices.Lookup(ctx.DeviceKey, srcIP)
	if !ok {
		return ctx
	}

	ctx.Known = true
	if key := strings.TrimSpace(record.DeviceKey); key != "" {
		ctx.DeviceKey = key
	}
	ctx.Label = strings.TrimSpace(record.Label)
	ctx.Status = normalizeKnownDeviceStatus(record)
	return ctx
}

func normalizeKnownDeviceStatus(record knowledge.KnownDeviceRecord) string {
	status := strings.TrimSpace(record.Status)
	if status != "" {
		return status
	}
	if record.Trusted {
		return "allowed"
	}
	return "unknown"
}

func (h *FlowHandler) buildDeviceNotificationEvents(now time.Time, key, srcIP, dstIP string, srcPort, dstPort uint16, profile *device.DeviceProfile) []Event {
	if h == nil || profile == nil {
		return nil
	}

	known := h.lookupKnownDevice(srcIP, srcIP)
	events := make([]Event, 0, 2)

	if profile.ObserveNotification("I8_NEW_DEVICE_OBSERVED", now.Unix()) == 1 {
		events = append(events, Event{
			Timestamp:      now,
			Type:           "I8_NEW_DEVICE_OBSERVED",
			Severity:       SeverityInfo,
			RuleID:         "I8_NEW_DEVICE_OBSERVED",
			Category:       "I8",
			FlowKey:        key,
			SrcIP:          srcIP,
			SrcPort:        srcPort,
			DstIP:          dstIP,
			DstPort:        dstPort,
			ObservedFact:   "A previously unseen device was observed on the network.",
			Inference:      "This may be a newly added household device or an unknown device connected to the network.",
			Limitation:     "Passive monitoring cannot determine whether this device is authorized by the user.",
			Recommendation: "Confirm whether this device belongs to your household.",
			Message:        "A previously unseen device was observed on the network.",
		})
	}

	if !known.Known && profile.ObserveNotification("I8_UNREGISTERED_DEVICE_ACTIVE", now.Unix()) == 1 {
		events = append(events, Event{
			Timestamp:      now,
			Type:           "I8_UNREGISTERED_DEVICE_ACTIVE",
			Severity:       SeverityWarning,
			RuleID:         "I8_UNREGISTERED_DEVICE_ACTIVE",
			Category:       "I8",
			FlowKey:        key,
			SrcIP:          srcIP,
			SrcPort:        srcPort,
			DstIP:          dstIP,
			DstPort:        dstPort,
			ObservedFact:   "A device that is not present in the known device list is actively communicating.",
			Inference:      "This may be a household device that has not been labeled yet, or another device that should be reviewed.",
			Limitation:     "Passive monitoring cannot confirm device ownership or intent.",
			Recommendation: "Review whether the device should be marked as allowed, left as unknown, or treated as a block candidate.",
			Message:        "An unregistered device was observed sending traffic.",
		})
	}

	for i := range events {
		h.enrichEvent(&events[i])
	}

	return events
}

func (h *FlowHandler) buildQuarantineRecommendationEvent(now time.Time, key, srcIP, dstIP string, srcPort, dstPort uint16, profile *device.DeviceProfile, matches []rules.Match) *Event {
	if h == nil || profile == nil || len(matches) == 0 {
		return nil
	}

	known := h.lookupKnownDevice(srcIP, srcIP)
	existingHighRisk := profile.SeverityCounts[string(SeverityHigh)] + profile.SeverityCounts[string(SeverityCritical)]
	batchHighRisk := 0
	reasons := make([]string, 0, 3)
	needsRecommendation := false

	for _, match := range matches {
		if match.Severity == rules.SeverityHigh || match.Severity == rules.SeverityCritical {
			batchHighRisk++
		}

		id := strings.TrimSpace(match.RuleID)
		if id == "" {
			id = strings.TrimSpace(match.Type)
		}
		evidence := strings.ToLower(strings.TrimSpace(match.Evidence))
		message := strings.ToLower(strings.TrimSpace(match.Message))

		if id == "R1_COMPOSITE_RISK" && (strings.Contains(evidence, "risk_level=high") || strings.Contains(evidence, "recommended_action=isolate_or_block")) {
			needsRecommendation = true
			reasons = append(reasons, "high_composite_risk")
		}
		if strings.Contains(evidence, "recommended_action=isolate_or_block") || strings.Contains(message, "recommended_action=isolate_or_block") {
			needsRecommendation = true
			reasons = append(reasons, "explicit_isolation_recommendation")
		}
	}

	if !known.Known && existingHighRisk+batchHighRisk >= 2 {
		needsRecommendation = true
		reasons = append(reasons, "unknown_device_with_multiple_high_risk_signals")
	}

	if !needsRecommendation {
		return nil
	}
	if profile.ObserveNotification("R1_QUARANTINE_RECOMMENDATION", now.Unix()) != 1 {
		return nil
	}

	event := &Event{
		Timestamp:               now,
		Type:                    "R1_QUARANTINE_RECOMMENDATION",
		Severity:                SeverityHigh,
		RuleID:                  "R1_QUARANTINE_RECOMMENDATION",
		Category:                "R1",
		FlowKey:                 key,
		SrcIP:                   srcIP,
		SrcPort:                 srcPort,
		DstIP:                   dstIP,
		DstPort:                 dstPort,
		ObservedFact:            "Multiple high-risk signals were observed from this device.",
		Inference:               "Temporary isolation may reduce exposure while the user reviews the device.",
		Limitation:              "Blocking or isolation may interrupt legitimate device functionality, and passive monitoring cannot prove malicious intent.",
		Recommendation:          "Confirm the device identity before applying isolation and review vendor guidance if the device belongs to your household.",
		RecommendedAction:       "isolate_or_block",
		DryRun:                  true,
		SuggestedFirewallAction: "temporary_isolation",
		Message:                 "Multiple high-risk signals suggest this device may need temporary isolation while it is reviewed.",
		Evidence:                fmt.Sprintf("recommended_action=isolate_or_block reasons=%s dry_run=true", strings.Join(dedupeNonEmptyStrings(reasons), ",")),
	}
	h.enrichEvent(event)
	return event
}
