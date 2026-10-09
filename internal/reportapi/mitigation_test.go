package reportapi

import (
	"testing"
	"time"
)

func TestBuildMitigationPlanCreatesNarrowRuleForPlaintextCredentials(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	precision := BuildDetectionPrecisionReport(
		[]Event{
			{
				Timestamp:  ts,
				RuleID:     "I7_HTTP_AUTH",
				Type:       "INSECURE_HTTP_AUTH",
				Category:   "I7",
				Severity:   "CRITICAL",
				Confidence: "high",
				SrcIP:      "192.168.50.20",
				DstIP:      "198.51.100.10",
				DstPort:    80,
			},
		},
		[]FlowRecord{
			{
				Timestamp:           ts,
				FlowKey:             "tcp|auth",
				SrcIP:               "192.168.50.20",
				DstIP:               "198.51.100.10",
				DstPort:             80,
				Protocol:            "tcp",
				AppProtocol:         "http",
				Direction:           "external",
				ObservedDestination: "api.example",
			},
		},
		nil,
		[]InventoryDevice{{IP: "192.168.50.20", CategoryCandidate: "Camera"}},
	)

	plan := BuildMitigationPlanWithFlows(precision, []FlowRecord{
		{
			Timestamp:           ts.Add(2 * time.Minute),
			FlowKey:             "tcp|auth-2",
			SrcIP:               "192.168.50.20",
			DstIP:               "198.51.100.10",
			DstPort:             80,
			Protocol:            "tcp",
			AppProtocol:         "http",
			Direction:           "external",
			ObservedDestination: "api.example",
			BytesOut:            120,
			BytesIn:             240,
			PacketCount:         6,
		},
	})
	if plan.Metrics.ActionCount != 1 {
		t.Fatalf("ActionCount=%d, want 1: %+v", plan.Metrics.ActionCount, plan.Actions)
	}
	action := plan.Actions[0]
	if action.Kind != "block_service" {
		t.Fatalf("Kind=%q, want block_service", action.Kind)
	}
	if action.Status != "review_required" {
		t.Fatalf("Status=%q, want review_required", action.Status)
	}
	if action.RiskReductionTarget.Exposure == "" || action.WhyThisAction == "" || action.WhyNotStrongerAction == "" {
		t.Fatalf("action=%+v, want risk target and action rationale", action)
	}
	if action.AutoApply.Eligible || len(action.AutoApply.BlockedBy) == 0 {
		t.Fatalf("AutoApply=%+v, want review-gated auto apply", action.AutoApply)
	}
	if len(action.FirewallRules) != 1 || action.FirewallRules[0].DstPort != 80 {
		t.Fatalf("FirewallRules=%+v, want tcp/80 rule", action.FirewallRules)
	}
	if action.Impact.EstimatedBlockedFlows != 1 || action.Impact.EstimatedBlockedBytes != 360 {
		t.Fatalf("Impact=%+v, want measured blocked flow and bytes", action.Impact)
	}
	if !mitigationStringSliceContains(action.Impact.ObservedDestinations, "api.example") {
		t.Fatalf("ObservedDestinations=%+v, want api.example", action.Impact.ObservedDestinations)
	}
	if plan.Metrics.EstimatedBlockedFlows != 1 || plan.Metrics.MeasuredImpactCount == 0 {
		t.Fatalf("Metrics=%+v, want measured impact", plan.Metrics)
	}
	if !action.RollbackRequired {
		t.Fatalf("RollbackRequired=false, want true")
	}
}

func TestBuildMitigationPlanUsesReviewFallbackForHighRiskUnknownMitigation(t *testing.T) {
	precision := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:         "incident-1",
				State:      "risky",
				Score:      82,
				Confidence: "medium",
				DeviceIP:   "192.168.50.44",
				Signals: []PrecisionSignal{
					{Key: "baseline_novelty", Layer: "context", Weight: 30},
					{Key: "category_deviation", Layer: "context", Weight: 30},
				},
			},
		},
	}

	plan := BuildMitigationPlan(precision)
	if plan.Metrics.ActionCount != 1 {
		t.Fatalf("ActionCount=%d, want 1", plan.Metrics.ActionCount)
	}
	action := plan.Actions[0]
	if action.Kind != "isolate_device" || action.Status != "review_required" {
		t.Fatalf("action=%+v, want review-only isolate fallback", action)
	}
	if action.Impact.Level != "high" {
		t.Fatalf("Impact=%+v, want high impact", action.Impact)
	}
}

func TestBuildMitigationPlanResolvesDomainBlockConflict(t *testing.T) {
	precision := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:              "incident-domain",
				State:           "suspicious",
				Score:           58,
				Confidence:      "high",
				DeviceIP:        "192.168.50.70",
				PrimaryTaxonomy: "baseline_novelty",
				Signals: []PrecisionSignal{
					{Key: "baseline_novelty", Layer: "context", Taxonomy: "baseline_novelty", Detail: "destinations=updates.vendor-demo.example protocols=TLS ports=443", Weight: 20},
					{Key: "category_deviation", Layer: "context", Taxonomy: "category_deviation", Detail: "unexpected_ports=443", Weight: 18},
					{Key: "correlation_multi_context", Layer: "correlation", Taxonomy: "correlation", Weight: 6},
				},
			},
		},
	}

	plan := BuildMitigationPlan(precision)
	if plan.Metrics.ConflictResolvedCount == 0 {
		t.Fatalf("ResolvedConflicts=%+v, want dns/destination conflict", plan.ResolvedConflicts)
	}
	if !mitigationActionKindExists(plan.Actions, "dns_block") {
		t.Fatalf("Actions=%+v, want dns_block kept", plan.Actions)
	}
	if mitigationActionKindExists(plan.Actions, "block_destination") {
		t.Fatalf("Actions=%+v, block_destination should be superseded by dns_block", plan.Actions)
	}
}

func TestBuildMitigationPlanDowngradesAutoApplyWhenMeasuredImpactTouchesBaseline(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	precision := BuildDetectionPrecisionReport(
		[]Event{
			{
				Timestamp:  ts.Add(6 * time.Minute),
				RuleID:     "I2_TELNET_SERVICE_OBSERVED",
				Type:       "I2_TELNET_SERVICE_OBSERVED",
				Category:   "I2",
				Severity:   "HIGH",
				Confidence: "high",
				SrcIP:      "192.168.50.80",
				DstIP:      "198.51.100.23",
				DstPort:    23,
			},
		},
		[]FlowRecord{
			{
				Timestamp:           ts,
				FlowKey:             "tcp|telnet-learned",
				SrcIP:               "192.168.50.80",
				DstIP:               "198.51.100.23",
				DstPort:             23,
				Protocol:            "tcp",
				AppProtocol:         "telnet",
				Direction:           "external",
				ObservedDestination: "198.51.100.23",
			},
			{
				Timestamp:           ts.Add(6 * time.Minute),
				FlowKey:             "tcp|telnet-repeat",
				SrcIP:               "192.168.50.80",
				DstIP:               "198.51.100.23",
				DstPort:             23,
				Protocol:            "tcp",
				AppProtocol:         "telnet",
				Direction:           "external",
				ObservedDestination: "198.51.100.23",
				BytesOut:            512,
				BytesIn:             512,
				PacketCount:         8,
			},
		},
		nil,
		[]InventoryDevice{{IP: "192.168.50.80", CategoryCandidate: "Camera"}},
	)

	plan := BuildMitigationPlanWithFlows(precision, []FlowRecord{
		{
			Timestamp:           ts.Add(6 * time.Minute),
			FlowKey:             "tcp|telnet-repeat",
			SrcIP:               "192.168.50.80",
			DstIP:               "198.51.100.23",
			DstPort:             23,
			Protocol:            "tcp",
			AppProtocol:         "telnet",
			Direction:           "external",
			ObservedDestination: "198.51.100.23",
			BytesOut:            512,
			BytesIn:             512,
			PacketCount:         8,
		},
	})
	if plan.Metrics.AutoDowngradedCount == 0 {
		t.Fatalf("Metrics=%+v, want auto downgrade", plan.Metrics)
	}
	action := plan.Actions[0]
	if action.Kind != "block_service" {
		t.Fatalf("action=%+v, want block_service", action)
	}
	if action.Status != "review_required" {
		t.Fatalf("Status=%q, want review_required after impact downgrade", action.Status)
	}
	if action.AutoApply.Eligible || !action.AutoApply.Downgraded {
		t.Fatalf("AutoApply=%+v, want downgraded review requirement", action.AutoApply)
	}
	if !mitigationStringSliceContains(action.AutoApply.BlockedBy, "blocks_learned_baseline_destination") &&
		!mitigationStringSliceContains(action.AutoApply.BlockedBy, "blocks_learned_baseline_port") {
		t.Fatalf("BlockedBy=%+v, want baseline blocker", action.AutoApply.BlockedBy)
	}
}

func TestBuildMitigationPlanIncludesResearchGradeSummaryAndReadiness(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	precision := BuildDetectionPrecisionReport(
		[]Event{
			{
				Timestamp:  ts,
				RuleID:     "I2_TELNET_SERVICE_OBSERVED",
				Type:       "I2_TELNET_SERVICE_OBSERVED",
				Category:   "I2",
				Severity:   "HIGH",
				Confidence: "high",
				SrcIP:      "192.168.50.91",
				DstIP:      "203.0.113.23",
				DstPort:    23,
			},
		},
		nil,
		nil,
		[]InventoryDevice{{IP: "192.168.50.91", CategoryCandidate: "Camera"}},
	)

	flows := []FlowRecord{}
	for i := 0; i < 5; i++ {
		flows = append(flows, FlowRecord{
			Timestamp:           ts.Add(time.Duration(i) * time.Minute),
			FlowKey:             "tcp|telnet|" + string(rune('a'+i)),
			SrcIP:               "192.168.50.91",
			DstIP:               "203.0.113.23",
			DstPort:             23,
			Protocol:            "tcp",
			AppProtocol:         "telnet",
			Direction:           "external",
			ObservedDestination: "203.0.113.23",
			BytesOut:            128,
			BytesIn:             128,
			PacketCount:         2,
		})
	}
	plan := BuildMitigationPlanWithFlows(precision, flows)

	if plan.Summary.ResearchStage != "rule_based_virtual_patch_planning" {
		t.Fatalf("Summary=%+v, want phase-2 research stage", plan.Summary)
	}
	if plan.Summary.Decision == "" || len(plan.Summary.RollbackRequiredActions) != 1 {
		t.Fatalf("Summary=%+v, want decision and rollback action", plan.Summary)
	}
	if len(plan.SafetyPolicy.AutoApplyAllowedWhen) == 0 || len(plan.SafetyPolicy.ImpactDowngradeTriggers) == 0 {
		t.Fatalf("SafetyPolicy=%+v, want explicit policy", plan.SafetyPolicy)
	}
	if !plan.ExecutionReadiness.DryRunReady {
		t.Fatalf("ExecutionReadiness=%+v, want dry-run ready", plan.ExecutionReadiness)
	}
	if plan.ExecutionReadiness.ApplyReady {
		t.Fatalf("ExecutionReadiness=%+v, impact-measured service block should still require dry-run review", plan.ExecutionReadiness)
	}
	if !plan.PaperSummary.VirtualPatchPlanReadyForDryRun || !plan.PaperSummary.NormalTrafficImpactMeasurable {
		t.Fatalf("PaperSummary=%+v, want dry-run-ready measurable plan", plan.PaperSummary)
	}
}

func TestBuildMitigationPlanExplainsImpactWithHistoricalUseAndCriticalFlows(t *testing.T) {
	ts := time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC)
	precision := DetectionPrecisionReport{
		Baseline: BehaviorBaseline{
			Devices: []DeviceBehaviorProfile{
				{
					IP:                  "192.168.50.92",
					BaselineReady:       true,
					LearnedDestinations: []string{"resolver.local"},
					LearnedPorts:        []uint16{53},
				},
			},
		},
		Incidents: []PrecisionIncident{
			{
				ID:         "incident-telnet",
				State:      "risky",
				Score:      76,
				Confidence: "high",
				DeviceIP:   "192.168.50.92",
				Signals: []PrecisionSignal{
					{Key: "event_i2_telnet_service_observed", Layer: "event", Taxonomy: "insecure_service", Weight: 35},
				},
			},
		},
	}
	flows := []FlowRecord{
		{Timestamp: ts, FlowKey: "telnet-1", SrcIP: "192.168.50.92", DstIP: "203.0.113.23", DstPort: 23, Protocol: "tcp", AppProtocol: "telnet", Direction: "external", ObservedDestination: "203.0.113.23", BytesOut: 100, BytesIn: 200, PacketCount: 3},
		{Timestamp: ts.Add(time.Minute), FlowKey: "telnet-2", SrcIP: "192.168.50.92", DstIP: "203.0.113.23", DstPort: 23, Protocol: "tcp", AppProtocol: "telnet", Direction: "external", ObservedDestination: "203.0.113.23", BytesOut: 100, BytesIn: 200, PacketCount: 3},
		{Timestamp: ts.Add(2 * time.Minute), FlowKey: "telnet-3", SrcIP: "192.168.50.92", DstIP: "203.0.113.23", DstPort: 23, Protocol: "tcp", AppProtocol: "telnet", Direction: "external", ObservedDestination: "203.0.113.23", BytesOut: 100, BytesIn: 200, PacketCount: 3},
		{Timestamp: ts.Add(3 * time.Minute), FlowKey: "dns-1", SrcIP: "192.168.50.92", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local", ObservedDestination: "resolver.local", BytesOut: 50, BytesIn: 80, PacketCount: 2},
		{Timestamp: ts.Add(4 * time.Minute), FlowKey: "dns-2", SrcIP: "192.168.50.92", DstIP: "192.168.50.1", DstPort: 53, Protocol: "udp", AppProtocol: "dns", Direction: "local", ObservedDestination: "resolver.local", BytesOut: 50, BytesIn: 80, PacketCount: 2},
	}

	plan := BuildMitigationPlanWithFlows(precision, flows)
	if plan.Metrics.ActionCount != 1 {
		t.Fatalf("ActionCount=%d, want 1", plan.Metrics.ActionCount)
	}
	impact := plan.Actions[0].Impact
	if impact.EstimatedBlockedFlows != 3 {
		t.Fatalf("Impact=%+v, want 3 blocked telnet flows", impact)
	}
	if impact.HistoricalDeviceFlows != 5 {
		t.Fatalf("Impact=%+v, want 5 historical device flows", impact)
	}
	if impact.MaintainedCriticalFlows != 2 || impact.BlockedCriticalFlows != 0 {
		t.Fatalf("Impact=%+v, want DNS maintained and no critical flows blocked", impact)
	}
	if !mitigationKVContains(impact.CriticalFlowKinds, "dns", 2) {
		t.Fatalf("CriticalFlowKinds=%+v, want dns count", impact.CriticalFlowKinds)
	}
	if !mitigationKVContains(impact.DestinationUseCounts, "203.0.113.23", 3) {
		t.Fatalf("DestinationUseCounts=%+v, want destination reuse count", impact.DestinationUseCounts)
	}
	if !mitigationPortUseContains(impact.PortUseCounts, 23, 3) {
		t.Fatalf("PortUseCounts=%+v, want port reuse count", impact.PortUseCounts)
	}
	if impact.BaselineImpact != "blocks_non_baseline_observed_flows" {
		t.Fatalf("BaselineImpact=%q, want non-baseline observed flows", impact.BaselineImpact)
	}
	if !mitigationStringSliceContains(impact.NormalTrafficRiskReasons, "3 historical flow(s) match the mitigation target") {
		t.Fatalf("NormalTrafficRiskReasons=%+v, want blocked-flow reason", impact.NormalTrafficRiskReasons)
	}
	if !mitigationStringSliceContains(impact.NormalTrafficRiskReasons, "2 DNS/DHCP/NTP or discovery flow(s) remain outside the mitigation target") {
		t.Fatalf("NormalTrafficRiskReasons=%+v, want maintained-critical reason", impact.NormalTrafficRiskReasons)
	}
}

func TestBuildMitigationPlanEnrichesDeviceIdentityFromInventory(t *testing.T) {
	precision := DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:         "incident-telnet",
				State:      "risky",
				Score:      76,
				Confidence: "high",
				DeviceIP:   "192.168.50.92",
				Signals: []PrecisionSignal{
					{Key: "event_i2_telnet_service_observed", Layer: "event", Taxonomy: "insecure_service", Weight: 35},
				},
			},
		},
	}

	plan := BuildMitigationPlanWithFlowsAndInventory(precision, nil, []InventoryDevice{
		{
			IP:                 "192.168.50.92",
			MACAddress:         "aa:bb:cc:dd:ee:ff",
			Hostname:           "camera-01",
			DHCPLeaseExpiresAt: "2026-09-27T12:00:00Z",
			DHCPLeaseState:     "active",
		},
	})
	if plan.Metrics.ActionCount != 1 {
		t.Fatalf("ActionCount=%d, want 1", plan.Metrics.ActionCount)
	}
	action := plan.Actions[0]
	if action.DeviceIdentity.MACAddress != "aa:bb:cc:dd:ee:ff" ||
		action.DeviceIdentity.Hostname != "camera-01" ||
		action.DeviceIdentity.Confidence != "dhcp_lease_active" {
		t.Fatalf("DeviceIdentity=%+v, want DHCP-backed identity", action.DeviceIdentity)
	}
	if action.DeviceLabel != "camera-01" {
		t.Fatalf("DeviceLabel=%q, want hostname label", action.DeviceLabel)
	}
}

func TestBuildMitigationPlanPaperSummaryCapturesMonitorOnlyLimitation(t *testing.T) {
	plan := BuildMitigationPlan(DetectionPrecisionReport{
		Incidents: []PrecisionIncident{
			{
				ID:              "incident-observe",
				State:           "observe",
				Score:           25,
				Confidence:      "low",
				DeviceIP:        "192.168.50.31",
				PrimaryTaxonomy: "baseline_novelty",
				Signals: []PrecisionSignal{
					{Key: "baseline_novelty", Taxonomy: "baseline_novelty", Weight: 12},
				},
			},
		},
	})

	if plan.Summary.Decision != "observe_only" {
		t.Fatalf("Summary=%+v, want observe_only", plan.Summary)
	}
	if !plan.ExecutionReadiness.MonitorOnly || plan.ExecutionReadiness.ApplyReady {
		t.Fatalf("ExecutionReadiness=%+v, want monitor-only non-apply plan", plan.ExecutionReadiness)
	}
	if !mitigationStringSliceContains(plan.PaperSummary.MissingEvidence, "normal traffic impact could not be estimated because no historical matching flows were available") {
		t.Fatalf("MissingEvidence=%+v, want impact-estimate limitation", plan.PaperSummary.MissingEvidence)
	}
	if !mitigationStringSliceContains(plan.PaperSummary.MissingEvidence, "only monitor-only actions were selected, so risk reduction must be evaluated after more observation") {
		t.Fatalf("MissingEvidence=%+v, want monitor-only limitation", plan.PaperSummary.MissingEvidence)
	}
}

func mitigationActionKindExists(actions []MitigationAction, kind string) bool {
	for _, action := range actions {
		if action.Kind == kind {
			return true
		}
	}
	return false
}

func mitigationStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func mitigationKVContains(items []KV, key string, count int) bool {
	for _, item := range items {
		if item.Key == key && item.Count == count {
			return true
		}
	}
	return false
}

func mitigationPortUseContains(items []MitigationPortUseCount, port uint16, count int) bool {
	for _, item := range items {
		if item.Port == port && item.Count == count {
			return true
		}
	}
	return false
}
