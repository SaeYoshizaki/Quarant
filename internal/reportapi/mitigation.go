package reportapi

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type MitigationPlan struct {
	GeneratedAt        string                       `json:"generated_at"`
	Mode               string                       `json:"mode"`
	Source             PrecisionSources             `json:"source"`
	ActionTaxonomy     []MitigationActionKind       `json:"action_taxonomy"`
	SafetyPolicy       MitigationSafetyPolicy       `json:"safety_policy"`
	Metrics            MitigationMetrics            `json:"metrics"`
	Summary            MitigationPlanSummary        `json:"summary"`
	ExecutionReadiness MitigationExecutionReadiness `json:"execution_readiness"`
	PaperSummary       MitigationPaperSummary       `json:"paper_summary"`
	Actions            []MitigationAction           `json:"actions"`
	ResolvedConflicts  []MitigationConflict         `json:"resolved_conflicts,omitempty"`
	Suppressed         []MitigationSuppression      `json:"suppressed"`
	Recommendations    []string                     `json:"recommendations"`
	Limitations        []string                     `json:"limitations"`
}

type MitigationMetrics struct {
	IncidentCount         int  `json:"incident_count"`
	ActionCount           int  `json:"action_count"`
	AutoEligibleCount     int  `json:"auto_eligible_count"`
	ReviewRequiredCount   int  `json:"review_required_count"`
	MonitorOnlyCount      int  `json:"monitor_only_count"`
	HighImpactCount       int  `json:"high_impact_count"`
	MeasuredImpactCount   int  `json:"measured_impact_count"`
	EstimatedBlockedFlows int  `json:"estimated_blocked_flows"`
	AutoDowngradedCount   int  `json:"auto_downgraded_count"`
	RollbackRequiredCount int  `json:"rollback_required_count"`
	ConflictResolvedCount int  `json:"conflict_resolved_count"`
	ActionKinds           []KV `json:"action_kinds,omitempty"`
}

type MitigationPlanSummary struct {
	Decision                string   `json:"decision"`
	ResearchStage           string   `json:"research_stage"`
	ActionKinds             []KV     `json:"action_kinds,omitempty"`
	AutoEligibleActions     []string `json:"auto_eligible_actions,omitempty"`
	ReviewRequiredActions   []string `json:"review_required_actions,omitempty"`
	MonitorOnlyActions      []string `json:"monitor_only_actions,omitempty"`
	HighImpactActions       []string `json:"high_impact_actions,omitempty"`
	BaselineTouchingActions []string `json:"baseline_touching_actions,omitempty"`
	RollbackRequiredActions []string `json:"rollback_required_actions,omitempty"`
	ConflictCount           int      `json:"conflict_count"`
	SuppressedIncidentCount int      `json:"suppressed_incident_count"`
	EstimatedBlockedFlows   int      `json:"estimated_blocked_flows"`
}

type MitigationSafetyPolicy struct {
	AutoApplyAllowedWhen     []string `json:"auto_apply_allowed_when"`
	ReviewRequiredWhen       []string `json:"review_required_when"`
	NeverAutoApplyKinds      []string `json:"never_auto_apply_kinds"`
	ImpactDowngradeTriggers  []string `json:"impact_downgrade_triggers"`
	ConflictResolutionPolicy []string `json:"conflict_resolution_policy"`
	RollbackRequirements     []string `json:"rollback_requirements"`
}

type MitigationExecutionReadiness struct {
	DryRunReady  bool     `json:"dry_run_ready"`
	ApplyReady   bool     `json:"apply_ready"`
	MonitorOnly  bool     `json:"monitor_only"`
	Blocked      bool     `json:"blocked"`
	Blockers     []string `json:"blockers,omitempty"`
	NextSteps    []string `json:"next_steps,omitempty"`
	ReadyActions []string `json:"ready_actions,omitempty"`
}

type MitigationPaperSummary struct {
	Claim                          string   `json:"claim"`
	SupportedClaims                []string `json:"supported_claims"`
	MissingEvidence                []string `json:"missing_evidence"`
	TableColumns                   []string `json:"table_columns"`
	PrimaryOutcomeMetrics          []string `json:"primary_outcome_metrics"`
	ReObservationRequired          bool     `json:"re_observation_required"`
	NormalTrafficImpactMeasurable  bool     `json:"normal_traffic_impact_measurable"`
	VirtualPatchPlanReadyForDryRun bool     `json:"virtual_patch_plan_ready_for_dry_run"`
}

type MitigationAction struct {
	ID                   string                   `json:"id"`
	IncidentID           string                   `json:"incident_id"`
	DeviceIP             string                   `json:"device_ip"`
	DeviceLabel          string                   `json:"device_label,omitempty"`
	DeviceIdentity       MitigationDeviceIdentity `json:"device_identity,omitempty"`
	Kind                 string                   `json:"kind"`
	Status               string                   `json:"status"`
	Priority             int                      `json:"priority"`
	Confidence           string                   `json:"confidence"`
	Title                string                   `json:"title"`
	Rationale            string                   `json:"rationale"`
	RiskReductionTarget  MitigationRiskTarget     `json:"risk_reduction_target"`
	WhyThisAction        string                   `json:"why_this_action"`
	WhyNotStrongerAction string                   `json:"why_not_stronger_action,omitempty"`
	AutoApply            MitigationAutoApply      `json:"auto_apply"`
	Impact               MitigationImpact         `json:"impact"`
	Preconditions        []string                 `json:"preconditions,omitempty"`
	FirewallRules        []MitigationRule         `json:"firewall_rules,omitempty"`
	Validation           []MitigationValidation   `json:"validation,omitempty"`
	RollbackRequired     bool                     `json:"rollback_required"`
	Metadata             map[string]string        `json:"metadata,omitempty"`
}

type MitigationDeviceIdentity struct {
	IP                 string   `json:"ip,omitempty"`
	MACAddress         string   `json:"mac_address,omitempty"`
	Hostname           string   `json:"hostname,omitempty"`
	DHCPLeaseExpiresAt string   `json:"dhcp_lease_expires_at,omitempty"`
	DHCPLeaseState     string   `json:"dhcp_lease_state,omitempty"`
	Confidence         string   `json:"confidence,omitempty"`
	Assumptions        []string `json:"assumptions,omitempty"`
}

type MitigationActionKind struct {
	Kind             string `json:"kind"`
	Description      string `json:"description"`
	Strength         string `json:"strength"`
	AutoApplyDefault string `json:"auto_apply_default"`
}

type MitigationRiskTarget struct {
	Taxonomy       string   `json:"taxonomy,omitempty"`
	SignalKeys     []string `json:"signal_keys,omitempty"`
	Exposure       string   `json:"exposure"`
	ExpectedEffect string   `json:"expected_effect"`
}

type MitigationAutoApply struct {
	Eligible   bool     `json:"eligible"`
	Level      string   `json:"level"`
	Reason     string   `json:"reason"`
	Required   []string `json:"required,omitempty"`
	BlockedBy  []string `json:"blocked_by,omitempty"`
	Downgraded bool     `json:"downgraded,omitempty"`
}

type MitigationImpact struct {
	Level                    string                   `json:"level"`
	NormalTrafficRisk        string                   `json:"normal_traffic_risk"`
	NormalTrafficRiskReasons []string                 `json:"normal_traffic_risk_reasons,omitempty"`
	AffectedTraffic          []string                 `json:"affected_traffic,omitempty"`
	Reason                   string                   `json:"reason"`
	HistoricalDeviceFlows    int                      `json:"historical_device_flows,omitempty"`
	EstimatedBlockedFlows    int                      `json:"estimated_blocked_flows,omitempty"`
	EstimatedBlockedBytes    int64                    `json:"estimated_blocked_bytes,omitempty"`
	EstimatedBlockedPackets  int                      `json:"estimated_blocked_packets,omitempty"`
	MaintainedCriticalFlows  int                      `json:"maintained_critical_flows,omitempty"`
	BlockedCriticalFlows     int                      `json:"blocked_critical_flows,omitempty"`
	CriticalFlowKinds        []KV                     `json:"critical_flow_kinds,omitempty"`
	DestinationUseCounts     []KV                     `json:"destination_use_counts,omitempty"`
	PortUseCounts            []MitigationPortUseCount `json:"port_use_counts,omitempty"`
	ObservedDestinations     []string                 `json:"observed_destinations,omitempty"`
	ObservedProtocols        []string                 `json:"observed_protocols,omitempty"`
	ObservedPorts            []uint16                 `json:"observed_ports,omitempty"`
	SampleFlows              []MitigationImpactedFlow `json:"sample_flows,omitempty"`
	BaselineImpact           string                   `json:"baseline_impact,omitempty"`
	MeasurementWindow        Window                   `json:"measurement_window,omitempty"`
}

type MitigationImpactedFlow struct {
	Timestamp           string `json:"ts,omitempty"`
	FlowKey             string `json:"flow_key,omitempty"`
	SrcIP               string `json:"src_ip,omitempty"`
	DstIP               string `json:"dst_ip,omitempty"`
	DstPort             uint16 `json:"dst_port,omitempty"`
	Protocol            string `json:"protocol,omitempty"`
	AppProtocol         string `json:"app_protocol,omitempty"`
	ObservedDestination string `json:"observed_destination,omitempty"`
	BytesOut            int64  `json:"bytes_out,omitempty"`
	BytesIn             int64  `json:"bytes_in,omitempty"`
	PacketCount         int    `json:"packet_count,omitempty"`
}

type MitigationPortUseCount struct {
	Port  uint16 `json:"port"`
	Count int    `json:"count"`
}

type MitigationRule struct {
	ID       string `json:"id"`
	Backend  string `json:"backend"`
	Action   string `json:"action"`
	DeviceIP string `json:"device_ip"`
	Protocol string `json:"protocol,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	Domain   string `json:"domain,omitempty"`
	DstZone  string `json:"dst_zone,omitempty"`
	Comment  string `json:"comment"`
}

type MitigationValidation struct {
	Metric   string `json:"metric"`
	Expected string `json:"expected"`
}

type MitigationSuppression struct {
	IncidentID string `json:"incident_id"`
	DeviceIP   string `json:"device_ip,omitempty"`
	Reason     string `json:"reason"`
}

type MitigationConflict struct {
	KeptActionID        string   `json:"kept_action_id"`
	SuppressedActionIDs []string `json:"suppressed_action_ids"`
	DeviceIP            string   `json:"device_ip,omitempty"`
	Reason              string   `json:"reason"`
}

func LoadMitigationPlan(eventsPath, flowsPath, observationsPath, inventoryPath string) (MitigationPlan, error) {
	return LoadMitigationPlanWithSecurityEvents(eventsPath, "", flowsPath, observationsPath, inventoryPath)
}

func LoadMitigationPlanWithSecurityEvents(eventsPath, securityEventsPath, flowsPath, observationsPath, inventoryPath string) (MitigationPlan, error) {
	precision, err := LoadDetectionPrecisionReportWithSecurityEvents(eventsPath, securityEventsPath, flowsPath, observationsPath, inventoryPath)
	if err != nil {
		return MitigationPlan{}, err
	}
	flows, err := LoadFlows(flowsPath)
	if err != nil {
		return MitigationPlan{}, err
	}
	inventory, err := LoadInventoryWithFallback(inventoryPath, eventsPath, flowsPath)
	if err != nil {
		return MitigationPlan{}, err
	}
	return BuildMitigationPlanWithFlowsAndInventory(precision, flows, inventory.Devices), nil
}

func BuildMitigationPlan(precision DetectionPrecisionReport) MitigationPlan {
	return BuildMitigationPlanWithFlows(precision, nil)
}

func BuildMitigationPlanWithFlows(precision DetectionPrecisionReport, flows []FlowRecord) MitigationPlan {
	return BuildMitigationPlanWithFlowsAndInventory(precision, flows, nil)
}

func BuildMitigationPlanWithFlowsAndInventory(precision DetectionPrecisionReport, flows []FlowRecord, devices []InventoryDevice) MitigationPlan {
	candidates := []MitigationAction{}
	suppressed := []MitigationSuppression{}
	for _, incident := range precision.Incidents {
		incidentActions := mitigationActionsForIncident(incident)
		if len(incidentActions) == 0 {
			suppressed = append(suppressed, MitigationSuppression{
				IncidentID: incident.ID,
				DeviceIP:   incident.DeviceIP,
				Reason:     "No safe rule-based mitigation matched this incident. Keep it in human review.",
			})
			continue
		}
		candidates = append(candidates, incidentActions...)
	}
	actions, conflicts := resolveMitigationConflicts(candidates)
	actions = enrichMitigationActionDeviceIdentity(actions, devices)
	actions = estimateMitigationImpacts(actions, flows, precision.Baseline)
	sort.SliceStable(actions, func(i, j int) bool {
		if actions[i].Priority == actions[j].Priority {
			return actions[i].ID < actions[j].ID
		}
		return actions[i].Priority > actions[j].Priority
	})
	plan := MitigationPlan{
		GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
		Mode:              "rule_based_dry_run",
		Source:            precision.Source,
		ActionTaxonomy:    mitigationActionTaxonomy(),
		SafetyPolicy:      mitigationSafetyPolicy(),
		Actions:           actions,
		ResolvedConflicts: conflicts,
		Suppressed:        suppressed,
		Recommendations: []string{
			"Start in dry-run mode and review generated gateway rules before applying them.",
			"Prefer narrow service-specific blocks before full device isolation.",
			"Re-run passive observation after mitigation and compare incident and risk metrics before calling a device remediated.",
		},
		Limitations: []string{
			"Rule-based mitigation cannot confirm exploitability or device compromise.",
			"Gateway rules reduce network exposure but do not patch firmware or remove vulnerable code from the device.",
			"Impact estimates are derived from observed metadata and may miss encrypted or unseen dependencies.",
		},
	}
	plan.Metrics = buildMitigationMetrics(plan, precision)
	plan.Summary = buildMitigationPlanSummary(plan)
	plan.ExecutionReadiness = buildMitigationExecutionReadiness(plan)
	plan.PaperSummary = buildMitigationPaperSummary(plan)
	return plan
}

func mitigationActionsForIncident(incident PrecisionIncident) []MitigationAction {
	if strings.TrimSpace(incident.DeviceIP) == "" {
		return nil
	}
	var actions []MitigationAction
	if hasAnyMitigationSignal(incident, "event_i7_http_auth", "event_i7_http_token", "event_i7_http_body_secret", "event_i3_auth_token_in_url") {
		actions = append(actions, newServiceBlockMitigation(incident, 95, "Block plaintext HTTP egress for exposed credentials", "Credential-like material was observed over plaintext HTTP. Blocking outbound HTTP for this device is a narrow virtual patch that reduces repeated exposure.", "tcp", 80, "wan", "medium", []string{"tcp/80 outbound from device"}, "plaintext credential exposure", "targeted service block removes repeated plaintext credential leakage", "Full isolation may break unrelated device functions; block only TCP/80 first."))
	}
	if hasSignalContaining(incident, "telnet") {
		actions = append(actions, newServiceBlockMitigation(incident, 90, "Block Telnet traffic", "Telnet was observed or inferred. Blocking TCP/23 reduces remote management exposure without changing the device firmware.", "tcp", 23, "wan", "low", []string{"tcp/23"}, "insecure remote management service", "Telnet has a narrow service signature and is rarely required for normal IoT operation.", "Destination or device isolation is stronger than needed when a single risky service can be blocked."))
	}
	if hasSignalContaining(incident, "ftp") {
		actions = append(actions, newServiceBlockMitigation(incident, 86, "Block FTP traffic", "FTP was observed or inferred. Blocking TCP/21 removes a plaintext management and file-transfer exposure.", "tcp", 21, "wan", "medium", []string{"tcp/21"}, "plaintext file transfer or management service", "FTP is service-specific and can be blocked without cutting off all device traffic.", "Full isolation may be unnecessary if only FTP is risky."))
	}
	if hasSignalContaining(incident, "mqtt") && !hasSignalContaining(incident, "mqtts") {
		actions = append(actions, newServiceBlockMitigation(incident, 78, "Block plaintext MQTT", "Plaintext MQTT was observed. Blocking TCP/1883 reduces unauthenticated or unencrypted broker exposure when the device does not require it.", "tcp", 1883, "wan", "medium", []string{"tcp/1883"}, "plaintext MQTT broker exposure", "MQTT plaintext has a known port and can be narrowed to TCP/1883.", "Device isolation is stronger and should wait until MQTT is confirmed unnecessary."))
	}
	if hasAttackEvidenceMitigationSignal(incident) {
		if attackEvidenceReachedExposedService(incident) {
			actions = append(actions, MitigationAction{
				ID:                   mitigationActionID(incident, "restrict_inbound"),
				IncidentID:           incident.ID,
				DeviceIP:             incident.DeviceIP,
				DeviceLabel:          incident.DeviceLabel,
				Kind:                 "restrict_inbound",
				Status:               "review_required",
				Priority:             attackEvidenceMitigationPriority(incident),
				Confidence:           incident.Confidence,
				Title:                "Review inbound exposure and tighten gateway policy",
				Rationale:            "Router-boundary evidence included accepted or exposed-service attempts. The response should verify that no WAN path reaches the IoT service and preserve logs for before-after evaluation.",
				RiskReductionTarget:  mitigationRiskTarget(incident, "accepted or exposed inbound probing", "remove unintended inbound exposure while preserving default-deny evidence"),
				WhyThisAction:        "Accepted or exposed-service evidence is stronger than background blocked scans and justifies reviewed inbound policy tightening.",
				WhyNotStrongerAction: "No device compromise was proven; isolating the device would add disruption without stronger evidence.",
				AutoApply:            mitigationAutoApply(false, "review_required", "Inbound policy changes can lock out legitimate remote administration and should be reviewed.", "exposed inbound path reviewed", "target device identity stable"),
				Impact:               mitigationImpact("low", []string{"inbound traffic to device"}, "The action targets inbound exposure and does not block additional outbound dependencies."),
				Preconditions:        []string{"Gateway firewall can identify the IoT device IP.", "Accepted inbound path or exposed service is reviewed."},
				Validation:           defaultMitigationValidation(),
				RollbackRequired:     false,
			})
		} else {
			actions = append(actions, MitigationAction{
				ID:                  mitigationActionID(incident, "confirm_inbound_posture"),
				IncidentID:          incident.ID,
				DeviceIP:            incident.DeviceIP,
				DeviceLabel:         incident.DeviceLabel,
				Kind:                "monitor_only",
				Status:              "monitor_only",
				Priority:            28,
				Confidence:          incident.Confidence,
				Title:               "Confirm default-deny inbound posture",
				Rationale:           "Router-boundary evidence was already blocked or rejected. This is useful posture evidence, but it should not be treated as proof that mitigation reduced internet scan volume.",
				RiskReductionTarget: mitigationRiskTarget(incident, "blocked inbound probing evidence", "preserve default-deny posture and continue measuring boundary evidence"),
				WhyThisAction:       "DROP/REJECT evidence confirms the gateway denied the attempt, so monitoring and posture confirmation are safer than adding disruptive rules.",
				AutoApply:           mitigationAutoApply(true, "safe_auto", "Posture confirmation does not change gateway behavior."),
				Impact:              mitigationImpact("low", nil, "Monitoring does not block traffic."),
				Validation: []MitigationValidation{
					{Metric: "blocked_boundary_evidence", Expected: "blocked or rejected inbound attempts remain blocked"},
					{Metric: "accepted_boundary_evidence", Expected: "no accepted inbound attempts appear"},
				},
			})
		}
	}
	if incident.State == "observe" || incident.PrimaryTaxonomy == "baseline_novelty" {
		actions = append(actions, monitorOnlyMitigation(incident))
	}
	if incident.PrimaryTaxonomy == "category_deviation" && incident.Score >= 50 {
		actions = append(actions, restrictLANMitigation(incident))
	}
	if target := mitigationDestinationTarget(incident); target != "" && incident.Score >= 50 {
		actions = append(actions, blockDestinationMitigation(incident, target))
		if looksLikeDomain(target) {
			actions = append(actions, dnsBlockMitigation(incident, target))
		}
	}
	if len(actions) == 0 && (incident.State == "risky" || incident.Score >= 70) {
		actions = append(actions, isolateDeviceMitigation(incident))
	}
	return actions
}

func hasAttackEvidenceMitigationSignal(incident PrecisionIncident) bool {
	if hasAnyMitigationSignal(incident, "attack_like_inbound_blocks") {
		return true
	}
	for _, signal := range incident.Signals {
		if strings.HasPrefix(signal.Key, "attack_evidence_") {
			return true
		}
	}
	return false
}

func attackEvidenceReachedExposedService(incident PrecisionIncident) bool {
	for _, signal := range incident.Signals {
		if !strings.HasPrefix(signal.Key, "attack_evidence_") {
			continue
		}
		detail := strings.ToLower(signal.Detail)
		if strings.Contains(detail, "accepted=0") && strings.Contains(detail, "exposed_service_attempts=0") {
			continue
		}
		if strings.Contains(detail, "accepted=") || strings.Contains(detail, "exposed_service_attempts=") {
			return true
		}
	}
	return false
}

func attackEvidenceMitigationPriority(incident PrecisionIncident) int {
	if attackEvidenceReachedExposedService(incident) {
		return 82
	}
	if hasAnyMitigationSignal(incident, "attack_evidence_sensitive_service_probe", "attack_evidence_suspicious_tcp_flags") {
		return 58
	}
	return 48
}

func isolateDeviceMitigation(incident PrecisionIncident) MitigationAction {
	return MitigationAction{
		ID:                   mitigationActionID(incident, "quarantine_device"),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "isolate_device",
		Status:               "review_required",
		Priority:             65,
		Confidence:           incident.Confidence,
		Title:                "Move device to restricted network policy",
		Rationale:            "The incident is high risk but no narrow service-specific mitigation matched. Full isolation is available only as a human-reviewed fallback.",
		RiskReductionTarget:  mitigationRiskTarget(incident, "broad device risk exposure", "move the device to a restricted policy so only explicitly allowed traffic remains"),
		WhyThisAction:        "No narrow rule matched the incident, so isolation is the fallback for high-risk evidence.",
		WhyNotStrongerAction: "This is already the strongest rule-based mitigation; firmware patching or credential rotation must happen outside the gateway.",
		AutoApply:            mitigationAutoApply(false, "never_auto", "Device isolation can break core functionality and requires explicit approval.", "owner approved disruption", "rollback path available", "device identity stable"),
		Impact:               mitigationImpact("high", []string{"most device traffic except DNS/DHCP and explicitly allowed services"}, "Full isolation can break normal device functionality and requires rollback planning."),
		Preconditions:        []string{"Owner approved disruption risk.", "Rollback path is available.", "Device identity is stable enough to target at the gateway."},
		Validation:           defaultMitigationValidation(),
		RollbackRequired:     true,
	}
}

func newServiceBlockMitigation(incident PrecisionIncident, priority int, title, rationale, proto string, port uint16, zone, impactLevel string, affected []string, exposure, expected, whyNotStronger string) MitigationAction {
	return MitigationAction{
		ID:                   mitigationActionID(incident, fmt.Sprintf("block_service_%s_%d", proto, port)),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "block_service",
		Status:               mitigationStatusForAction("block_service", impactLevel),
		Priority:             priority,
		Confidence:           incident.Confidence,
		Title:                title,
		Rationale:            rationale,
		RiskReductionTarget:  mitigationRiskTarget(incident, exposure, expected),
		WhyThisAction:        fmt.Sprintf("The matched signal maps to a known service port (%s/%d), so a service-specific virtual patch is the narrowest effective control.", proto, port),
		WhyNotStrongerAction: whyNotStronger,
		AutoApply:            mitigationAutoApplyForAction("block_service", impactLevel),
		Impact: mitigationImpact(
			impactLevel,
			affected,
			"Service-specific blocking is narrower than device isolation but can still affect legitimate device features.",
		),
		Preconditions: []string{
			"Gateway can enforce per-device firewall rules.",
			"Device IP or DHCP lease is stable enough for a dry-run rule.",
		},
		FirewallRules: []MitigationRule{
			{
				ID:       mitigationActionID(incident, fmt.Sprintf("block_service_%s_%d", proto, port)) + "_rule",
				Backend:  "openwrt_uci",
				Action:   "REJECT",
				DeviceIP: incident.DeviceIP,
				Protocol: proto,
				DstPort:  port,
				DstZone:  zone,
				Comment:  title,
			},
		},
		Validation:       defaultMitigationValidation(),
		RollbackRequired: true,
	}
}

func monitorOnlyMitigation(incident PrecisionIncident) MitigationAction {
	return MitigationAction{
		ID:                   mitigationActionID(incident, "monitor_only"),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "monitor_only",
		Status:               "monitor_only",
		Priority:             20,
		Confidence:           incident.Confidence,
		Title:                "Continue passive observation",
		Rationale:            "The incident is observe-only or baseline novelty without enough evidence for a gateway block.",
		RiskReductionTarget:  mitigationRiskTarget(incident, "weak or unconfirmed risk signal", "avoid disruption while collecting evidence needed for a stronger decision"),
		WhyThisAction:        "The current precision state does not justify blocking traffic.",
		WhyNotStrongerAction: "A stronger gateway rule could create false mitigation by breaking normal traffic from a weak signal.",
		AutoApply:            mitigationAutoApply(true, "safe_auto", "Monitor-only actions do not change network behavior."),
		Impact:               mitigationImpact("low", nil, "Monitoring does not block traffic."),
		Validation: []MitigationValidation{
			{Metric: "signal_repetition", Expected: "signal either repeats and strengthens or remains isolated"},
			{Metric: "baseline", Expected: "device baseline becomes more stable after additional observation"},
		},
	}
}

func restrictLANMitigation(incident PrecisionIncident) MitigationAction {
	return MitigationAction{
		ID:                   mitigationActionID(incident, "restrict_lan_access"),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "restrict_lan_access",
		Status:               "review_required",
		Priority:             68,
		Confidence:           incident.Confidence,
		Title:                "Restrict lateral LAN access",
		Rationale:            "Category deviation suggests the device may be using unexpected local protocols or ports.",
		RiskReductionTarget:  mitigationRiskTarget(incident, "unexpected local or category-deviating behavior", "reduce lateral movement and local attack surface while preserving internet, DNS, and DHCP paths"),
		WhyThisAction:        "LAN restriction targets lateral exposure without fully isolating the device.",
		WhyNotStrongerAction: "Full isolation is reserved for high-risk or multi-signal evidence because it can break normal device function.",
		AutoApply:            mitigationAutoApply(false, "review_required", "LAN restrictions can break pairing, discovery, casting, printing, and local automation.", "owner approved local-service disruption", "device identity stable"),
		Impact:               mitigationImpact("medium", []string{"device-to-LAN traffic", "local discovery or pairing flows"}, "Restricting LAN access can affect normal local integrations."),
		Preconditions:        []string{"IoT zone and LAN zone are separated at the gateway.", "Required local services are known or can be allowlisted."},
		Validation:           defaultMitigationValidation(),
		RollbackRequired:     true,
	}
}

func blockDestinationMitigation(incident PrecisionIncident, target string) MitigationAction {
	rule := MitigationRule{
		ID:       mitigationActionID(incident, "block_destination") + "_rule",
		Backend:  "openwrt_uci",
		Action:   "REJECT",
		DeviceIP: incident.DeviceIP,
		DstZone:  "wan",
		Comment:  "Block suspicious destination",
	}
	if looksLikeIP(target) {
		rule.DstIP = target
	}
	return MitigationAction{
		ID:                   mitigationActionID(incident, "block_destination"),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "block_destination",
		Status:               "review_required",
		Priority:             62,
		Confidence:           incident.Confidence,
		Title:                "Block suspicious destination",
		Rationale:            "A high-scoring novelty or category-deviation incident included a destination that can be targeted directly.",
		RiskReductionTarget:  mitigationRiskTarget(incident, "suspicious external destination "+target, "prevent repeated communication with the observed destination"),
		WhyThisAction:        "Destination blocking is narrower than isolating the device and targets the observed exposure directly.",
		WhyNotStrongerAction: "Device isolation is more disruptive and should wait until destination blocking is insufficient or the incident escalates.",
		AutoApply:            mitigationAutoApply(false, "review_required", "Destination blocks can break vendor cloud, update, or telemetry functions.", "destination reviewed", "owner impact accepted"),
		Impact:               mitigationImpact("medium", []string{"traffic to " + target}, "Destination blocks can disrupt cloud-backed device features."),
		Preconditions:        []string{"Destination is stable enough to target.", "Owner accepts possible vendor cloud disruption."},
		FirewallRules:        []MitigationRule{rule},
		Validation:           defaultMitigationValidation(),
		RollbackRequired:     true,
		Metadata:             map[string]string{"target": target},
	}
}

func dnsBlockMitigation(incident PrecisionIncident, domain string) MitigationAction {
	return MitigationAction{
		ID:                   mitigationActionID(incident, "dns_block"),
		IncidentID:           incident.ID,
		DeviceIP:             incident.DeviceIP,
		DeviceLabel:          incident.DeviceLabel,
		Kind:                 "dns_block",
		Status:               "review_required",
		Priority:             64,
		Confidence:           incident.Confidence,
		Title:                "Block destination at DNS layer",
		Rationale:            "The suspicious destination appears domain-based, so DNS blocking is narrower than IP firewall blocking when addresses may rotate.",
		RiskReductionTarget:  mitigationRiskTarget(incident, "domain destination "+domain, "prevent resolution of the suspicious destination for the affected device or IoT zone"),
		WhyThisAction:        "DNS blocking follows the observed domain and avoids chasing changing IP addresses.",
		WhyNotStrongerAction: "Full device isolation is more disruptive; DNS block is a narrower virtual patch for one destination.",
		AutoApply:            mitigationAutoApply(false, "review_required", "DNS blocks can disable vendor cloud functionality and should be reviewed.", "domain reviewed", "expected cloud dependency checked"),
		Impact:               mitigationImpact("medium", []string{"DNS resolution for " + domain}, "DNS blocks can disrupt cloud-backed device features."),
		Preconditions:        []string{"Gateway DNS enforcement is active.", "Device cannot bypass gateway DNS policy."},
		FirewallRules: []MitigationRule{
			{
				ID:       mitigationActionID(incident, "dns_block") + "_rule",
				Backend:  "openwrt_dnsmasq",
				Action:   "NXDOMAIN",
				DeviceIP: incident.DeviceIP,
				Domain:   domain,
				Comment:  "Block suspicious domain",
			},
		},
		Validation:       defaultMitigationValidation(),
		RollbackRequired: true,
		Metadata:         map[string]string{"domain": domain},
	}
}

func mitigationImpact(level string, affected []string, reason string) MitigationImpact {
	level = strings.ToLower(strings.TrimSpace(level))
	if level == "" {
		level = "medium"
	}
	normalRisk := "possible"
	switch level {
	case "low":
		normalRisk = "unlikely"
	case "high":
		normalRisk = "likely"
	}
	return MitigationImpact{
		Level:             level,
		NormalTrafficRisk: normalRisk,
		AffectedTraffic:   uniqueSortedStrings(affected),
		Reason:            reason,
	}
}

func defaultMitigationValidation() []MitigationValidation {
	return []MitigationValidation{
		{Metric: "incident_count", Expected: "same device incident count decreases after re-observation"},
		{Metric: "blocked_service_signal", Expected: "targeted service signal is no longer observed"},
		{Metric: "normal_traffic", Expected: "DNS/DHCP and expected baseline traffic remain visible"},
	}
}

func mitigationActionTaxonomy() []MitigationActionKind {
	return []MitigationActionKind{
		{Kind: "block_service", Description: "Block a narrow service or port associated with a risky signal.", Strength: "narrow", AutoApplyDefault: "eligible only for low-impact well-known insecure services"},
		{Kind: "block_destination", Description: "Block traffic from a device to a specific external IP destination.", Strength: "medium", AutoApplyDefault: "review_required"},
		{Kind: "restrict_inbound", Description: "Preserve or add inbound deny posture and logging for attack-like inbound activity.", Strength: "narrow", AutoApplyDefault: "review_required"},
		{Kind: "restrict_lan_access", Description: "Restrict device-to-LAN lateral traffic while preserving basic gateway services.", Strength: "medium", AutoApplyDefault: "review_required"},
		{Kind: "isolate_device", Description: "Move a device to a restricted policy where only explicitly allowed traffic remains.", Strength: "strong", AutoApplyDefault: "never_auto"},
		{Kind: "dns_block", Description: "Block or override DNS resolution for a suspicious domain destination.", Strength: "medium", AutoApplyDefault: "review_required"},
		{Kind: "monitor_only", Description: "Do not change network behavior; continue observing until evidence strengthens.", Strength: "none", AutoApplyDefault: "safe_auto"},
	}
}

func mitigationSafetyPolicy() MitigationSafetyPolicy {
	return MitigationSafetyPolicy{
		AutoApplyAllowedWhen: []string{
			"action kind is monitor_only, or a narrow block_service with low measured impact",
			"dry-run output has been generated",
			"target device identity is stable",
			"rollback is available when the action changes gateway behavior",
			"historical flow impact does not touch learned baseline destinations or ports",
		},
		ReviewRequiredWhen: []string{
			"action affects destination, DNS, LAN reachability, inbound policy, or device isolation",
			"DNS/DHCP/NTP or discovery traffic would be blocked",
			"estimated blocked flows are greater than or equal to 5",
			"estimated blocked bytes are greater than or equal to 1MB",
			"normal traffic impact is likely",
			"device baseline is unavailable for a non-service-specific action",
		},
		NeverAutoApplyKinds: []string{"isolate_device"},
		ImpactDowngradeTriggers: []string{
			"blocks_learned_baseline_destination",
			"blocks_learned_baseline_port",
			"estimated_blocked_flows_ge_5",
			"estimated_blocked_bytes_ge_1mb",
			"normal_traffic_risk_likely",
			"baseline_unavailable",
			"blocked_critical_flows_gt_0",
		},
		ConflictResolutionPolicy: []string{
			"dns_block supersedes block_destination for the same domain target",
			"isolate_device supersedes narrower active mitigations for the same incident",
			"active mitigation supersedes monitor_only for the same incident",
			"duplicate gateway rule targets are removed",
		},
		RollbackRequirements: []string{
			"every behavior-changing gateway rule must have a rollback path",
			"post-apply observation must compare incident count, targeted signal disappearance, and normal traffic continuity",
		},
	}
}

func mitigationRiskTarget(incident PrecisionIncident, exposure, expected string) MitigationRiskTarget {
	keys := make([]string, 0, len(incident.Signals))
	for _, signal := range incident.Signals {
		if strings.TrimSpace(signal.Key) != "" {
			keys = append(keys, signal.Key)
		}
	}
	sort.Strings(keys)
	return MitigationRiskTarget{
		Taxonomy:       incident.PrimaryTaxonomy,
		SignalKeys:     keys,
		Exposure:       exposure,
		ExpectedEffect: expected,
	}
}

func mitigationStatusForAction(kind, impactLevel string) string {
	if kind == "monitor_only" {
		return "monitor_only"
	}
	if kind == "block_service" && strings.EqualFold(strings.TrimSpace(impactLevel), "low") {
		return "auto_eligible"
	}
	return "review_required"
}

func mitigationAutoApplyForAction(kind, impactLevel string) MitigationAutoApply {
	switch mitigationStatusForAction(kind, impactLevel) {
	case "auto_eligible":
		return mitigationAutoApply(true, "low_risk_auto", "Narrow low-impact service block with stable device identity can be applied automatically in controlled experiments.", "dry-run reviewed", "rollback available", "device identity stable")
	case "monitor_only":
		return mitigationAutoApply(true, "safe_auto", "Monitor-only action does not change network behavior.")
	default:
		return mitigationAutoApply(false, "review_required", "Action can disrupt normal device behavior and requires human approval.", "dry-run reviewed", "rollback available")
	}
}

func mitigationAutoApply(eligible bool, level, reason string, requirements ...string) MitigationAutoApply {
	out := MitigationAutoApply{
		Eligible: eligible,
		Level:    strings.TrimSpace(level),
		Reason:   strings.TrimSpace(reason),
		Required: uniqueSortedStrings(requirements),
	}
	if !eligible {
		out.BlockedBy = []string{"human_review_required"}
	}
	return out
}

func mitigationDestinationTarget(incident PrecisionIncident) string {
	for _, signal := range incident.Signals {
		for _, token := range strings.Fields(signal.Detail) {
			token = strings.Trim(token, " ,")
			if strings.HasPrefix(token, "destinations=") {
				values := strings.TrimPrefix(token, "destinations=")
				first := strings.Split(values, ",")[0]
				first = strings.TrimSpace(first)
				if first != "" {
					return first
				}
			}
		}
	}
	return ""
}

func looksLikeDomain(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && strings.Contains(value, ".") && !looksLikeIP(value)
}

func looksLikeIP(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && r != '.' && r != ':' {
			return false
		}
	}
	return strings.Contains(value, ".") || strings.Contains(value, ":")
}

func resolveMitigationConflicts(actions []MitigationAction) ([]MitigationAction, []MitigationConflict) {
	if len(actions) == 0 {
		return nil, nil
	}
	kept := make([]MitigationAction, 0, len(actions))
	conflicts := []MitigationConflict{}
	suppressed := map[string]bool{}

	byIncident := map[string][]MitigationAction{}
	for _, action := range actions {
		key := firstNonEmpty(action.IncidentID, action.DeviceIP)
		byIncident[key] = append(byIncident[key], action)
	}
	for _, group := range byIncident {
		if len(group) == 0 {
			continue
		}
		active := group
		if strongest := strongestActionOfKind(active, "isolate_device"); strongest != nil {
			var removed []string
			for _, action := range active {
				if action.ID == strongest.ID || action.Kind == "monitor_only" {
					continue
				}
				suppressed[action.ID] = true
				removed = append(removed, action.ID)
			}
			if len(removed) > 0 {
				conflicts = append(conflicts, MitigationConflict{
					KeptActionID:        strongest.ID,
					SuppressedActionIDs: removed,
					DeviceIP:            strongest.DeviceIP,
					Reason:              "isolate_device supersedes narrower gateway blocks for the same incident.",
				})
			}
		}
		if dns := strongestActionOfKind(active, "dns_block"); dns != nil {
			var removed []string
			for _, action := range active {
				if action.Kind != "block_destination" || action.DeviceIP != dns.DeviceIP {
					continue
				}
				if action.Metadata["target"] == dns.Metadata["domain"] {
					suppressed[action.ID] = true
					removed = append(removed, action.ID)
				}
			}
			if len(removed) > 0 {
				conflicts = append(conflicts, MitigationConflict{
					KeptActionID:        dns.ID,
					SuppressedActionIDs: removed,
					DeviceIP:            dns.DeviceIP,
					Reason:              "dns_block is preferred for domain targets because it follows rotating destination IPs.",
				})
			}
		}
		if len(active) > 1 {
			var activeIDs []string
			for _, action := range active {
				if action.Kind != "monitor_only" {
					activeIDs = append(activeIDs, action.ID)
				}
			}
			if len(activeIDs) > 0 {
				for _, action := range active {
					if action.Kind == "monitor_only" {
						suppressed[action.ID] = true
						conflicts = append(conflicts, MitigationConflict{
							KeptActionID:        activeIDs[0],
							SuppressedActionIDs: []string{action.ID},
							DeviceIP:            action.DeviceIP,
							Reason:              "monitor_only is redundant when an active mitigation is selected for the same incident.",
						})
					}
				}
			}
		}
	}

	seenRule := map[string]string{}
	for _, action := range actions {
		if suppressed[action.ID] {
			continue
		}
		key := mitigationRuleDedupeKey(action)
		if key != "" {
			if existing := seenRule[key]; existing != "" {
				suppressed[action.ID] = true
				conflicts = append(conflicts, MitigationConflict{
					KeptActionID:        existing,
					SuppressedActionIDs: []string{action.ID},
					DeviceIP:            action.DeviceIP,
					Reason:              "duplicate gateway rule target removed.",
				})
				continue
			}
			seenRule[key] = action.ID
		}
		kept = append(kept, action)
	}
	return kept, conflicts
}

func enrichMitigationActionDeviceIdentity(actions []MitigationAction, devices []InventoryDevice) []MitigationAction {
	if len(actions) == 0 {
		return actions
	}
	byIP := map[string]InventoryDevice{}
	for _, device := range devices {
		ip := strings.TrimSpace(device.IP)
		if ip != "" {
			byIP[ip] = device
		}
	}
	out := make([]MitigationAction, len(actions))
	copy(out, actions)
	for i := range out {
		ip := strings.TrimSpace(out[i].DeviceIP)
		identity := MitigationDeviceIdentity{
			IP:          ip,
			Confidence:  "ip_observed",
			Assumptions: []string{"device IP must remain stable for gateway enforcement"},
		}
		if device, ok := byIP[ip]; ok {
			identity.MACAddress = strings.ToLower(strings.TrimSpace(device.MACAddress))
			identity.Hostname = strings.TrimSpace(device.Hostname)
			identity.DHCPLeaseExpiresAt = strings.TrimSpace(device.DHCPLeaseExpiresAt)
			identity.DHCPLeaseState = strings.TrimSpace(device.DHCPLeaseState)
			switch {
			case identity.MACAddress != "" && identity.DHCPLeaseState == "active":
				identity.Confidence = "dhcp_lease_active"
				identity.Assumptions = []string{"DHCP lease maps observed IP to MAC at planning time", "static DHCP lease is recommended before apply"}
			case identity.MACAddress != "":
				identity.Confidence = "mac_observed"
				identity.Assumptions = []string{"MAC was observed in inventory", "lease state should be verified before apply"}
			}
			if out[i].DeviceLabel == "" {
				out[i].DeviceLabel = firstNonEmpty(identity.Hostname, identity.MACAddress)
			}
		}
		out[i].DeviceIdentity = identity
	}
	return out
}

func estimateMitigationImpacts(actions []MitigationAction, flows []FlowRecord, baseline BehaviorBaseline) []MitigationAction {
	if len(actions) == 0 {
		return actions
	}
	baselineByIP := map[string]DeviceBehaviorProfile{}
	for _, profile := range baseline.Devices {
		baselineByIP[strings.TrimSpace(profile.IP)] = profile
	}
	out := make([]MitigationAction, len(actions))
	copy(out, actions)
	for i := range out {
		matches := impactedFlowsForAction(out[i], flows)
		deviceFlows := historicalFlowsForActionDevice(out[i], flows)
		applyImpactEstimate(&out[i], matches, deviceFlows, baselineByIP[out[i].DeviceIP])
	}
	return out
}

func historicalFlowsForActionDevice(action MitigationAction, flows []FlowRecord) []FlowRecord {
	if len(flows) == 0 || strings.TrimSpace(action.DeviceIP) == "" {
		return nil
	}
	var out []FlowRecord
	for _, flow := range flows {
		if strings.TrimSpace(flow.SrcIP) == action.DeviceIP || strings.TrimSpace(flow.DstIP) == action.DeviceIP {
			out = append(out, flow)
		}
	}
	return out
}

func impactedFlowsForAction(action MitigationAction, flows []FlowRecord) []FlowRecord {
	if len(flows) == 0 || action.Kind == "monitor_only" {
		return nil
	}
	var out []FlowRecord
	for _, flow := range flows {
		if !mitigationFlowMatchesAction(action, flow) {
			continue
		}
		out = append(out, flow)
	}
	return out
}

func mitigationFlowMatchesAction(action MitigationAction, flow FlowRecord) bool {
	if strings.TrimSpace(action.DeviceIP) != "" && strings.TrimSpace(flow.SrcIP) != action.DeviceIP {
		return false
	}
	switch action.Kind {
	case "block_service":
		for _, rule := range action.FirewallRules {
			if rule.DstPort != 0 && flow.DstPort != rule.DstPort {
				continue
			}
			if rule.Protocol != "" && !flowProtocolMatchesRule(flow, rule.Protocol) {
				continue
			}
			return true
		}
	case "block_destination":
		target := strings.TrimSpace(action.Metadata["target"])
		return target != "" && flowMatchesDestination(flow, target)
	case "dns_block":
		domain := strings.TrimSpace(action.Metadata["domain"])
		return domain != "" && flowMatchesDestination(flow, domain)
	case "restrict_lan_access":
		return classifyProtectionFlow(flow) == protectionFlowLocal && !isNoiseFlow(flow)
	case "isolate_device":
		return !isEssentialGatewayFlow(flow)
	case "restrict_inbound":
		return strings.EqualFold(flow.Direction, "inbound") || strings.TrimSpace(flow.DstIP) == action.DeviceIP
	default:
		return false
	}
	return false
}

func flowProtocolMatchesRule(flow FlowRecord, protocol string) bool {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		return true
	}
	return strings.EqualFold(flow.Protocol, protocol) ||
		strings.EqualFold(flow.AppProtocol, protocol) ||
		(protocol == "tcp" && strings.EqualFold(flow.Protocol, "tcp")) ||
		(protocol == "udp" && strings.EqualFold(flow.Protocol, "udp"))
}

func flowMatchesDestination(flow FlowRecord, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	values := []string{flow.DstIP, flow.ObservedDestination, flow.Host, flow.SNI}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if value == target || strings.HasSuffix(value, "."+target) {
			return true
		}
	}
	return false
}

func isEssentialGatewayFlow(flow FlowRecord) bool {
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(flow.AppProtocol, flow.Protocol)))
	switch protocol {
	case "dns", "dhcp", "ntp", "mdns", "ssdp", "arp", "llmnr", "nbns":
		return true
	}
	switch flow.DstPort {
	case 53, 67, 68, 123, 137, 138, 1900, 5353, 5355:
		return true
	default:
		return false
	}
}

func applyImpactEstimate(action *MitigationAction, flows, deviceFlows []FlowRecord, baseline DeviceBehaviorProfile) {
	if action == nil {
		return
	}
	action.Impact.HistoricalDeviceFlows = len(deviceFlows)
	if len(flows) == 0 {
		action.Impact.MaintainedCriticalFlows, action.Impact.CriticalFlowKinds = maintainedCriticalFlowSummary(action, deviceFlows)
		action.Impact.BaselineImpact = baselineImpactForAction(*action, baseline)
		action.Impact.Level, action.Impact.NormalTrafficRisk = measuredImpactLevel(*action)
		action.Impact.NormalTrafficRiskReasons = normalTrafficRiskReasons(*action)
		if action.Kind != "monitor_only" {
			action.Impact.Reason = strings.TrimSpace(action.Impact.Reason + " No matching historical flows were found, so disruption could not be measured from this run.")
		}
		action.AutoApply = finalizeMitigationAutoApply(*action)
		if action.Status == "auto_eligible" && !action.AutoApply.Eligible {
			action.Status = "review_required"
		}
		return
	}
	destinations := map[string]bool{}
	protocols := map[string]bool{}
	ports := map[uint16]bool{}
	var bytes int64
	var packets int
	var first, last time.Time
	samples := make([]MitigationImpactedFlow, 0, minInt(5, len(flows)))
	for _, flow := range flows {
		dest := normalizedProtectionDestination(flow)
		if dest == "" {
			dest = flow.DstIP
		}
		addStringBool(destinations, dest)
		addStringBool(protocols, firstNonEmpty(flow.AppProtocol, flow.Protocol))
		if flow.DstPort != 0 {
			ports[flow.DstPort] = true
		}
		bytes += flow.BytesOut + flow.BytesIn
		packets += flow.PacketCount
		if first.IsZero() || flow.Timestamp.Before(first) {
			first = flow.Timestamp
		}
		if flow.Timestamp.After(last) {
			last = flow.Timestamp
		}
		if len(samples) < 5 {
			samples = append(samples, mitigationImpactedFlow(flow))
		}
	}
	action.Impact.EstimatedBlockedFlows = len(flows)
	action.Impact.EstimatedBlockedBytes = bytes
	action.Impact.EstimatedBlockedPackets = packets
	action.Impact.BlockedCriticalFlows = countCriticalFlows(flows)
	action.Impact.MaintainedCriticalFlows, action.Impact.CriticalFlowKinds = maintainedCriticalFlowSummary(action, deviceFlows)
	action.Impact.ObservedDestinations = sortedStringBoolSet(destinations)
	action.Impact.ObservedProtocols = sortedStringBoolSet(protocols)
	action.Impact.ObservedPorts = sortedPortSet(ports)
	action.Impact.DestinationUseCounts = destinationUseCounts(deviceFlows, action.Impact.ObservedDestinations)
	action.Impact.PortUseCounts = portUseCounts(deviceFlows, action.Impact.ObservedPorts)
	action.Impact.SampleFlows = samples
	if !first.IsZero() {
		action.Impact.MeasurementWindow.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		action.Impact.MeasurementWindow.End = last.UTC().Format(time.RFC3339)
	}
	action.Impact.BaselineImpact = baselineImpactForAction(*action, baseline)
	action.Impact.Level, action.Impact.NormalTrafficRisk = measuredImpactLevel(*action)
	action.Impact.NormalTrafficRiskReasons = normalTrafficRiskReasons(*action)
	action.AutoApply = finalizeMitigationAutoApply(*action)
	if action.Status == "auto_eligible" && !action.AutoApply.Eligible {
		action.Status = "review_required"
	}
}

func mitigationImpactedFlow(flow FlowRecord) MitigationImpactedFlow {
	out := MitigationImpactedFlow{
		FlowKey:             flow.FlowKey,
		SrcIP:               flow.SrcIP,
		DstIP:               flow.DstIP,
		DstPort:             flow.DstPort,
		Protocol:            flow.Protocol,
		AppProtocol:         flow.AppProtocol,
		ObservedDestination: normalizedProtectionDestination(flow),
		BytesOut:            flow.BytesOut,
		BytesIn:             flow.BytesIn,
		PacketCount:         flow.PacketCount,
	}
	if !flow.Timestamp.IsZero() {
		out.Timestamp = flow.Timestamp.UTC().Format(time.RFC3339)
	}
	return out
}

func baselineImpactForAction(action MitigationAction, baseline DeviceBehaviorProfile) string {
	if action.Kind == "monitor_only" {
		return "none"
	}
	if strings.TrimSpace(baseline.IP) == "" {
		return "baseline_unavailable"
	}
	learnedDestinations := map[string]bool{}
	for _, value := range baseline.LearnedDestinations {
		learnedDestinations[strings.ToLower(strings.TrimSpace(value))] = true
	}
	for _, dest := range action.Impact.ObservedDestinations {
		if learnedDestinations[strings.ToLower(strings.TrimSpace(dest))] {
			return "blocks_learned_baseline_destination"
		}
	}
	learnedPorts := map[uint16]bool{}
	for _, port := range baseline.LearnedPorts {
		learnedPorts[port] = true
	}
	for _, port := range action.Impact.ObservedPorts {
		if learnedPorts[port] {
			return "blocks_learned_baseline_port"
		}
	}
	if action.Impact.EstimatedBlockedFlows > 0 {
		return "blocks_non_baseline_observed_flows"
	}
	return "no_matching_historical_flows"
}

func measuredImpactLevel(action MitigationAction) (string, string) {
	if action.Kind == "monitor_only" {
		return "low", "unlikely"
	}
	if action.Kind == "isolate_device" {
		return "high", "likely"
	}
	if action.Impact.BlockedCriticalFlows > 0 {
		return "high", "likely"
	}
	switch action.Impact.BaselineImpact {
	case "blocks_learned_baseline_destination", "blocks_learned_baseline_port":
		return "high", "likely"
	}
	switch {
	case action.Impact.EstimatedBlockedFlows >= 20:
		return "high", "likely"
	case action.Impact.EstimatedBlockedFlows >= 5:
		return "medium", "possible"
	case action.Impact.EstimatedBlockedFlows > 0:
		return "medium", "possible"
	default:
		return action.Impact.Level, action.Impact.NormalTrafficRisk
	}
}

func maintainedCriticalFlowSummary(action *MitigationAction, flows []FlowRecord) (int, []KV) {
	if action == nil || len(flows) == 0 {
		return 0, nil
	}
	counts := map[string]int{}
	var maintained int
	for _, flow := range flows {
		if !isEssentialGatewayFlow(flow) {
			continue
		}
		if mitigationFlowMatchesAction(*action, flow) {
			continue
		}
		maintained++
		addCount(counts, criticalFlowKind(flow))
	}
	return maintained, toSortedKV(counts)
}

func countCriticalFlows(flows []FlowRecord) int {
	var count int
	for _, flow := range flows {
		if isEssentialGatewayFlow(flow) {
			count++
		}
	}
	return count
}

func criticalFlowKind(flow FlowRecord) string {
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(flow.AppProtocol, flow.Protocol)))
	switch {
	case protocol == "dns" || flow.DstPort == 53:
		return "dns"
	case protocol == "dhcp" || flow.DstPort == 67 || flow.DstPort == 68:
		return "dhcp"
	case protocol == "ntp" || flow.DstPort == 123:
		return "ntp"
	case protocol == "mdns" || flow.DstPort == 5353:
		return "mdns"
	case protocol == "ssdp" || flow.DstPort == 1900:
		return "ssdp"
	case protocol == "arp":
		return "arp"
	case protocol == "llmnr" || flow.DstPort == 5355:
		return "llmnr"
	case protocol == "nbns" || flow.DstPort == 137 || flow.DstPort == 138:
		return "nbns"
	default:
		return "essential_gateway"
	}
}

func destinationUseCounts(flows []FlowRecord, destinations []string) []KV {
	if len(flows) == 0 || len(destinations) == 0 {
		return nil
	}
	wanted := map[string]string{}
	for _, dest := range destinations {
		key := strings.ToLower(strings.TrimSpace(dest))
		if key != "" {
			wanted[key] = strings.TrimSpace(dest)
		}
	}
	counts := map[string]int{}
	for _, flow := range flows {
		dest := strings.ToLower(strings.TrimSpace(normalizedProtectionDestination(flow)))
		if dest == "" {
			dest = strings.ToLower(strings.TrimSpace(flow.DstIP))
		}
		label, ok := wanted[dest]
		if !ok {
			continue
		}
		counts[label]++
	}
	return toSortedKV(counts)
}

func portUseCounts(flows []FlowRecord, ports []uint16) []MitigationPortUseCount {
	if len(flows) == 0 || len(ports) == 0 {
		return nil
	}
	wanted := map[uint16]bool{}
	for _, port := range ports {
		if port != 0 {
			wanted[port] = true
		}
	}
	counts := map[uint16]int{}
	for _, flow := range flows {
		if wanted[flow.DstPort] {
			counts[flow.DstPort]++
		}
	}
	out := make([]MitigationPortUseCount, 0, len(counts))
	for port, count := range counts {
		out = append(out, MitigationPortUseCount{Port: port, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Port < out[j].Port
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func normalTrafficRiskReasons(action MitigationAction) []string {
	reasons := []string{}
	switch action.Kind {
	case "monitor_only":
		reasons = append(reasons, "monitor_only does not change network behavior")
	case "isolate_device":
		reasons = append(reasons, "isolate_device can block broad device functionality")
	case "restrict_lan_access":
		reasons = append(reasons, "restrict_lan_access can affect local pairing, discovery, casting, printing, or automation")
	case "block_destination", "dns_block":
		reasons = append(reasons, action.Kind+" can affect vendor cloud, update, telemetry, or remote-control paths")
	case "block_service":
		reasons = append(reasons, "block_service targets a specific port/protocol instead of all device traffic")
	}
	if action.Impact.EstimatedBlockedFlows == 0 {
		reasons = append(reasons, "no historical matching flows were observed for the mitigation target")
	} else {
		reasons = append(reasons, fmt.Sprintf("%d historical flow(s) match the mitigation target", action.Impact.EstimatedBlockedFlows))
	}
	if action.Impact.HistoricalDeviceFlows > 0 {
		reasons = append(reasons, fmt.Sprintf("%d total historical flow(s) were observed for the device", action.Impact.HistoricalDeviceFlows))
	}
	if action.Impact.BlockedCriticalFlows > 0 {
		reasons = append(reasons, fmt.Sprintf("%d DNS/DHCP/NTP or discovery flow(s) would be blocked", action.Impact.BlockedCriticalFlows))
	}
	if action.Impact.MaintainedCriticalFlows > 0 {
		reasons = append(reasons, fmt.Sprintf("%d DNS/DHCP/NTP or discovery flow(s) remain outside the mitigation target", action.Impact.MaintainedCriticalFlows))
	}
	switch action.Impact.BaselineImpact {
	case "blocks_learned_baseline_destination":
		reasons = append(reasons, "mitigation target includes a learned baseline destination")
	case "blocks_learned_baseline_port":
		reasons = append(reasons, "mitigation target includes a learned baseline port")
	case "blocks_non_baseline_observed_flows":
		reasons = append(reasons, "matching flows were observed but are not part of the learned baseline")
	case "baseline_unavailable":
		reasons = append(reasons, "device baseline is unavailable")
	case "no_matching_historical_flows":
		reasons = append(reasons, "no matching historical flow was found")
	}
	if action.Impact.EstimatedBlockedFlows >= 20 {
		reasons = append(reasons, "estimated blocked flow count is high")
	} else if action.Impact.EstimatedBlockedFlows >= 5 {
		reasons = append(reasons, "estimated blocked flow count is moderate")
	}
	return uniqueSortedStrings(reasons)
}

func finalizeMitigationAutoApply(action MitigationAction) MitigationAutoApply {
	current := action.AutoApply
	if action.Kind == "monitor_only" {
		return current
	}
	blockers := mitigationAutoApplyBlockers(action)
	if len(blockers) == 0 {
		return current
	}
	out := current
	out.Eligible = false
	out.Level = "review_required"
	out.Downgraded = current.Eligible
	out.BlockedBy = uniqueSortedStrings(append(out.BlockedBy, blockers...))
	out.Required = uniqueSortedStrings(append(out.Required, "human review after measured impact estimate"))
	out.Reason = strings.TrimSpace(current.Reason + " Auto-apply is blocked by measured impact: " + strings.Join(blockers, ", ") + ".")
	return out
}

func mitigationAutoApplyBlockers(action MitigationAction) []string {
	var blockers []string
	switch action.Kind {
	case "isolate_device", "restrict_lan_access", "block_destination", "dns_block":
		blockers = append(blockers, action.Kind+"_requires_review")
	}
	switch action.Impact.BaselineImpact {
	case "blocks_learned_baseline_destination", "blocks_learned_baseline_port":
		blockers = append(blockers, action.Impact.BaselineImpact)
	}
	if action.Impact.EstimatedBlockedFlows >= 5 {
		blockers = append(blockers, "estimated_blocked_flows_ge_5")
	}
	if action.Impact.EstimatedBlockedBytes >= 1_000_000 {
		blockers = append(blockers, "estimated_blocked_bytes_ge_1mb")
	}
	if action.Impact.BlockedCriticalFlows > 0 {
		blockers = append(blockers, "blocked_critical_flows_gt_0")
	}
	if action.Impact.NormalTrafficRisk == "likely" {
		blockers = append(blockers, "normal_traffic_risk_likely")
	}
	if action.Impact.BaselineImpact == "baseline_unavailable" && action.Kind != "block_service" {
		blockers = append(blockers, "baseline_unavailable")
	}
	return uniqueSortedStrings(blockers)
}

func sortedStringBoolSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func strongestActionOfKind(actions []MitigationAction, kind string) *MitigationAction {
	var best *MitigationAction
	for i := range actions {
		if actions[i].Kind != kind {
			continue
		}
		if best == nil || actions[i].Priority > best.Priority {
			best = &actions[i]
		}
	}
	return best
}

func mitigationRuleDedupeKey(action MitigationAction) string {
	if len(action.FirewallRules) == 0 {
		return ""
	}
	rule := action.FirewallRules[0]
	return strings.Join([]string{
		action.Kind,
		rule.DeviceIP,
		rule.Protocol,
		fmt.Sprintf("%d", rule.DstPort),
		rule.DstIP,
		rule.Domain,
		rule.Action,
	}, "|")
}

func hasAnyMitigationSignal(incident PrecisionIncident, keys ...string) bool {
	wanted := map[string]bool{}
	for _, key := range keys {
		wanted[strings.ToLower(strings.TrimSpace(key))] = true
	}
	for _, signal := range incident.Signals {
		if wanted[strings.ToLower(strings.TrimSpace(signal.Key))] {
			return true
		}
	}
	return false
}

func hasSignalContaining(incident PrecisionIncident, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, signal := range incident.Signals {
		haystack := strings.ToLower(signal.Key + " " + signal.Label + " " + signal.Detail)
		if strings.Contains(haystack, value) {
			return true
		}
	}
	return false
}

func mitigationActionID(incident PrecisionIncident, kind string) string {
	base := firstNonEmpty(incident.ID, incident.DeviceIP, "incident")
	base = strings.ToLower(strings.TrimSpace(base))
	var b strings.Builder
	for _, r := range base + "_" + kind {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return fmt.Sprintf("mitigation_%s", strings.TrimSpace(kind))
	}
	return out
}

func buildMitigationMetrics(plan MitigationPlan, precision DetectionPrecisionReport) MitigationMetrics {
	kindCounts := map[string]int{}
	metrics := MitigationMetrics{
		IncidentCount:         len(precision.Incidents),
		ActionCount:           len(plan.Actions),
		ConflictResolvedCount: len(plan.ResolvedConflicts),
	}
	for _, action := range plan.Actions {
		addCount(kindCounts, action.Kind)
		switch action.Status {
		case "auto_eligible":
			metrics.AutoEligibleCount++
		case "monitor_only":
			metrics.MonitorOnlyCount++
		default:
			metrics.ReviewRequiredCount++
		}
		if action.Impact.Level == "high" {
			metrics.HighImpactCount++
		}
		if action.Kind != "monitor_only" && (action.Impact.EstimatedBlockedFlows > 0 || action.Impact.BaselineImpact != "") {
			metrics.MeasuredImpactCount++
		}
		metrics.EstimatedBlockedFlows += action.Impact.EstimatedBlockedFlows
		if action.AutoApply.Downgraded {
			metrics.AutoDowngradedCount++
		}
		if action.RollbackRequired {
			metrics.RollbackRequiredCount++
		}
	}
	metrics.ActionKinds = toSortedKV(kindCounts)
	return metrics
}

func buildMitigationPlanSummary(plan MitigationPlan) MitigationPlanSummary {
	summary := MitigationPlanSummary{
		ResearchStage:           "rule_based_virtual_patch_planning",
		ActionKinds:             plan.Metrics.ActionKinds,
		ConflictCount:           len(plan.ResolvedConflicts),
		SuppressedIncidentCount: len(plan.Suppressed),
		EstimatedBlockedFlows:   plan.Metrics.EstimatedBlockedFlows,
		AutoEligibleActions:     []string{},
		ReviewRequiredActions:   []string{},
		MonitorOnlyActions:      []string{},
		HighImpactActions:       []string{},
		BaselineTouchingActions: []string{},
		RollbackRequiredActions: []string{},
	}
	for _, action := range plan.Actions {
		switch action.Status {
		case "auto_eligible":
			summary.AutoEligibleActions = append(summary.AutoEligibleActions, action.ID)
		case "monitor_only":
			summary.MonitorOnlyActions = append(summary.MonitorOnlyActions, action.ID)
		default:
			summary.ReviewRequiredActions = append(summary.ReviewRequiredActions, action.ID)
		}
		if action.Impact.Level == "high" {
			summary.HighImpactActions = append(summary.HighImpactActions, action.ID)
		}
		if mitigationActionTouchesBaseline(action) {
			summary.BaselineTouchingActions = append(summary.BaselineTouchingActions, action.ID)
		}
		if action.RollbackRequired {
			summary.RollbackRequiredActions = append(summary.RollbackRequiredActions, action.ID)
		}
	}
	summary.AutoEligibleActions = uniqueSortedStrings(summary.AutoEligibleActions)
	summary.ReviewRequiredActions = uniqueSortedStrings(summary.ReviewRequiredActions)
	summary.MonitorOnlyActions = uniqueSortedStrings(summary.MonitorOnlyActions)
	summary.HighImpactActions = uniqueSortedStrings(summary.HighImpactActions)
	summary.BaselineTouchingActions = uniqueSortedStrings(summary.BaselineTouchingActions)
	summary.RollbackRequiredActions = uniqueSortedStrings(summary.RollbackRequiredActions)

	switch {
	case plan.Metrics.ActionCount == 0:
		summary.Decision = "no_rule_based_mitigation"
	case plan.Metrics.ActionCount == plan.Metrics.MonitorOnlyCount:
		summary.Decision = "observe_only"
	case plan.Metrics.ReviewRequiredCount > 0:
		summary.Decision = "dry_run_review_required"
	default:
		summary.Decision = "auto_apply_candidate"
	}
	return summary
}

func buildMitigationExecutionReadiness(plan MitigationPlan) MitigationExecutionReadiness {
	readiness := MitigationExecutionReadiness{
		DryRunReady:  len(plan.Actions) > 0,
		MonitorOnly:  len(plan.Actions) > 0 && plan.Metrics.ActionCount == plan.Metrics.MonitorOnlyCount,
		ReadyActions: []string{},
	}
	var blockers []string
	var nextSteps []string
	if len(plan.Actions) == 0 {
		blockers = append(blockers, "no mitigation actions were generated")
		nextSteps = append(nextSteps, "collect more passive evidence or add a rule mapping for the incident taxonomy")
	}
	for _, action := range plan.Actions {
		if action.AutoApply.Eligible && action.Kind != "monitor_only" {
			readiness.ReadyActions = append(readiness.ReadyActions, action.ID)
		}
		if action.Kind != "monitor_only" && !action.AutoApply.Eligible {
			blockers = append(blockers, action.AutoApply.BlockedBy...)
		}
	}
	if plan.Metrics.ReviewRequiredCount > 0 {
		nextSteps = append(nextSteps, "review dry-run gateway rules and measured impact before apply")
	}
	if plan.Metrics.AutoDowngradedCount > 0 {
		nextSteps = append(nextSteps, "inspect auto-apply downgrades caused by historical flow impact")
	}
	if plan.Metrics.MonitorOnlyCount > 0 {
		nextSteps = append(nextSteps, "continue observation for monitor-only incidents until evidence strengthens or decays")
	}
	if plan.Metrics.RollbackRequiredCount > 0 {
		nextSteps = append(nextSteps, "prepare rollback for behavior-changing gateway rules")
	}
	readiness.ReadyActions = uniqueSortedStrings(readiness.ReadyActions)
	readiness.Blockers = uniqueSortedStrings(blockers)
	readiness.NextSteps = uniqueSortedStrings(nextSteps)
	readiness.ApplyReady = len(readiness.ReadyActions) > 0 && len(readiness.Blockers) == 0
	readiness.Blocked = len(readiness.Blockers) > 0 || len(plan.Actions) == 0
	return readiness
}

func buildMitigationPaperSummary(plan MitigationPlan) MitigationPaperSummary {
	missing := []string{}
	if plan.Metrics.MeasuredImpactCount == 0 {
		missing = append(missing, "normal traffic impact could not be estimated because no historical matching flows were available")
	}
	if plan.Metrics.ActionCount == 0 {
		missing = append(missing, "no rule-based mitigation action was generated for the observed incidents")
	}
	if plan.Metrics.ActionCount == plan.Metrics.MonitorOnlyCount && plan.Metrics.ActionCount > 0 {
		missing = append(missing, "only monitor-only actions were selected, so risk reduction must be evaluated after more observation")
	}
	return MitigationPaperSummary{
		Claim: "Passive observations can be converted into rule-based virtual patch plans with explicit safety gates and measurable disruption estimates.",
		SupportedClaims: []string{
			"incident-level signals are mapped to a fixed mitigation action taxonomy",
			"each action records its risk reduction target and why a stronger action was not selected",
			"auto-apply eligibility is blocked by review-required kinds and measured normal-traffic impact",
			"historical flows estimate how many observed communications each action would block",
			"impact estimation separates blocked target flows from maintained DNS/DHCP/NTP and discovery traffic",
			"port and destination reuse counts explain how likely a mitigation is to affect normal behavior",
			"conflicting actions are resolved before rule export",
		},
		MissingEvidence: missing,
		TableColumns: []string{
			"incident_id",
			"device_ip",
			"action_kind",
			"auto_apply_level",
			"risk_reduction_target",
			"estimated_blocked_flows",
			"maintained_critical_flows",
			"blocked_critical_flows",
			"destination_use_counts",
			"port_use_counts",
			"baseline_impact",
			"normal_traffic_risk",
			"normal_traffic_risk_reasons",
			"status",
		},
		PrimaryOutcomeMetrics: []string{
			"incident count before and after mitigation",
			"targeted signal disappearance rate",
			"estimated blocked normal flows",
			"auto-apply downgrade rate",
			"review-required action rate",
			"conflict resolution count",
		},
		ReObservationRequired:          plan.Metrics.ActionCount > 0,
		NormalTrafficImpactMeasurable:  plan.Metrics.MeasuredImpactCount > 0,
		VirtualPatchPlanReadyForDryRun: len(plan.Actions) > 0,
	}
}

func mitigationActionTouchesBaseline(action MitigationAction) bool {
	switch action.Impact.BaselineImpact {
	case "blocks_learned_baseline_destination", "blocks_learned_baseline_port":
		return true
	default:
		return false
	}
}
