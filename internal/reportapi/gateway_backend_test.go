package reportapi

import "testing"

func TestBuildOpenWrtGatewayBackendPlanAddsManagedTagsAndRollback(t *testing.T) {
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:         "action-http",
				IncidentID: "incident-1",
				DeviceIP:   "192.168.50.20",
				DeviceIdentity: MitigationDeviceIdentity{
					IP:                 "192.168.50.20",
					MACAddress:         "aa:bb:cc:dd:ee:ff",
					Hostname:           "camera-01",
					DHCPLeaseState:     "active",
					DHCPLeaseExpiresAt: "2026-09-27T12:00:00Z",
					Confidence:         "dhcp_lease_active",
				},
				Kind:  "block_service",
				Title: "Block HTTP",
				FirewallRules: []MitigationRule{
					{
						ID:       "rule-http",
						Backend:  "openwrt_uci",
						Action:   "REJECT",
						DeviceIP: "192.168.50.20",
						Protocol: "tcp",
						DstPort:  80,
						DstZone:  "wan",
						Comment:  "Block HTTP",
					},
				},
			},
		},
	}

	got := BuildOpenWrtGatewayBackendPlan(plan, "iot", "wan")
	if got.Metrics.RuleCount != 1 || got.Metrics.FirewallRules != 1 || got.Metrics.RollbackCommands != 1 {
		t.Fatalf("Metrics=%+v, want one firewall rule with rollback", got.Metrics)
	}
	rule := got.Rules[0]
	if rule.ManagedTag != "quarant-managed" || rule.Policy != "denylist" || rule.Family != "firewall" {
		t.Fatalf("rule=%+v, want managed denylist firewall rule", rule)
	}
	if rule.DeviceMAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("rule=%+v, want device MAC", rule)
	}
	if !gatewayStringSliceContains(rule.UCICommands, "uci set firewall.quarant_rule_http.src_ip='192.168.50.20'") ||
		!gatewayStringSliceContains(rule.UCICommands, "uci set firewall.quarant_rule_http.src_mac='aa:bb:cc:dd:ee:ff'") {
		t.Fatalf("UCICommands=%+v, want src_ip and src_mac commands", rule.UCICommands)
	}
	if !gatewayStringSliceContains(rule.RollbackCommands, "uci -q delete firewall.quarant_rule_http || true") {
		t.Fatalf("RollbackCommands=%+v, want delete command", rule.RollbackCommands)
	}
	if !gatewayStringSliceContains(rule.DeviceIdentity, "mac:aa:bb:cc:dd:ee:ff") {
		t.Fatalf("DeviceIdentity=%+v, want MAC identity", rule.DeviceIdentity)
	}
	if gatewayStringSliceContains(rule.DeviceIdentity, "requires_stable_dhcp_lease") {
		t.Fatalf("DeviceIdentity=%+v, stable lease warning should not be identity when MAC is available", rule.DeviceIdentity)
	}
}

func TestBuildOpenWrtGatewayBackendPlanHandlesDNSAndDuplicateConflicts(t *testing.T) {
	action := MitigationAction{
		ID:         "action-domain",
		IncidentID: "incident-domain",
		DeviceIP:   "192.168.50.21",
		Kind:       "dns_block",
		FirewallRules: []MitigationRule{
			{
				ID:       "rule-domain-a",
				Backend:  "openwrt_dnsmasq",
				Action:   "NXDOMAIN",
				DeviceIP: "192.168.50.21",
				Domain:   "bad.example",
				Comment:  "Block domain",
			},
			{
				ID:       "rule-domain-b",
				Backend:  "openwrt_dnsmasq",
				Action:   "NXDOMAIN",
				DeviceIP: "192.168.50.21",
				Domain:   "bad.example",
				Comment:  "Block domain duplicate",
			},
		},
	}

	got := BuildOpenWrtGatewayBackendPlan(MitigationPlan{Actions: []MitigationAction{action}}, "iot", "wan")
	if got.Metrics.RuleCount != 1 || got.Metrics.DNSRules != 1 || got.Metrics.ConflictCount != 1 {
		t.Fatalf("Metrics=%+v conflicts=%+v, want DNS rule and duplicate conflict", got.Metrics, got.Conflicts)
	}
	rule := got.Rules[0]
	if rule.Family != "dns" || rule.Domain != "bad.example" {
		t.Fatalf("rule=%+v, want DNS block", rule)
	}
	if !gatewayStringSliceContains(rule.UCICommands, "uci set dhcp.quarant_rule_domain_a.name='bad.example'") {
		t.Fatalf("UCICommands=%+v, want dnsmasq domain command", rule.UCICommands)
	}
	if !gatewayStringSliceContains(rule.RollbackCommands, "uci -q delete dhcp.quarant_rule_domain_a || true") {
		t.Fatalf("RollbackCommands=%+v, want dhcp delete", rule.RollbackCommands)
	}
}

func TestBuildOpenWrtGatewayBackendPlanFlagsAllowDenySameTarget(t *testing.T) {
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:       "deny-http",
				DeviceIP: "192.168.50.30",
				Kind:     "block_service",
				FirewallRules: []MitigationRule{
					{ID: "deny-http-rule", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.30", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
				},
			},
			{
				ID:       "allow-http",
				DeviceIP: "192.168.50.30",
				Kind:     "allow_service",
				FirewallRules: []MitigationRule{
					{ID: "allow-http-rule", Backend: "openwrt_uci", Action: "ACCEPT", DeviceIP: "192.168.50.30", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
				},
			},
		},
	}

	got := BuildOpenWrtGatewayBackendPlan(plan, "iot", "wan")
	if got.Metrics.RuleCount != 2 || got.Metrics.AllowlistRules != 1 || got.Metrics.DenylistRules != 1 {
		t.Fatalf("Metrics=%+v rules=%+v, want allowlist and denylist retained", got.Metrics, got.Rules)
	}
	if got.Metrics.BlockingConflicts != 1 {
		t.Fatalf("Metrics=%+v conflicts=%+v, want blocking allow/deny conflict", got.Metrics, got.Conflicts)
	}
	if got.Conflicts[0].Type != "allow_deny_same_target" || got.Conflicts[0].Severity != "blocking" {
		t.Fatalf("Conflicts=%+v, want blocking allow/deny conflict", got.Conflicts)
	}
}

func TestBuildOpenWrtGatewayBackendPlanZonePolicySuppressesNarrowerRule(t *testing.T) {
	plan := MitigationPlan{
		Actions: []MitigationAction{
			{
				ID:       "deny-http",
				DeviceIP: "192.168.50.31",
				Kind:     "block_service",
				FirewallRules: []MitigationRule{
					{ID: "deny-http-rule", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.31", Protocol: "tcp", DstPort: 80, DstZone: "wan"},
				},
			},
			{
				ID:       "isolate-device",
				DeviceIP: "192.168.50.31",
				Kind:     "isolate_device",
				FirewallRules: []MitigationRule{
					{ID: "isolate-rule", Backend: "openwrt_uci", Action: "REJECT", DeviceIP: "192.168.50.31", DstZone: "wan"},
				},
			},
		},
	}

	got := BuildOpenWrtGatewayBackendPlan(plan, "iot", "wan")
	if got.Metrics.RuleCount != 1 || got.Metrics.ZonePolicyRules != 1 {
		t.Fatalf("Metrics=%+v rules=%+v, want only zone policy rule kept", got.Metrics, got.Rules)
	}
	if got.Rules[0].ID != "isolate-rule" {
		t.Fatalf("Rules=%+v, want isolate rule kept", got.Rules)
	}
	if got.Metrics.WarningConflicts != 1 {
		t.Fatalf("Metrics=%+v conflicts=%+v, want warning conflict", got.Metrics, got.Conflicts)
	}
	if got.Conflicts[0].Type != "zone_supersedes_rule" {
		t.Fatalf("Conflicts=%+v, want zone supersedes conflict", got.Conflicts)
	}
}

func gatewayStringSliceContains(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}
