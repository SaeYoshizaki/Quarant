package reportapi

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type GatewayBackendPlan struct {
	GeneratedAt     string                 `json:"generated_at"`
	Backend         string                 `json:"backend"`
	Mode            string                 `json:"mode"`
	ManagedTag      string                 `json:"managed_tag"`
	RuleModelPolicy GatewayRuleModelPolicy `json:"rule_model_policy"`
	Metrics         GatewayBackendMetrics  `json:"metrics"`
	Rules           []GatewayRule          `json:"rules"`
	Conflicts       []GatewayRuleConflict  `json:"conflicts,omitempty"`
	Warnings        []string               `json:"warnings,omitempty"`
	Recommendations []string               `json:"recommendations"`
}

type GatewayRuleModelPolicy struct {
	DeviceIdentityPolicy []string `json:"device_identity_policy"`
	PolicyFamilies       []string `json:"policy_families"`
	ConflictPolicy       []string `json:"conflict_policy"`
	ApplyPolicy          []string `json:"apply_policy"`
}

type GatewayBackendMetrics struct {
	RuleCount         int `json:"rule_count"`
	FirewallRules     int `json:"firewall_rules"`
	DNSRules          int `json:"dns_rules"`
	DenylistRules     int `json:"denylist_rules"`
	AllowlistRules    int `json:"allowlist_rules"`
	ZonePolicyRules   int `json:"zone_policy_rules"`
	WarningCount      int `json:"warning_count"`
	ConflictCount     int `json:"conflict_count"`
	BlockingConflicts int `json:"blocking_conflicts"`
	WarningConflicts  int `json:"warning_conflicts"`
	InfoConflicts     int `json:"info_conflicts"`
	RollbackCommands  int `json:"rollback_commands"`
}

type GatewayRule struct {
	ID               string   `json:"id"`
	ActionID         string   `json:"action_id"`
	IncidentID       string   `json:"incident_id,omitempty"`
	Backend          string   `json:"backend"`
	OpenWrtSection   string   `json:"openwrt_section"`
	Family           string   `json:"family"`
	Policy           string   `json:"policy"`
	Intent           string   `json:"intent"`
	ManagedTag       string   `json:"managed_tag"`
	DeviceIP         string   `json:"device_ip,omitempty"`
	DeviceMAC        string   `json:"device_mac,omitempty"`
	DeviceIdentity   []string `json:"device_identity,omitempty"`
	SrcZone          string   `json:"src_zone,omitempty"`
	DstZone          string   `json:"dst_zone,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	DstPort          uint16   `json:"dst_port,omitempty"`
	DstIP            string   `json:"dst_ip,omitempty"`
	Domain           string   `json:"domain,omitempty"`
	Action           string   `json:"action"`
	Comment          string   `json:"comment"`
	UCICommands      []string `json:"uci_commands"`
	RollbackCommands []string `json:"rollback_commands"`
	Warnings         []string `json:"warnings,omitempty"`
}

type GatewayRuleConflict struct {
	RuleID      string `json:"rule_id"`
	ExistingID  string `json:"existing_id"`
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	ConflictKey string `json:"conflict_key"`
	Resolution  string `json:"resolution"`
}

func BuildOpenWrtGatewayBackendPlan(plan MitigationPlan, iotZone, wanZone string) GatewayBackendPlan {
	iotZone = firstNonEmpty(strings.TrimSpace(iotZone), "iot")
	wanZone = firstNonEmpty(strings.TrimSpace(wanZone), "wan")
	out := GatewayBackendPlan{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		Backend:         "openwrt_uci",
		Mode:            "dry_run",
		ManagedTag:      "quarant-managed",
		RuleModelPolicy: gatewayRuleModelPolicy(),
		Recommendations: []string{
			"Review the generated UCI commands before applying them to OpenWrt.",
			"Prefer DHCP static leases or MAC-aware inventory before relying on per-device IP rules.",
			"Keep generated rollback commands with the experiment artifact.",
		},
	}
	keptByExactKey := map[string]string{}
	var candidates []GatewayRule
	for _, action := range plan.Actions {
		for _, rule := range action.FirewallRules {
			gatewayRule, ok := gatewayRuleFromMitigationRule(action, rule, iotZone, wanZone, out.ManagedTag)
			if !ok {
				continue
			}
			key := gatewayExactConflictKey(gatewayRule)
			if existing := keptByExactKey[key]; existing != "" {
				out.Conflicts = append(out.Conflicts, GatewayRuleConflict{
					RuleID:      gatewayRule.ID,
					ExistingID:  existing,
					Type:        "duplicate",
					Severity:    "info",
					ConflictKey: key,
					Resolution:  "suppressed duplicate generated backend rule",
				})
				continue
			}
			keptByExactKey[key] = gatewayRule.ID
			candidates = append(candidates, gatewayRule)
			out.Warnings = append(out.Warnings, gatewayRule.Warnings...)
		}
	}
	out.Rules, out.Conflicts = resolveGatewayRuleConflicts(candidates, out.Conflicts)
	sort.SliceStable(out.Rules, func(i, j int) bool {
		return out.Rules[i].ID < out.Rules[j].ID
	})
	out.Warnings = uniqueSortedStrings(out.Warnings)
	out.Metrics = gatewayBackendMetrics(out)
	return out
}

func gatewayRuleModelPolicy() GatewayRuleModelPolicy {
	return GatewayRuleModelPolicy{
		DeviceIdentityPolicy: []string{
			"per-device rules are generated from observed IP addresses",
			"OpenWrt deployment should bind device IPs to DHCP static leases where possible",
			"MAC-based identity is reserved in the model but omitted unless inventory provides it",
		},
		PolicyFamilies: []string{
			"denylist: block a specific service, destination, or domain",
			"allowlist: reserved for reviewed exceptions and future isolation policies",
			"zone_policy: reserved for reviewed LAN or isolation posture changes",
		},
		ConflictPolicy: []string{
			"duplicate generated backend targets are suppressed",
			"zone_policy supersedes narrower denylist or allowlist rules for the same device",
			"denylist and allowlist rules for the same exact target are treated as blocking conflicts",
			"dns domain blocks are represented separately from firewall IP/port blocks",
			"DNS and firewall blocks for the same destination are retained but marked as overlap for review",
			"review-required actions remain dry-run until explicit apply support is enabled",
		},
		ApplyPolicy: []string{
			"dry-run is the default mode",
			"apply script generation requires an explicit apply request",
			"blocking gateway conflicts prevent apply script generation",
			"apply scripts snapshot OpenWrt configuration before changing generated sections",
			"generated commands include Quarant managed tags",
			"rollback commands delete only generated Quarant-managed sections",
		},
	}
}

func resolveGatewayRuleConflicts(rules []GatewayRule, existing []GatewayRuleConflict) ([]GatewayRule, []GatewayRuleConflict) {
	if len(rules) == 0 {
		return nil, existing
	}
	conflicts := append([]GatewayRuleConflict{}, existing...)
	suppressed := map[string]bool{}
	for i := range rules {
		if suppressed[rules[i].ID] {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			if suppressed[rules[j].ID] {
				continue
			}
			conflict, suppressID, ok := gatewayPairConflict(rules[i], rules[j])
			if !ok {
				continue
			}
			conflicts = append(conflicts, conflict)
			if suppressID != "" {
				suppressed[suppressID] = true
			}
		}
	}
	out := make([]GatewayRule, 0, len(rules))
	for _, rule := range rules {
		if !suppressed[rule.ID] {
			out = append(out, rule)
		}
	}
	return out, conflicts
}

func gatewayPairConflict(a, b GatewayRule) (GatewayRuleConflict, string, bool) {
	if a.DeviceIP == "" || b.DeviceIP == "" || a.DeviceIP != b.DeviceIP {
		return GatewayRuleConflict{}, "", false
	}
	if a.Policy == "zone_policy" && b.Policy != "zone_policy" {
		return gatewayConflict(a, b, "zone_supersedes_rule", "warning", "zone_policy supersedes narrower generated rule for same device"), b.ID, true
	}
	if b.Policy == "zone_policy" && a.Policy != "zone_policy" {
		return gatewayConflict(b, a, "zone_supersedes_rule", "warning", "zone_policy supersedes narrower generated rule for same device"), a.ID, true
	}
	if gatewaySameTarget(a, b) && a.Policy != b.Policy {
		return gatewayConflict(a, b, "allow_deny_same_target", "blocking", "review required: allowlist and denylist target the same traffic"), "", true
	}
	if gatewayDNSFirewallOverlap(a, b) {
		return gatewayConflict(a, b, "dns_firewall_overlap", "info", "retained overlap: DNS and firewall rules may target the same destination"), "", true
	}
	return GatewayRuleConflict{}, "", false
}

func gatewayConflict(kept, other GatewayRule, typ, severity, resolution string) GatewayRuleConflict {
	return GatewayRuleConflict{
		RuleID:      other.ID,
		ExistingID:  kept.ID,
		Type:        typ,
		Severity:    severity,
		ConflictKey: gatewayReviewConflictKey(kept, other),
		Resolution:  resolution,
	}
}

func gatewayRuleFromMitigationRule(action MitigationAction, rule MitigationRule, iotZone, wanZone, managedTag string) (GatewayRule, bool) {
	family := "firewall"
	policy := "denylist"
	intent := "block"
	if rule.Backend == "openwrt_dnsmasq" {
		family = "dns"
	}
	if action.Kind == "restrict_lan_access" || action.Kind == "isolate_device" {
		policy = "zone_policy"
		intent = "restrict"
	} else if strings.EqualFold(strings.TrimSpace(rule.Action), "ACCEPT") {
		policy = "allowlist"
		intent = "allow"
	}
	if action.Kind == "monitor_only" {
		return GatewayRule{}, false
	}
	if family == "firewall" && strings.TrimSpace(rule.DeviceIP) == "" {
		return GatewayRule{}, false
	}
	if family == "dns" && strings.TrimSpace(rule.Domain) == "" {
		return GatewayRule{}, false
	}
	section := sanitizeGatewaySection(firstNonEmpty(rule.ID, action.ID))
	if section == "" {
		section = sanitizeGatewaySection(action.ID)
	}
	if section == "" {
		section = "quarant_rule"
	}
	comment := gatewayRuleComment(action, rule, managedTag)
	out := GatewayRule{
		ID:             firstNonEmpty(rule.ID, action.ID),
		ActionID:       action.ID,
		IncidentID:     action.IncidentID,
		Backend:        firstNonEmpty(rule.Backend, "openwrt_uci"),
		OpenWrtSection: section,
		Family:         family,
		Policy:         policy,
		Intent:         intent,
		ManagedTag:     managedTag,
		DeviceIP:       rule.DeviceIP,
		DeviceMAC:      action.DeviceIdentity.MACAddress,
		SrcZone:        iotZone,
		DstZone:        firstNonEmpty(rule.DstZone, wanZone),
		Protocol:       rule.Protocol,
		DstPort:        rule.DstPort,
		DstIP:          rule.DstIP,
		Domain:         rule.Domain,
		Action:         firstNonEmpty(rule.Action, "REJECT"),
		Comment:        comment,
	}
	if out.DstZone == "wan" {
		out.DstZone = wanZone
	}
	out.DeviceIdentity = gatewayDeviceIdentity(out)
	out.Warnings = gatewayRuleWarnings(out)
	out.UCICommands = gatewayRuleUCICommands(out)
	out.RollbackCommands = gatewayRuleRollbackCommands(out)
	return out, true
}

func gatewayRuleComment(action MitigationAction, rule MitigationRule, managedTag string) string {
	parts := []string{managedTag, action.Kind}
	if strings.TrimSpace(action.IncidentID) != "" {
		parts = append(parts, "incident="+action.IncidentID)
	}
	if strings.TrimSpace(rule.Comment) != "" {
		parts = append(parts, rule.Comment)
	} else if strings.TrimSpace(action.Title) != "" {
		parts = append(parts, action.Title)
	}
	return strings.Join(parts, " ")
}

func gatewayDeviceIdentity(rule GatewayRule) []string {
	values := []string{}
	if strings.TrimSpace(rule.DeviceIP) != "" {
		values = append(values, "ip:"+strings.TrimSpace(rule.DeviceIP))
		if strings.TrimSpace(rule.DeviceMAC) == "" {
			values = append(values, "requires_stable_dhcp_lease")
		}
	}
	if strings.TrimSpace(rule.DeviceMAC) != "" {
		values = append(values, "mac:"+strings.TrimSpace(rule.DeviceMAC))
	}
	return uniqueSortedStrings(values)
}

func gatewayRuleWarnings(rule GatewayRule) []string {
	var warnings []string
	if rule.Family == "firewall" && strings.TrimSpace(rule.DeviceIP) != "" && strings.TrimSpace(rule.DeviceMAC) == "" {
		warnings = append(warnings, "per-device rule uses IP identity; prefer DHCP static lease or MAC-backed inventory")
	}
	if rule.Policy == "zone_policy" {
		warnings = append(warnings, "zone policy action requires human review before apply")
	}
	if rule.Family == "dns" {
		warnings = append(warnings, "dns block may not affect devices that bypass gateway DNS")
	}
	return uniqueSortedStrings(warnings)
}

func gatewayRuleUCICommands(rule GatewayRule) []string {
	switch rule.Family {
	case "dns":
		return []string{
			"uci -q delete dhcp." + rule.OpenWrtSection + " || true",
			"uci set dhcp." + rule.OpenWrtSection + "='domain'",
			"uci set dhcp." + rule.OpenWrtSection + ".name=" + shellQuoteValue(rule.Domain),
			"uci set dhcp." + rule.OpenWrtSection + ".ip='0.0.0.0'",
			"uci set dhcp." + rule.OpenWrtSection + ".comment=" + shellQuoteValue(rule.Comment),
		}
	default:
		commands := []string{
			"uci -q delete firewall." + rule.OpenWrtSection + " || true",
			"uci set firewall." + rule.OpenWrtSection + "='rule'",
			"uci set firewall." + rule.OpenWrtSection + ".name=" + shellQuoteValue(rule.Comment),
			"uci set firewall." + rule.OpenWrtSection + ".src=" + shellQuoteValue(rule.SrcZone),
			"uci set firewall." + rule.OpenWrtSection + ".src_ip=" + shellQuoteValue(rule.DeviceIP),
		}
		if strings.TrimSpace(rule.DstZone) != "" {
			commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".dest="+shellQuoteValue(rule.DstZone))
		}
		if strings.TrimSpace(rule.Protocol) != "" {
			commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".proto="+shellQuoteValue(rule.Protocol))
		}
		if strings.TrimSpace(rule.DeviceMAC) != "" {
			commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".src_mac="+shellQuoteValue(rule.DeviceMAC))
		}
		if strings.TrimSpace(rule.DstIP) != "" {
			commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".dest_ip="+shellQuoteValue(rule.DstIP))
		}
		if rule.DstPort != 0 {
			commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".dest_port="+shellQuoteValue(fmt.Sprintf("%d", rule.DstPort)))
		}
		commands = append(commands, "uci set firewall."+rule.OpenWrtSection+".target="+shellQuoteValue(rule.Action))
		return commands
	}
}

func gatewayRuleRollbackCommands(rule GatewayRule) []string {
	switch rule.Family {
	case "dns":
		return []string{"uci -q delete dhcp." + rule.OpenWrtSection + " || true"}
	default:
		return []string{"uci -q delete firewall." + rule.OpenWrtSection + " || true"}
	}
}

func gatewayExactConflictKey(rule GatewayRule) string {
	return strings.Join([]string{
		rule.Family,
		rule.Policy,
		rule.DeviceIP,
		rule.SrcZone,
		rule.DstZone,
		rule.Protocol,
		fmt.Sprintf("%d", rule.DstPort),
		rule.DstIP,
		rule.Domain,
		rule.Action,
	}, "|")
}

func gatewayReviewConflictKey(a, b GatewayRule) string {
	parts := []string{
		a.DeviceIP,
		firstNonEmpty(a.Domain, b.Domain),
		firstNonEmpty(a.DstIP, b.DstIP),
		firstNonEmpty(a.Protocol, b.Protocol),
		fmt.Sprintf("%d", firstNonZeroUint16(a.DstPort, b.DstPort)),
		a.Policy + "_vs_" + b.Policy,
		a.Family + "_vs_" + b.Family,
	}
	return strings.Join(parts, "|")
}

func gatewaySameTarget(a, b GatewayRule) bool {
	if a.DeviceIP != b.DeviceIP {
		return false
	}
	if strings.TrimSpace(a.Domain) != "" || strings.TrimSpace(b.Domain) != "" {
		return strings.EqualFold(a.Domain, b.Domain) && strings.TrimSpace(a.Domain) != ""
	}
	if strings.TrimSpace(a.DstIP) != "" || strings.TrimSpace(b.DstIP) != "" {
		return strings.EqualFold(a.DstIP, b.DstIP) &&
			strings.EqualFold(a.Protocol, b.Protocol) &&
			a.DstPort == b.DstPort
	}
	return strings.EqualFold(a.Protocol, b.Protocol) &&
		a.DstPort != 0 &&
		a.DstPort == b.DstPort
}

func gatewayDNSFirewallOverlap(a, b GatewayRule) bool {
	if a.DeviceIP != b.DeviceIP {
		return false
	}
	if a.Family == b.Family {
		return false
	}
	dns, fw := a, b
	if b.Family == "dns" {
		dns, fw = b, a
	}
	if dns.Family != "dns" || fw.Family != "firewall" {
		return false
	}
	if strings.TrimSpace(dns.Domain) == "" {
		return false
	}
	return strings.EqualFold(dns.Domain, fw.Domain) ||
		strings.EqualFold(dns.Domain, fw.DstIP) ||
		strings.Contains(strings.ToLower(fw.Comment), strings.ToLower(dns.Domain))
}

func firstNonZeroUint16(values ...uint16) uint16 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func gatewayBackendMetrics(plan GatewayBackendPlan) GatewayBackendMetrics {
	metrics := GatewayBackendMetrics{
		RuleCount:     len(plan.Rules),
		WarningCount:  len(plan.Warnings),
		ConflictCount: len(plan.Conflicts),
	}
	for _, conflict := range plan.Conflicts {
		switch conflict.Severity {
		case "blocking":
			metrics.BlockingConflicts++
		case "warning":
			metrics.WarningConflicts++
		default:
			metrics.InfoConflicts++
		}
	}
	for _, rule := range plan.Rules {
		switch rule.Family {
		case "dns":
			metrics.DNSRules++
		default:
			metrics.FirewallRules++
		}
		switch rule.Policy {
		case "allowlist":
			metrics.AllowlistRules++
		case "zone_policy":
			metrics.ZonePolicyRules++
		default:
			metrics.DenylistRules++
		}
		metrics.RollbackCommands += len(rule.RollbackCommands)
	}
	return metrics
}

func sanitizeGatewaySection(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range "quarant_" + value {
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
	if len(out) > 48 {
		out = out[:48]
		out = strings.Trim(out, "_")
	}
	return out
}

func shellQuoteValue(value string) string {
	value = strings.ReplaceAll(value, `'`, `'\''`)
	return "'" + value + "'"
}
