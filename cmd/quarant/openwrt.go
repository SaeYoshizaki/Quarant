package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/device"
	"quarant/internal/reportapi"
)

type openWrtImportConfig struct {
	DHCPLeasesPath        string
	DNSLogPath            string
	FirewallLogPath       string
	ConntrackPath         string
	OutDir                string
	SecurityEventsOutPath string
	AttackEvidenceOutPath string
	TaxonomyPolicyPath    string
	BaseTime              time.Time
}

type openWrtImportResult struct {
	EventCount         int
	SecurityEventCount int
	AttackFindingCount int
	FlowCount          int
	ObservationCount   int
	DeviceCount        int
	SkippedLineCount   int
}

type openWrtCollectConfig struct {
	Host       string
	SSHBin     string
	SSHOptions []string
	OutDir     string
	Timeout    time.Duration
	BaseTime   time.Time
}

type openWrtCollectResult struct {
	Host             string              `json:"host"`
	CollectedAt      string              `json:"collected_at"`
	RawDir           string              `json:"raw_dir"`
	OutputsDir       string              `json:"outputs_dir"`
	RawFiles         map[string]string   `json:"raw_files"`
	Import           openWrtImportResult `json:"import"`
	CollectionErrors []string            `json:"collection_errors,omitempty"`
}

type openWrtSetupPlanConfig struct {
	IOTNetwork      string
	IOTZone         string
	IOTDevice       string
	IOTPorts        []string
	IOTIP           string
	IOTNetmask      string
	DHCPStart       int
	DHCPLimit       int
	DHCPLeaseTime   string
	WANZone         string
	LANZone         string
	AllowIOTToLAN   bool
	InstallPackages bool
	OutPath         string
}

type openWrtDevice struct {
	IP             string
	MAC            string
	Hostname       string
	LeaseExpiresAt time.Time
	LeaseState     string
	FirstSeen      time.Time
	LastSeen       time.Time
	Protocols      map[string]bool
	Ports          map[uint16]bool
	Hosts          map[string]bool
}

type stringListFlag []string

func (f *stringListFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(*f, " ")
}

func (f *stringListFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func runOpenWrt(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("openwrt requires a subcommand: setup-plan, import, or collect")
	}
	switch args[0] {
	case "setup-plan":
		return runOpenWrtSetupPlanCLI(args[1:], os.Stdout)
	case "import":
		return runOpenWrtImportCLI(args[1:], os.Stdout)
	case "collect":
		return runOpenWrtCollectCLI(args[1:], os.Stdout)
	default:
		return fmt.Errorf("unknown openwrt subcommand %q: use setup-plan, import, or collect", args[0])
	}
}

func runOpenWrtSetupPlanCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("openwrt setup-plan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := openWrtSetupPlanConfig{
		IOTNetwork:      "iot",
		IOTZone:         "iot",
		IOTDevice:       "br-iot",
		IOTIP:           "192.168.50.1",
		IOTNetmask:      "255.255.255.0",
		DHCPStart:       100,
		DHCPLimit:       150,
		DHCPLeaseTime:   "12h",
		WANZone:         "wan",
		LANZone:         "lan",
		InstallPackages: true,
		OutPath:         "openwrt-quarant-setup.sh",
	}
	var iotPorts stringListFlag
	fs.StringVar(&cfg.IOTNetwork, "iot-network", cfg.IOTNetwork, "OpenWrt network section name for IoT")
	fs.StringVar(&cfg.IOTZone, "iot-zone", cfg.IOTZone, "OpenWrt firewall zone name for IoT")
	fs.StringVar(&cfg.IOTDevice, "iot-device", cfg.IOTDevice, "OpenWrt device name for IoT bridge/interface")
	fs.Var(&iotPorts, "iot-port", "bridge port for the IoT network; may be repeated, for example lan4")
	fs.StringVar(&cfg.IOTIP, "iot-ip", cfg.IOTIP, "router IP address on the IoT network")
	fs.StringVar(&cfg.IOTNetmask, "iot-netmask", cfg.IOTNetmask, "netmask for the IoT network")
	fs.IntVar(&cfg.DHCPStart, "dhcp-start", cfg.DHCPStart, "DHCP start offset for IoT devices")
	fs.IntVar(&cfg.DHCPLimit, "dhcp-limit", cfg.DHCPLimit, "DHCP address count for IoT devices")
	fs.StringVar(&cfg.DHCPLeaseTime, "dhcp-leasetime", cfg.DHCPLeaseTime, "DHCP lease time for IoT devices")
	fs.StringVar(&cfg.WANZone, "wan-zone", cfg.WANZone, "existing OpenWrt WAN firewall zone")
	fs.StringVar(&cfg.LANZone, "lan-zone", cfg.LANZone, "existing OpenWrt LAN firewall zone")
	fs.BoolVar(&cfg.AllowIOTToLAN, "allow-iot-to-lan", cfg.AllowIOTToLAN, "allow IoT zone forwarding to LAN zone")
	fs.BoolVar(&cfg.InstallPackages, "install-packages", cfg.InstallPackages, "include opkg install commands for visibility tools")
	fs.StringVar(&cfg.OutPath, "out", cfg.OutPath, "script output path, or - for stdout")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse openwrt setup-plan flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("openwrt setup-plan accepts flags only")
	}
	cfg.IOTPorts = iotPorts
	script, err := buildOpenWrtSetupPlan(cfg)
	if err != nil {
		return err
	}
	if cfg.OutPath == "-" {
		_, err := fmt.Fprint(out, script)
		return err
	}
	if err := os.WriteFile(cfg.OutPath, []byte(script), 0644); err != nil {
		return err
	}
	fmt.Fprintf(out, "OpenWrt setup plan written: %s\n", cfg.OutPath)
	return nil
}

func buildOpenWrtSetupPlan(cfg openWrtSetupPlanConfig) (string, error) {
	if strings.TrimSpace(cfg.IOTNetwork) == "" {
		return "", fmt.Errorf("--iot-network is required")
	}
	if strings.TrimSpace(cfg.IOTZone) == "" {
		return "", fmt.Errorf("--iot-zone is required")
	}
	if strings.TrimSpace(cfg.IOTDevice) == "" {
		return "", fmt.Errorf("--iot-device is required")
	}
	if net.ParseIP(strings.TrimSpace(cfg.IOTIP)) == nil {
		return "", fmt.Errorf("--iot-ip must be an IP address")
	}
	if net.ParseIP(strings.TrimSpace(cfg.IOTNetmask)) == nil {
		return "", fmt.Errorf("--iot-netmask must be an IP netmask")
	}
	if cfg.DHCPStart <= 0 || cfg.DHCPLimit <= 0 {
		return "", fmt.Errorf("--dhcp-start and --dhcp-limit must be positive")
	}
	cfg.IOTNetwork = sanitizeOpenWrtName(cfg.IOTNetwork)
	cfg.IOTZone = sanitizeOpenWrtName(cfg.IOTZone)
	cfg.WANZone = sanitizeOpenWrtName(firstNonEmptyString(cfg.WANZone, "wan"))
	cfg.LANZone = sanitizeOpenWrtName(firstNonEmptyString(cfg.LANZone, "lan"))
	if cfg.IOTNetwork == "" || cfg.IOTZone == "" || cfg.WANZone == "" || cfg.LANZone == "" {
		return "", fmt.Errorf("network and zone names must contain letters, numbers, or underscores")
	}
	iotDeviceSection := sanitizeOpenWrtName(cfg.IOTNetwork + "_device")

	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("set -eu\n\n")
	b.WriteString("# Generated by Quarant. Review before running on OpenWrt.\n")
	b.WriteString("# Goal: create an IoT gateway network with DHCP/DNS/firewall visibility for passive monitoring.\n\n")
	b.WriteString("echo '[quarant] backing up current OpenWrt config'\n")
	b.WriteString("BACKUP_DIR=\"/root/quarant-backup-$(date +%Y%m%d-%H%M%S)\"\n")
	b.WriteString("mkdir -p \"$BACKUP_DIR\"\n")
	b.WriteString("cp /etc/config/network \"$BACKUP_DIR/network\" 2>/dev/null || true\n")
	b.WriteString("cp /etc/config/dhcp \"$BACKUP_DIR/dhcp\" 2>/dev/null || true\n")
	b.WriteString("cp /etc/config/firewall \"$BACKUP_DIR/firewall\" 2>/dev/null || true\n\n")

	if cfg.InstallPackages {
		b.WriteString("echo '[quarant] installing optional visibility tools when available'\n")
		b.WriteString("opkg update || true\n")
		b.WriteString("opkg install conntrack tcpdump-mini || true\n\n")
	}

	b.WriteString("echo '[quarant] configuring IoT network'\n")
	b.WriteString("uci -q delete network." + iotDeviceSection + " || true\n")
	b.WriteString("uci -q delete network." + cfg.IOTNetwork + " || true\n")
	b.WriteString("uci set network." + iotDeviceSection + "='device'\n")
	b.WriteString("uci set network." + iotDeviceSection + ".name=" + shellQuote(cfg.IOTDevice) + "\n")
	b.WriteString("uci set network." + iotDeviceSection + ".type='bridge'\n")
	for _, port := range cfg.IOTPorts {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		b.WriteString("uci add_list network." + iotDeviceSection + ".ports=" + shellQuote(port) + "\n")
	}
	if len(cfg.IOTPorts) == 0 {
		b.WriteString("# No bridge ports were specified. Add one later, for example:\n")
		b.WriteString("# uci add_list network." + iotDeviceSection + ".ports='lan4'\n")
	}
	b.WriteString("uci set network." + cfg.IOTNetwork + "='interface'\n")
	b.WriteString("uci set network." + cfg.IOTNetwork + ".proto='static'\n")
	b.WriteString("uci set network." + cfg.IOTNetwork + ".device=" + shellQuote(cfg.IOTDevice) + "\n")
	b.WriteString("uci set network." + cfg.IOTNetwork + ".ipaddr=" + shellQuote(cfg.IOTIP) + "\n")
	b.WriteString("uci set network." + cfg.IOTNetwork + ".netmask=" + shellQuote(cfg.IOTNetmask) + "\n\n")

	b.WriteString("echo '[quarant] configuring IoT DHCP and DNS query logging'\n")
	b.WriteString("uci -q delete dhcp." + cfg.IOTNetwork + " || true\n")
	b.WriteString("uci set dhcp." + cfg.IOTNetwork + "='dhcp'\n")
	b.WriteString("uci set dhcp." + cfg.IOTNetwork + ".interface=" + shellQuote(cfg.IOTNetwork) + "\n")
	b.WriteString("uci set dhcp." + cfg.IOTNetwork + ".start=" + shellQuote(strconv.Itoa(cfg.DHCPStart)) + "\n")
	b.WriteString("uci set dhcp." + cfg.IOTNetwork + ".limit=" + shellQuote(strconv.Itoa(cfg.DHCPLimit)) + "\n")
	b.WriteString("uci set dhcp." + cfg.IOTNetwork + ".leasetime=" + shellQuote(firstNonEmptyString(cfg.DHCPLeaseTime, "12h")) + "\n")
	b.WriteString("uci set dhcp.@dnsmasq[0].logqueries='1'\n")
	b.WriteString("uci set dhcp.@dnsmasq[0].logdhcp='1'\n\n")

	b.WriteString("echo '[quarant] configuring firewall isolation and logging'\n")
	b.WriteString("uci -q delete firewall." + cfg.IOTZone + " || true\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + "='zone'\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".name=" + shellQuote(cfg.IOTZone) + "\n")
	b.WriteString("uci add_list firewall." + cfg.IOTZone + ".network=" + shellQuote(cfg.IOTNetwork) + "\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".input='REJECT'\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".output='ACCEPT'\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".forward='REJECT'\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".log='1'\n")
	b.WriteString("uci set firewall." + cfg.IOTZone + ".log_limit='30/minute'\n\n")

	writeOpenWrtRule(&b, "quarant_allow_iot_dns", "Allow-IoT-DNS", cfg.IOTZone, "", "tcp udp", "", "53", "ACCEPT")
	writeOpenWrtRule(&b, "quarant_allow_iot_dhcp", "Allow-IoT-DHCP", cfg.IOTZone, "", "udp", "68", "67", "ACCEPT")
	writeOpenWrtForwarding(&b, "quarant_iot_to_wan", cfg.IOTZone, cfg.WANZone)
	if cfg.AllowIOTToLAN {
		writeOpenWrtForwarding(&b, "quarant_iot_to_lan", cfg.IOTZone, cfg.LANZone)
	} else {
		b.WriteString("# IoT to LAN forwarding is intentionally not created.\n")
		b.WriteString("# This keeps IoT devices away from trusted LAN clients unless you explicitly allow it.\n\n")
	}

	b.WriteString("echo '[quarant] committing config'\n")
	b.WriteString("uci commit network\n")
	b.WriteString("uci commit dhcp\n")
	b.WriteString("uci commit firewall\n\n")
	b.WriteString("echo '[quarant] restarting services'\n")
	b.WriteString("/etc/init.d/network reload || /etc/init.d/network restart\n")
	b.WriteString("/etc/init.d/dnsmasq restart\n")
	b.WriteString("/etc/init.d/firewall restart\n\n")

	b.WriteString("echo '[quarant] visibility checks'\n")
	b.WriteString("ubus call system board 2>/dev/null || true\n")
	b.WriteString("uci show network." + cfg.IOTNetwork + "\n")
	b.WriteString("uci show dhcp." + cfg.IOTNetwork + "\n")
	b.WriteString("uci show firewall." + cfg.IOTZone + "\n")
	b.WriteString("echo '[quarant] DHCP leases:'\n")
	b.WriteString("cat /tmp/dhcp.leases 2>/dev/null || true\n")
	b.WriteString("echo '[quarant] conntrack sample:'\n")
	b.WriteString("conntrack -L 2>/dev/null | head -20 || cat /proc/net/nf_conntrack 2>/dev/null | head -20 || true\n")
	b.WriteString("echo '[quarant] DNS/firewall log sample:'\n")
	b.WriteString("logread 2>/dev/null | grep -E 'dnsmasq.*query|SRC=.*DST=' | tail -50 || true\n\n")

	b.WriteString("cat <<'EOF'\n")
	b.WriteString("[quarant] Next step from your laptop:\n")
	b.WriteString("  ./quarant openwrt collect --host root@")
	b.WriteString(cfg.IOTIP)
	b.WriteString(" --out-dir runs/openwrt-001\n")
	b.WriteString("  ./quarant report runs/openwrt-001/events.jsonl\n")
	b.WriteString("EOF\n")
	return b.String(), nil
}

func runOpenWrtImportCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("openwrt import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := openWrtImportConfig{}
	fs.StringVar(&cfg.DHCPLeasesPath, "dhcp-leases", "", "OpenWrt /tmp/dhcp.leases path")
	fs.StringVar(&cfg.DNSLogPath, "dns-log", "", "dnsmasq log path")
	fs.StringVar(&cfg.FirewallLogPath, "firewall-log", "", "OpenWrt firewall/kernel log path")
	fs.StringVar(&cfg.ConntrackPath, "conntrack", "", "conntrack dump path")
	fs.StringVar(&cfg.OutDir, "out-dir", "openwrt-run", "directory to write Quarant JSON outputs")
	fs.StringVar(&cfg.SecurityEventsOutPath, "security-events-out", "", "security events JSONL output path (default: out-dir/security_events.jsonl)")
	fs.StringVar(&cfg.AttackEvidenceOutPath, "attack-evidence-out", "", "attack evidence report JSON output path (default: out-dir/attack_evidence_report.json)")
	fs.StringVar(&cfg.TaxonomyPolicyPath, "taxonomy-policy", "", "taxonomy policy JSON path, empty for built-in default")
	nowValue := fs.String("now", "", "base time for logs without a year, RFC3339")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse openwrt import flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("openwrt import accepts flags only")
	}
	if strings.TrimSpace(cfg.OutDir) == "" {
		return fmt.Errorf("--out-dir is required")
	}
	if strings.TrimSpace(*nowValue) != "" {
		now, err := time.Parse(time.RFC3339, strings.TrimSpace(*nowValue))
		if err != nil {
			return fmt.Errorf("parse --now: %w", err)
		}
		cfg.BaseTime = now
	}

	result, err := runOpenWrtImport(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "OpenWrt import complete: devices=%d flows=%d observations=%d events=%d security_events=%d attack_findings=%d out=%s\n",
		result.DeviceCount,
		result.FlowCount,
		result.ObservationCount,
		result.EventCount,
		result.SecurityEventCount,
		result.AttackFindingCount,
		cfg.OutDir,
	)
	if result.SkippedLineCount > 0 {
		fmt.Fprintf(out, "Skipped over-long log lines: %d\n", result.SkippedLineCount)
	}
	return nil
}

func runOpenWrtCollectCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("openwrt collect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := openWrtCollectConfig{}
	var sshOptions stringListFlag
	fs.StringVar(&cfg.Host, "host", "", "OpenWrt SSH target, for example root@192.168.1.1")
	fs.StringVar(&cfg.SSHBin, "ssh-bin", "ssh", "ssh executable path")
	fs.Var(&sshOptions, "ssh-option", "additional ssh option; may be repeated")
	fs.StringVar(&cfg.OutDir, "out-dir", "openwrt-run", "directory to write raw logs and Quarant JSON outputs")
	fs.DurationVar(&cfg.Timeout, "timeout", 20*time.Second, "timeout per SSH command")
	nowValue := fs.String("now", "", "base time for logs without a year, RFC3339")

	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse openwrt collect flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("openwrt collect accepts flags only")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return fmt.Errorf("--host is required")
	}
	if strings.TrimSpace(cfg.OutDir) == "" {
		return fmt.Errorf("--out-dir is required")
	}
	cfg.SSHOptions = sshOptions
	if strings.TrimSpace(*nowValue) != "" {
		now, err := time.Parse(time.RFC3339, strings.TrimSpace(*nowValue))
		if err != nil {
			return fmt.Errorf("parse --now: %w", err)
		}
		cfg.BaseTime = now
	}

	result, err := runOpenWrtCollect(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "OpenWrt collect complete: host=%s devices=%d flows=%d observations=%d events=%d out=%s\n",
		result.Host,
		result.Import.DeviceCount,
		result.Import.FlowCount,
		result.Import.ObservationCount,
		result.Import.EventCount,
		cfg.OutDir,
	)
	if len(result.CollectionErrors) > 0 {
		fmt.Fprintf(out, "Collection warnings: %s\n", strings.Join(result.CollectionErrors, "; "))
	}
	if result.Import.SkippedLineCount > 0 {
		fmt.Fprintf(out, "Skipped over-long log lines: %d\n", result.Import.SkippedLineCount)
	}
	return nil
}

func runOpenWrtCollect(cfg openWrtCollectConfig) (openWrtCollectResult, error) {
	if err := validateOpenWrtSSHHost(cfg.Host); err != nil {
		return openWrtCollectResult{}, err
	}
	if cfg.BaseTime.IsZero() {
		cfg.BaseTime = time.Now()
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if strings.TrimSpace(cfg.SSHBin) == "" {
		cfg.SSHBin = "ssh"
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return openWrtCollectResult{}, err
	}
	rawDir := filepath.Join(cfg.OutDir, "raw")
	if err := os.MkdirAll(rawDir, 0755); err != nil {
		return openWrtCollectResult{}, err
	}

	rawFiles := map[string]string{
		"dhcp_leases":  filepath.Join(rawDir, "dhcp.leases"),
		"dns_log":      filepath.Join(rawDir, "dnsmasq.log"),
		"firewall_log": filepath.Join(rawDir, "firewall.log"),
		"conntrack":    filepath.Join(rawDir, "conntrack.txt"),
	}
	commands := map[string]string{
		"dhcp_leases":  "cat /tmp/dhcp.leases 2>/dev/null || true",
		"dns_log":      "logread 2>/dev/null | grep 'dnsmasq.*query' || true",
		"firewall_log": "logread 2>/dev/null | grep -E 'SRC=.*DST=|DROP|REJECT|ACCEPT' || true",
		"conntrack":    "conntrack -L 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null || true",
	}

	result := openWrtCollectResult{
		Host:        cfg.Host,
		CollectedAt: cfg.BaseTime.UTC().Format(time.RFC3339),
		RawDir:      rawDir,
		OutputsDir:  cfg.OutDir,
		RawFiles:    rawFiles,
	}
	for key, command := range commands {
		output, err := runOpenWrtSSHCommand(cfg, command)
		if err != nil {
			result.CollectionErrors = append(result.CollectionErrors, fmt.Sprintf("%s: %v", key, err))
			output = nil
		}
		if err := os.WriteFile(rawFiles[key], output, 0644); err != nil {
			return openWrtCollectResult{}, err
		}
	}

	importResult, err := runOpenWrtImport(openWrtImportConfig{
		DHCPLeasesPath:  rawFiles["dhcp_leases"],
		DNSLogPath:      rawFiles["dns_log"],
		FirewallLogPath: rawFiles["firewall_log"],
		ConntrackPath:   rawFiles["conntrack"],
		OutDir:          cfg.OutDir,
		BaseTime:        cfg.BaseTime,
	})
	if err != nil {
		return openWrtCollectResult{}, err
	}
	result.Import = importResult
	if err := writeOpenWrtCollectStatus(filepath.Join(cfg.OutDir, "openwrt_collect_status.json"), result); err != nil {
		return openWrtCollectResult{}, err
	}
	return result, nil
}

func runOpenWrtSSHCommand(cfg openWrtCollectConfig, remoteCommand string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	// "--" ends ssh option parsing so the destination can never be read as an option.
	args := append([]string{}, cfg.SSHOptions...)
	args = append(args, "--", cfg.Host, remoteCommand)
	cmd := exec.CommandContext(ctx, cfg.SSHBin, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Errorf("ssh command timed out after %s", cfg.Timeout)
	}
	if err != nil {
		return output, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

// validateOpenWrtSSHHost rejects SSH destinations that ssh would parse as options (for example "-oProxyCommand=...").
func validateOpenWrtSSHHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("--host is required")
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("--host %q must not start with '-'", host)
	}
	return nil
}

func writeOpenWrtCollectStatus(path string, result openWrtCollectResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func runOpenWrtImport(cfg openWrtImportConfig) (openWrtImportResult, error) {
	if cfg.BaseTime.IsZero() {
		cfg.BaseTime = time.Now()
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return openWrtImportResult{}, err
	}

	importer := &openWrtImporter{
		baseTime: cfg.BaseTime,
		devices:  map[string]*openWrtDevice{},
	}
	if err := importer.readDHCPLeases(cfg.DHCPLeasesPath); err != nil {
		return openWrtImportResult{}, err
	}
	if err := importer.readDNSLog(cfg.DNSLogPath); err != nil {
		return openWrtImportResult{}, err
	}
	if err := importer.readFirewallLog(cfg.FirewallLogPath); err != nil {
		return openWrtImportResult{}, err
	}
	if err := importer.readConntrack(cfg.ConntrackPath); err != nil {
		return openWrtImportResult{}, err
	}

	eventsPath := filepath.Join(cfg.OutDir, "events.jsonl")
	securityEventsPath := defaultSibling(cfg.SecurityEventsOutPath, cfg.OutDir, "security_events.jsonl")
	attackEvidencePath := defaultSibling(cfg.AttackEvidenceOutPath, cfg.OutDir, "attack_evidence_report.json")
	flowsPath := filepath.Join(cfg.OutDir, "flows.jsonl")
	observationsPath := filepath.Join(cfg.OutDir, "observations.jsonl")
	inventoryPath := filepath.Join(cfg.OutDir, "device_inventory.json")
	taxonomyPolicy, err := reportapi.LoadSecurityTaxonomyPolicy(cfg.TaxonomyPolicyPath)
	if err != nil {
		return openWrtImportResult{}, err
	}
	importer.securityEvents = reportapi.NormalizeSecurityEventsWithPolicy(importer.securityEvents, taxonomyPolicy)
	if err := writeOpenWrtJSONL(eventsPath, importer.events); err != nil {
		return openWrtImportResult{}, err
	}
	if err := writeOpenWrtJSONL(securityEventsPath, importer.securityEvents); err != nil {
		return openWrtImportResult{}, err
	}
	attackEvidence := reportapi.BuildAttackEvidenceReportWithPolicy(importer.securityEvents, taxonomyPolicy)
	attackEvidence.Source.SecurityEvents = securityEventsPath
	if err := writePrettyJSON(attackEvidencePath, attackEvidence); err != nil {
		return openWrtImportResult{}, err
	}
	if err := writeOpenWrtJSONL(flowsPath, importer.flows); err != nil {
		return openWrtImportResult{}, err
	}
	if err := writeOpenWrtJSONL(observationsPath, importer.observations); err != nil {
		return openWrtImportResult{}, err
	}
	if err := analyzer.WriteDeviceInventoryJSON(inventoryPath, cfg.BaseTime, importer.inventory()); err != nil {
		return openWrtImportResult{}, err
	}

	return openWrtImportResult{
		EventCount:         len(importer.events),
		SecurityEventCount: len(importer.securityEvents),
		AttackFindingCount: len(attackEvidence.Findings),
		FlowCount:          len(importer.flows),
		ObservationCount:   len(importer.observations),
		DeviceCount:        len(importer.devices),
		SkippedLineCount:   importer.skippedLines,
	}, nil
}

type openWrtImporter struct {
	baseTime       time.Time
	devices        map[string]*openWrtDevice
	events         []analyzer.Event
	securityEvents []reportapi.SecurityEvent
	flows          []analyzer.FlowRecord
	observations   []analyzer.ObservationRecord
	skippedLines   int
}

func (i *openWrtImporter) scan(path string, fn func(string) error) error {
	skipped, err := scanOptionalFile(path, fn)
	i.skippedLines += skipped
	return err
}

func (i *openWrtImporter) readDHCPLeases(path string) error {
	return i.scan(path, func(line string) error {
		lease, ok := parseOpenWrtDHCPLease(line, i.baseTime)
		if !ok {
			return nil
		}
		device := i.device(lease.IP)
		device.MAC = lease.MAC
		device.LeaseExpiresAt = lease.ExpiresAt
		device.LeaseState = lease.State
		if lease.Hostname != "*" {
			device.Hostname = lease.Hostname
		}
		// The lease file is a snapshot taken at the reference time; a lease that is
		// still held shows the device was present then. The expiry is not a seen time.
		if lease.State != "expired" {
			device.FirstSeen = minNonZeroTime(device.FirstSeen, i.baseTime.UTC())
			device.LastSeen = maxTime(device.LastSeen, i.baseTime.UTC())
		}
		return nil
	})
}

func (i *openWrtImporter) readDNSLog(path string) error {
	return i.scan(path, func(line string) error {
		record, ok := parseOpenWrtDNSQuery(line, i.baseTime)
		if !ok {
			return nil
		}
		i.observeDevice(record.SrcIP, record.Timestamp, "dns", 53, record.Query)
		i.observations = append(i.observations, analyzer.ObservationRecord{
			Timestamp:           record.Timestamp,
			Kind:                "dns_query",
			SrcIP:               record.SrcIP,
			DstPort:             53,
			Protocol:            "udp",
			AppProtocol:         "dns",
			Direction:           "external",
			DNSQuery:            record.Query,
			ObservedDestination: record.Query,
			PacketCount:         1,
		})
		return nil
	})
}

func (i *openWrtImporter) readFirewallLog(path string) error {
	return i.scan(path, func(line string) error {
		record, ok := parseOpenWrtFirewallLine(line, i.baseTime)
		if !ok {
			return nil
		}
		i.addFlowFromFirewall(record)
		if securityEvent, ok := securityEventFromOpenWrtFirewallRecord(record); ok {
			i.securityEvents = append(i.securityEvents, securityEvent)
		}
		if strings.EqualFold(record.Action, "DROP") || strings.EqualFold(record.Action, "REJECT") {
			i.events = append(i.events, analyzer.Event{
				Timestamp:      record.Timestamp,
				Type:           "OPENWRT_FIREWALL_BLOCK",
				Severity:       analyzer.SeverityInfo,
				RuleID:         "OPENWRT_FIREWALL_BLOCK",
				Category:       "SOC",
				Confidence:     "high",
				ObservedFact:   "OpenWrt firewall logged a blocked packet.",
				Inference:      "This may represent background scanning, denied inbound access, or blocked egress depending on interfaces.",
				Limitation:     "Firewall logs do not prove exploit attempts or compromise by themselves.",
				Recommendation: "Correlate with direction, device role, and repeated sources before raising severity.",
				SrcIP:          record.SrcIP,
				SrcPort:        record.SrcPort,
				DstIP:          record.DstIP,
				DstPort:        record.DstPort,
				Evidence:       record.Raw,
				Message:        "OpenWrt firewall block observed.",
			})
		}
		return nil
	})
}

func (i *openWrtImporter) readConntrack(path string) error {
	return i.scan(path, func(line string) error {
		record, ok := parseOpenWrtConntrackLine(line, i.baseTime)
		if !ok {
			return nil
		}
		i.addFlow(record.Timestamp, record.SrcIP, record.SrcPort, record.DstIP, record.DstPort, record.Protocol, "conntrack")
		return nil
	})
}

func (i *openWrtImporter) addFlowFromFirewall(record openWrtFirewallRecord) {
	i.addFlow(record.Timestamp, record.SrcIP, record.SrcPort, record.DstIP, record.DstPort, record.Protocol, "firewall")
}

func (i *openWrtImporter) addFlow(ts time.Time, srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string, source string) {
	if strings.TrimSpace(srcIP) == "" || strings.TrimSpace(dstIP) == "" {
		return
	}
	appProtocol := inferOpenWrtAppProtocol(protocol, srcPort, dstPort)
	direction := openWrtDirection(srcIP, dstIP)
	destination := dstIP
	if direction == "local" && isPrivateIPString(srcIP) && !isPrivateIPString(dstIP) {
		destination = dstIP
	}
	i.observeDevice(srcIP, ts, appProtocol, dstPort, "")
	i.observeDevice(dstIP, ts, appProtocol, dstPort, "")

	flow := analyzer.FlowRecord{
		Timestamp:           ts,
		FlowKey:             openWrtFlowKey(protocol, srcIP, srcPort, dstIP, dstPort, source),
		SrcIP:               srcIP,
		SrcPort:             srcPort,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Protocol:            strings.ToLower(strings.TrimSpace(protocol)),
		AppProtocol:         appProtocol,
		PacketCount:         1,
		Direction:           direction,
		DeviceLabel:         i.deviceLabel(srcIP),
		ObservedDestination: destination,
	}
	i.flows = append(i.flows, flow)
	i.observations = append(i.observations, analyzer.ObservationRecord{
		Timestamp:           ts,
		Kind:                "flow_snapshot",
		FlowKey:             flow.FlowKey,
		SrcIP:               srcIP,
		SrcPort:             srcPort,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Protocol:            flow.Protocol,
		AppProtocol:         appProtocol,
		Direction:           direction,
		ObservedDestination: destination,
		PacketCount:         1,
	})
}

func (i *openWrtImporter) observeDevice(ip string, ts time.Time, protocol string, port uint16, host string) {
	if !isPrivateIPString(ip) {
		return
	}
	device := i.device(ip)
	device.FirstSeen = minNonZeroTime(device.FirstSeen, ts)
	device.LastSeen = maxTime(device.LastSeen, ts)
	if protocol != "" {
		device.Protocols[protocol] = true
	}
	if port != 0 {
		device.Ports[port] = true
	}
	if host != "" {
		device.Hosts[host] = true
	}
}

func (i *openWrtImporter) device(ip string) *openWrtDevice {
	ip = strings.TrimSpace(ip)
	if i.devices[ip] != nil {
		return i.devices[ip]
	}
	device := &openWrtDevice{
		IP:        ip,
		Protocols: map[string]bool{},
		Ports:     map[uint16]bool{},
		Hosts:     map[string]bool{},
	}
	i.devices[ip] = device
	return device
}

func (i *openWrtImporter) deviceLabel(ip string) string {
	device := i.devices[strings.TrimSpace(ip)]
	if device == nil {
		return ""
	}
	if device.Hostname != "" {
		return device.Hostname
	}
	return device.MAC
}

func (i *openWrtImporter) inventory() []device.InventorySnapshot {
	out := make([]device.InventorySnapshot, 0, len(i.devices))
	for _, item := range i.devices {
		if !isPrivateIPString(item.IP) {
			continue
		}
		out = append(out, device.InventorySnapshot{
			IP:                 item.IP,
			MACAddress:         item.MAC,
			Hostname:           item.Hostname,
			DHCPLeaseExpiresAt: formatOpenWrtTime(item.LeaseExpiresAt),
			DHCPLeaseState:     item.LeaseState,
			FirstSeen:          formatOpenWrtTime(item.FirstSeen),
			LastSeen:           formatOpenWrtTime(item.LastSeen),
			ObservedProtocols:  sortedOpenWrtStringSet(item.Protocols),
			ObservedPorts:      sortedOpenWrtPortSet(item.Ports),
			ObservedHosts:      sortedOpenWrtStringSet(item.Hosts),
			CategoryCandidate:  "GenericIoT",
			CategoryConfidence: "very_low",
			VendorCandidate:    item.MAC,
			VendorConfidence:   "low",
			FamilyCandidate:    item.Hostname,
			FamilyConfidence:   confidenceFromHostname(item.Hostname),
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].IP < out[b].IP })
	return out
}

type openWrtDHCPLease struct {
	ExpiresAt time.Time
	MAC       string
	IP        string
	Hostname  string
	State     string
}

// parseOpenWrtDHCPLease parses a dnsmasq lease line. The first field is the lease
// expiry epoch; 0 means an infinite lease and leaves ExpiresAt zero.
func parseOpenWrtDHCPLease(line string, base time.Time) (openWrtDHCPLease, bool) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return openWrtDHCPLease{}, false
	}
	epoch, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return openWrtDHCPLease{}, false
	}
	ip := strings.TrimSpace(fields[2])
	if net.ParseIP(ip) == nil {
		return openWrtDHCPLease{}, false
	}
	lease := openWrtDHCPLease{
		MAC:      strings.ToLower(fields[1]),
		IP:       ip,
		Hostname: fields[3],
	}
	if epoch <= 0 {
		lease.State = "infinite"
		return lease, true
	}
	lease.ExpiresAt = time.Unix(epoch, 0).UTC()
	lease.State = openWrtLeaseState(lease.ExpiresAt, base)
	return lease, true
}

func openWrtLeaseState(expiresAt, base time.Time) string {
	if expiresAt.IsZero() {
		return ""
	}
	if base.IsZero() {
		base = time.Now()
	}
	if expiresAt.Before(base.UTC()) {
		return "expired"
	}
	return "active"
}

type openWrtDNSRecord struct {
	Timestamp time.Time
	Query     string
	SrcIP     string
}

var dnsmasqQueryRe = regexp.MustCompile(`dnsmasq(?:\[[0-9]+\])?: query\[[^\]]+\] ([^ ]+) from ([0-9a-fA-F:.]+)`)

func parseOpenWrtDNSQuery(line string, base time.Time) (openWrtDNSRecord, bool) {
	matches := dnsmasqQueryRe.FindStringSubmatch(line)
	if len(matches) != 3 {
		return openWrtDNSRecord{}, false
	}
	srcIP := strings.TrimSpace(matches[2])
	if net.ParseIP(srcIP) == nil {
		return openWrtDNSRecord{}, false
	}
	query := strings.TrimSuffix(strings.TrimSpace(matches[1]), ".")
	if query == "" {
		return openWrtDNSRecord{}, false
	}
	return openWrtDNSRecord{
		Timestamp: parseOpenWrtLogTime(line, base),
		Query:     query,
		SrcIP:     srcIP,
	}, true
}

type openWrtFirewallRecord struct {
	Timestamp time.Time
	Action    string
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Protocol  string
	TCPFlags  []string
	Raw       string
}

func parseOpenWrtFirewallLine(line string, base time.Time) (openWrtFirewallRecord, bool) {
	srcIP := openWrtKV(line, "SRC")
	dstIP := openWrtKV(line, "DST")
	if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
		return openWrtFirewallRecord{}, false
	}
	protocol := strings.ToLower(openWrtKV(line, "PROTO"))
	if protocol == "" {
		protocol = "ip"
	}
	action := openWrtFirewallAction(line)
	return openWrtFirewallRecord{
		Timestamp: parseOpenWrtLogTime(line, base),
		Action:    action,
		SrcIP:     srcIP,
		SrcPort:   parseOpenWrtPort(openWrtKV(line, "SPT")),
		DstIP:     dstIP,
		DstPort:   parseOpenWrtPort(openWrtKV(line, "DPT")),
		Protocol:  protocol,
		TCPFlags:  openWrtTCPFlags(line),
		Raw:       strings.TrimSpace(line),
	}, true
}

type openWrtConntrackRecord struct {
	Timestamp time.Time
	SrcIP     string
	SrcPort   uint16
	DstIP     string
	DstPort   uint16
	Protocol  string
}

func parseOpenWrtConntrackLine(line string, base time.Time) (openWrtConntrackRecord, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return openWrtConntrackRecord{}, false
	}
	protocol := strings.ToLower(fields[0])
	// /proc/net/nf_conntrack lines start with the L3 family and number
	// ("ipv4 2 tcp 6 ..."); conntrack -L starts with the L4 protocol.
	if (protocol == "ipv4" || protocol == "ipv6") && len(fields) >= 3 {
		protocol = strings.ToLower(fields[2])
	}
	srcIP := openWrtKV(line, "src")
	dstIP := openWrtKV(line, "dst")
	if net.ParseIP(srcIP) == nil || net.ParseIP(dstIP) == nil {
		return openWrtConntrackRecord{}, false
	}
	return openWrtConntrackRecord{
		Timestamp: base.UTC(),
		SrcIP:     srcIP,
		SrcPort:   parseOpenWrtPort(openWrtKV(line, "sport")),
		DstIP:     dstIP,
		DstPort:   parseOpenWrtPort(openWrtKV(line, "dport")),
		Protocol:  protocol,
	}, true
}

// logreadTimePrefixRe matches OpenWrt logread output ("Sat Sep 26 12:00:02 2026 kern.warn ..."),
// which carries the year; logTimePrefixRe matches classic syslog ("Sep 26 12:00:02 host ...").
var (
	logreadTimePrefixRe = regexp.MustCompile(`^[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+(\d{4})\b`)
	logTimePrefixRe     = regexp.MustCompile(`^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\b`)
)

func parseOpenWrtLogTime(line string, base time.Time) time.Time {
	if matches := logreadTimePrefixRe.FindStringSubmatch(line); len(matches) == 5 {
		parsed, err := time.ParseInLocation("Jan 2 15:04:05 2006", strings.Join(matches[1:], " "), base.Location())
		if err == nil {
			return parsed.UTC()
		}
	}
	matches := logTimePrefixRe.FindStringSubmatch(line)
	if len(matches) != 4 {
		return base.UTC()
	}
	parsed, err := time.ParseInLocation("Jan 2 15:04:05", strings.Join(matches[1:], " "), base.Location())
	if err != nil {
		return base.UTC()
	}
	return withInferredLogYear(parsed, base).UTC()
}

// withInferredLogYear places a timestamp parsed without a year in the year of base,
// falling back to the previous year when that would land more than a day after base
// (for example a "Dec 31" line imported with a January reference time).
func withInferredLogYear(parsed, base time.Time) time.Time {
	loc := base.Location()
	t := time.Date(base.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), loc)
	if t.After(base.Add(24 * time.Hour)) {
		t = time.Date(base.Year()-1, parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(), loc)
	}
	return t
}

func openWrtKV(line, key string) string {
	prefix := key + "="
	for _, field := range strings.Fields(line) {
		if strings.HasPrefix(field, prefix) {
			return strings.Trim(strings.TrimPrefix(field, prefix), "\"")
		}
	}
	return ""
}

func openWrtFirewallAction(line string) string {
	upper := strings.ToUpper(line)
	switch {
	case strings.Contains(upper, "DROP"):
		return "DROP"
	case strings.Contains(upper, "REJECT"):
		return "REJECT"
	case strings.Contains(upper, "ACCEPT"):
		return "ACCEPT"
	default:
		return "LOG"
	}
}

func securityEventFromOpenWrtFirewallRecord(record openWrtFirewallRecord) (reportapi.SecurityEvent, bool) {
	if strings.TrimSpace(record.SrcIP) == "" || strings.TrimSpace(record.DstIP) == "" {
		return reportapi.SecurityEvent{}, false
	}
	direction := openWrtDirection(record.SrcIP, record.DstIP)
	deviceIP := ""
	if isPrivateIPString(record.DstIP) {
		deviceIP = record.DstIP
	} else if isPrivateIPString(record.SrcIP) {
		deviceIP = record.SrcIP
	}
	technique := openWrtAttackTechnique(record, direction)
	category := ""
	if strings.Contains(direction, "inbound") {
		category = "inbound_probe"
	}
	verdict := openWrtSecurityVerdict(record.Action)
	severity := "INFO"
	confidence := "medium"
	if strings.EqualFold(verdict, "accepted") && strings.Contains(direction, "inbound") {
		severity = "WARNING"
	}
	if isSensitiveIoTPort(record.DstPort) && strings.Contains(direction, "inbound") {
		severity = "WARNING"
	}
	return reportapi.SecurityEvent{
		Timestamp:       record.Timestamp,
		Source:          "openwrt_firewall",
		SourceFormat:    "nft_log",
		Sensor:          "openwrt",
		EventType:       "firewall_" + strings.ToLower(firstNonEmptyString(verdict, "log")),
		AttackCategory:  category,
		AttackTechnique: technique,
		Severity:        severity,
		Confidence:      confidence,
		Action:          record.Action,
		Verdict:         verdict,
		Direction:       direction,
		SrcIP:           record.SrcIP,
		SrcPort:         record.SrcPort,
		DstIP:           record.DstIP,
		DstPort:         record.DstPort,
		Protocol:        record.Protocol,
		TCPFlags:        record.TCPFlags,
		DeviceIP:        deviceIP,
		AssetRole:       openWrtAssetRole(deviceIP),
		AggregationKey:  openWrtSecurityAggregationKey(record, direction, deviceIP),
		Raw:             record.Raw,
		Evidence: map[string]string{
			"parser": "openwrt_firewall_v1",
			"action": record.Action,
		},
	}, true
}

func openWrtSecurityVerdict(action string) string {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case "DROP":
		return "dropped"
	case "REJECT":
		return "rejected"
	case "ACCEPT":
		return "accepted"
	default:
		return "logged"
	}
}

func openWrtAttackTechnique(record openWrtFirewallRecord, direction string) string {
	if !strings.Contains(direction, "inbound") {
		return ""
	}
	if strings.EqualFold(record.Protocol, "tcp") {
		flags := map[string]bool{}
		for _, flag := range record.TCPFlags {
			flags[strings.ToUpper(flag)] = true
		}
		switch {
		case flags["FIN"] && flags["PSH"] && flags["URG"]:
			return "tcp_xmas_scan"
		case flags["FIN"] && !flags["SYN"] && !flags["ACK"]:
			return "tcp_fin_scan"
		case flags["SYN"] && !flags["ACK"]:
			return "tcp_syn_probe"
		case len(flags) == 0:
			return "tcp_probe"
		}
	}
	if record.DstPort != 0 {
		return "inbound_port_probe"
	}
	return "inbound_probe"
}

func openWrtAssetRole(deviceIP string) string {
	if strings.TrimSpace(deviceIP) == "" {
		return ""
	}
	return "iot_device"
}

func openWrtSecurityAggregationKey(record openWrtFirewallRecord, direction, deviceIP string) string {
	return strings.Join([]string{
		direction,
		record.SrcIP,
		firstNonEmptyString(deviceIP, record.DstIP),
		record.Protocol,
		fmt.Sprintf("%d", record.DstPort),
	}, "|")
}

func isSensitiveIoTPort(port uint16) bool {
	switch port {
	case 21, 22, 23, 80, 81, 443, 554, 1883, 2323, 5000, 8000, 8080, 8443, 8883:
		return true
	default:
		return false
	}
}

func openWrtTCPFlags(line string) []string {
	upperFields := map[string]bool{}
	for _, field := range strings.Fields(strings.ToUpper(line)) {
		upperFields[strings.Trim(field, "[],:")] = true
	}
	flags := []string{}
	for _, flag := range []string{"SYN", "ACK", "FIN", "RST", "PSH", "URG", "ECE", "CWR"} {
		if upperFields[flag] {
			flags = append(flags, flag)
		}
	}
	return flags
}

func parseOpenWrtPort(value string) uint16 {
	n, err := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

func inferOpenWrtAppProtocol(protocol string, srcPort, dstPort uint16) string {
	switch {
	case srcPort == 53 || dstPort == 53:
		return "dns"
	case srcPort == 5353 || dstPort == 5353:
		return "mdns"
	case srcPort == 1900 || dstPort == 1900:
		return "ssdp"
	case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
		return "dhcp"
	case srcPort == 123 || dstPort == 123:
		return "ntp"
	case dstPort == 80 || srcPort == 80:
		return "http"
	case dstPort == 443 || srcPort == 443 || dstPort == 853 || srcPort == 853:
		return "tls"
	case dstPort == 1883 || srcPort == 1883:
		return "mqtt"
	case dstPort == 8883 || srcPort == 8883:
		return "mqtts"
	case dstPort == 23 || srcPort == 23:
		return "telnet"
	default:
		return strings.ToLower(strings.TrimSpace(protocol))
	}
}

func openWrtDirection(srcIP, dstIP string) string {
	srcPrivate := isPrivateIPString(srcIP)
	dstPrivate := isPrivateIPString(dstIP)
	switch {
	case srcPrivate && !dstPrivate:
		return "external"
	case srcPrivate && dstPrivate:
		return "local"
	case !srcPrivate && dstPrivate:
		return "inbound"
	default:
		return "external"
	}
}

func openWrtFlowKey(protocol, srcIP string, srcPort uint16, dstIP string, dstPort uint16, source string) string {
	return fmt.Sprintf("%s|%s:%d->%s:%d|%s", strings.ToLower(protocol), srcIP, srcPort, dstIP, dstPort, source)
}

func writeOpenWrtRule(b *strings.Builder, section, name, srcZone, destZone, proto, srcPort, destPort, target string) {
	section = sanitizeOpenWrtName(section)
	if section == "" {
		return
	}
	b.WriteString("uci -q delete firewall." + section + " || true\n")
	b.WriteString("uci set firewall." + section + "='rule'\n")
	b.WriteString("uci set firewall." + section + ".name=" + shellQuote(name) + "\n")
	if srcZone != "" {
		b.WriteString("uci set firewall." + section + ".src=" + shellQuote(srcZone) + "\n")
	}
	if destZone != "" {
		b.WriteString("uci set firewall." + section + ".dest=" + shellQuote(destZone) + "\n")
	}
	if proto != "" {
		b.WriteString("uci set firewall." + section + ".proto=" + shellQuote(proto) + "\n")
	}
	if srcPort != "" {
		b.WriteString("uci set firewall." + section + ".src_port=" + shellQuote(srcPort) + "\n")
	}
	if destPort != "" {
		b.WriteString("uci set firewall." + section + ".dest_port=" + shellQuote(destPort) + "\n")
	}
	b.WriteString("uci set firewall." + section + ".target=" + shellQuote(firstNonEmptyString(target, "ACCEPT")) + "\n\n")
}

func writeOpenWrtForwarding(b *strings.Builder, section, srcZone, destZone string) {
	section = sanitizeOpenWrtName(section)
	if section == "" {
		return
	}
	b.WriteString("uci -q delete firewall." + section + " || true\n")
	b.WriteString("uci set firewall." + section + "='forwarding'\n")
	b.WriteString("uci set firewall." + section + ".src=" + shellQuote(srcZone) + "\n")
	b.WriteString("uci set firewall." + section + ".dest=" + shellQuote(destZone) + "\n\n")
}

func sanitizeOpenWrtName(value string) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteRune(r)
		case r == '-':
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" || (out[0] >= '0' && out[0] <= '9') {
		return ""
	}
	return out
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

const openWrtMaxLineBytes = 16 * 1024 * 1024

// scanOptionalFile calls fn for each line of path. Lines longer than
// openWrtMaxLineBytes are skipped and counted instead of aborting the import.
func scanOptionalFile(path string, fn func(string) error) (int, error) {
	if strings.TrimSpace(path) == "" {
		return 0, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 64*1024)
	skipped := 0
	var line []byte
	tooLong := false
	for {
		chunk, err := reader.ReadSlice('\n')
		if !tooLong {
			if len(line)+len(chunk) > openWrtMaxLineBytes {
				tooLong = true
				line = line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return skipped, err
		}
		if tooLong {
			skipped++
		} else if len(line) > 0 {
			if fnErr := fn(strings.TrimRight(string(line), "\r\n")); fnErr != nil {
				return skipped, fnErr
			}
		}
		line = line[:0]
		tooLong = false
		if err == io.EOF {
			return skipped, nil
		}
	}
}

func writeOpenWrtJSONL[T any](path string, items []T) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	for _, item := range items {
		if err := enc.Encode(item); err != nil {
			return err
		}
	}
	return nil
}

func isPrivateIPString(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	return ip != nil && ip.IsPrivate()
}

func sortedOpenWrtStringSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for value := range set {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortedOpenWrtPortSet(set map[uint16]bool) []uint16 {
	out := make([]uint16, 0, len(set))
	for value := range set {
		if value != 0 {
			out = append(out, value)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

func minNonZeroTime(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}

func maxTime(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}
	if current.IsZero() || candidate.After(current) {
		return candidate
	}
	return current
}

func formatOpenWrtTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func confidenceFromHostname(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" || hostname == "*" {
		return ""
	}
	return "medium"
}
