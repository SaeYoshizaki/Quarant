package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quarant/analyzer"
)

func TestRunOpenWrtImportWritesQuarantOutputs(t *testing.T) {
	dir := t.TempDir()
	dhcpPath := filepath.Join(dir, "dhcp.leases")
	dnsPath := filepath.Join(dir, "dnsmasq.log")
	firewallPath := filepath.Join(dir, "firewall.log")
	conntrackPath := filepath.Join(dir, "conntrack.txt")
	outDir := filepath.Join(dir, "out")

	writeTestFile(t, dhcpPath, "1790409600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff\n")
	writeTestFile(t, dnsPath, "Sep 26 12:00:01 router dnsmasq[1234]: query[A] api.camera.example from 192.168.8.42\n")
	writeTestFile(t, firewallPath, "Sep 26 12:00:02 router kern.warn kernel: [123.45] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45123 DPT=23 SYN\n")
	writeTestFile(t, conntrackPath, "tcp 6 431999 ESTABLISHED src=192.168.8.42 dst=198.51.100.10 sport=50000 dport=443 src=198.51.100.10 dst=203.0.113.5 sport=443 dport=50000 [ASSURED]\n")

	result, err := runOpenWrtImport(openWrtImportConfig{
		DHCPLeasesPath:  dhcpPath,
		DNSLogPath:      dnsPath,
		FirewallLogPath: firewallPath,
		ConntrackPath:   conntrackPath,
		OutDir:          outDir,
		BaseTime:        time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("runOpenWrtImport: %v", err)
	}
	if result.DeviceCount != 1 {
		t.Fatalf("DeviceCount=%d, want 1", result.DeviceCount)
	}
	if result.FlowCount != 2 {
		t.Fatalf("FlowCount=%d, want 2", result.FlowCount)
	}
	if result.ObservationCount == 0 {
		t.Fatalf("ObservationCount=0, want observations")
	}
	if result.EventCount != 1 {
		t.Fatalf("EventCount=%d, want 1", result.EventCount)
	}
	if result.SecurityEventCount != 1 {
		t.Fatalf("SecurityEventCount=%d, want 1", result.SecurityEventCount)
	}

	events := readJSONLLines[analyzer.Event](t, filepath.Join(outDir, "events.jsonl"))
	if len(events) != 1 || events[0].RuleID != "OPENWRT_FIREWALL_BLOCK" {
		t.Fatalf("events=%+v, want firewall block event", events)
	}
	securityEvents := readJSONLLines[map[string]any](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(securityEvents) != 1 || securityEvents[0]["source"] != "openwrt_firewall" || securityEvents[0]["attack_technique"] != "tcp_syn_probe" {
		t.Fatalf("securityEvents=%+v, want OpenWrt tcp_syn_probe security event", securityEvents)
	}
	attackEvidenceData, err := os.ReadFile(filepath.Join(outDir, "attack_evidence_report.json"))
	if err != nil {
		t.Fatalf("read attack evidence: %v", err)
	}
	if !strings.Contains(string(attackEvidenceData), `"security_event_count": 1`) {
		t.Fatalf("attack evidence=%s, want security event count", attackEvidenceData)
	}
	flows := readJSONLLines[analyzer.FlowRecord](t, filepath.Join(outDir, "flows.jsonl"))
	if !flowWithAppProtocolExists(flows, "tls") || !flowWithAppProtocolExists(flows, "telnet") {
		t.Fatalf("flows=%+v, want tls and telnet flows", flows)
	}
	observations := readJSONLLines[analyzer.ObservationRecord](t, filepath.Join(outDir, "observations.jsonl"))
	if !observationDNSExists(observations, "api.camera.example") {
		t.Fatalf("observations=%+v, want DNS query", observations)
	}

	inventoryData, err := os.ReadFile(filepath.Join(outDir, "device_inventory.json"))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	if !strings.Contains(string(inventoryData), `"ip": "192.168.8.42"`) ||
		!strings.Contains(string(inventoryData), `"family_candidate": "camera-01"`) ||
		!strings.Contains(string(inventoryData), `"mac_address": "aa:bb:cc:dd:ee:ff"`) ||
		!strings.Contains(string(inventoryData), `"hostname": "camera-01"`) ||
		!strings.Contains(string(inventoryData), `"dhcp_lease_expires_at"`) {
		t.Fatalf("inventory=%s, want imported device", inventoryData)
	}
}

func TestBuildOpenWrtSetupPlanCreatesIOTGatewayScript(t *testing.T) {
	script, err := buildOpenWrtSetupPlan(openWrtSetupPlanConfig{
		IOTNetwork:      "iot",
		IOTZone:         "iot",
		IOTDevice:       "br-iot",
		IOTPorts:        []string{"lan4"},
		IOTIP:           "192.168.50.1",
		IOTNetmask:      "255.255.255.0",
		DHCPStart:       100,
		DHCPLimit:       80,
		DHCPLeaseTime:   "6h",
		WANZone:         "wan",
		LANZone:         "lan",
		InstallPackages: true,
	})
	if err != nil {
		t.Fatalf("buildOpenWrtSetupPlan: %v", err)
	}
	for _, want := range []string{
		"uci set network.iot='interface'",
		"uci set network.iot_device.name='br-iot'",
		"uci add_list network.iot_device.ports='lan4'",
		"uci set dhcp.@dnsmasq[0].logqueries='1'",
		"uci set firewall.iot.input='REJECT'",
		"uci set firewall.quarant_iot_to_wan='forwarding'",
		"IoT to LAN forwarding is intentionally not created",
		"conntrack -L",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("setup script missing %q:\n%s", want, script)
		}
	}
}

func TestRunOpenWrtSetupPlanCLIWritesScript(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "setup.sh")
	var out bytes.Buffer
	err := runOpenWrtSetupPlanCLI([]string{
		"--iot-port", "lan4",
		"--out", outPath,
	}, &out)
	if err != nil {
		t.Fatalf("runOpenWrtSetupPlanCLI: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read setup script: %v", err)
	}
	if !strings.Contains(string(data), "Generated by Quarant") {
		t.Fatalf("setup script=%s, want generated marker", data)
	}
	if !strings.Contains(out.String(), "OpenWrt setup plan written") {
		t.Fatalf("output=%q, want written message", out.String())
	}
}

func TestRunOpenWrtImportCLI(t *testing.T) {
	dir := t.TempDir()
	dhcpPath := filepath.Join(dir, "dhcp.leases")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, dhcpPath, "1790409600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff\n")

	var out bytes.Buffer
	err := runOpenWrtImportCLI([]string{
		"--dhcp-leases", dhcpPath,
		"--out-dir", outDir,
		"--now", "2026-09-26T12:00:00Z",
	}, &out)
	if err != nil {
		t.Fatalf("runOpenWrtImportCLI: %v", err)
	}
	if !strings.Contains(out.String(), "OpenWrt import complete") {
		t.Fatalf("output=%q, want completion summary", out.String())
	}
}

func TestRunOpenWrtCollectUsesSSHAndImports(t *testing.T) {
	dir := t.TempDir()
	sshPath := filepath.Join(dir, "fake-ssh")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, sshPath, `#!/bin/sh
cmd="$*"
case "$cmd" in
  *"/tmp/dhcp.leases"*)
    printf '%s\n' '1790409600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff'
    ;;
  *"dnsmasq"*)
    printf '%s\n' 'Sep 26 12:00:01 router dnsmasq[1234]: query[A] api.camera.example from 192.168.8.42'
    ;;
  *"SRC="*)
    printf '%s\n' 'Sep 26 12:00:02 router kern.warn kernel: [123.45] DROP IN=wan OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45123 DPT=23 SYN'
    ;;
  *"conntrack"*)
    printf '%s\n' 'tcp 6 431999 ESTABLISHED src=192.168.8.42 dst=198.51.100.10 sport=50000 dport=443 src=198.51.100.10 dst=203.0.113.5 sport=443 dport=50000 [ASSURED]'
    ;;
esac
`)
	if err := os.Chmod(sshPath, 0755); err != nil {
		t.Fatalf("chmod fake ssh: %v", err)
	}

	result, err := runOpenWrtCollect(openWrtCollectConfig{
		Host:     "root@192.0.2.1",
		SSHBin:   sshPath,
		OutDir:   outDir,
		Timeout:  time.Second,
		BaseTime: time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("runOpenWrtCollect: %v", err)
	}
	if result.Import.DeviceCount != 1 || result.Import.FlowCount != 2 || result.Import.EventCount != 1 {
		t.Fatalf("result=%+v, want imported OpenWrt data", result)
	}
	if len(result.CollectionErrors) != 0 {
		t.Fatalf("CollectionErrors=%+v, want none", result.CollectionErrors)
	}
	if _, err := os.Stat(filepath.Join(outDir, "raw", "dhcp.leases")); err != nil {
		t.Fatalf("raw dhcp leases not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "openwrt_collect_status.json")); err != nil {
		t.Fatalf("collect status not written: %v", err)
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readJSONLLines[T any](t *testing.T, path string) []T {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]T, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			t.Fatalf("unmarshal %s: %v", line, err)
		}
		out = append(out, item)
	}
	return out
}

func flowWithAppProtocolExists(flows []analyzer.FlowRecord, protocol string) bool {
	for _, flow := range flows {
		if flow.AppProtocol == protocol {
			return true
		}
	}
	return false
}

func observationDNSExists(observations []analyzer.ObservationRecord, query string) bool {
	for _, observation := range observations {
		if observation.Kind == "dns_query" && observation.DNSQuery == query {
			return true
		}
	}
	return false
}
