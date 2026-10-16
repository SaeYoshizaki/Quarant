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
	"quarant/internal/reportapi"
)

func TestParseOpenWrtLogTimeLogreadAndSyslog(t *testing.T) {
	base := time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC)
	cases := []struct {
		name string
		line string
		base time.Time
		want time.Time
	}{
		{
			name: "logread firewall line carries the year",
			line: "Sat Sep 26 12:00:02 2026 kern.warn kernel: [12345.678] DROP wan in: IN=eth1 OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 LEN=60 PROTO=TCP SPT=45123 DPT=23 SYN",
			base: base,
			want: time.Date(2026, 9, 26, 12, 0, 2, 0, time.UTC),
		},
		{
			name: "logread year wins over reference year",
			line: "Thu Dec 31 23:59:58 2026 daemon.info dnsmasq[1234]: query[A] example.com from 192.168.8.42",
			base: time.Date(2027, 1, 1, 0, 10, 0, 0, time.UTC),
			want: time.Date(2026, 12, 31, 23, 59, 58, 0, time.UTC),
		},
		{
			name: "classic syslog uses reference year",
			line: "Sep 26 12:00:01 router dnsmasq[1234]: query[A] example.com from 192.168.8.42",
			base: base,
			want: time.Date(2026, 9, 26, 12, 0, 1, 0, time.UTC),
		},
		{
			name: "classic syslog rolls back across new year",
			line: "Dec 31 23:59:59 router kern.warn kernel: DROP IN=wan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP",
			base: time.Date(2026, 1, 1, 0, 10, 0, 0, time.UTC),
			want: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name: "unknown prefix falls back to reference time",
			line: "kernel: DROP SRC=203.0.113.9 DST=192.168.8.42",
			base: base,
			want: base,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseOpenWrtLogTime(tc.line, tc.base); !got.Equal(tc.want) {
				t.Fatalf("parseOpenWrtLogTime=%s, want %s", got, tc.want)
			}
		})
	}
}

func TestRunOpenWrtImportLogreadFormat(t *testing.T) {
	dir := t.TempDir()
	dnsPath := filepath.Join(dir, "dnsmasq.log")
	firewallPath := filepath.Join(dir, "firewall.log")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, dnsPath, "Sat Sep 26 12:00:01 2026 daemon.info dnsmasq[1234]: query[A] example.com from 192.168.8.42\n")
	writeTestFile(t, firewallPath, "Sat Sep 26 12:00:02 2026 kern.warn kernel: [12345.678] DROP wan in: IN=eth1 OUT=br-lan MAC=00:11:22:33:44:55 SRC=203.0.113.9 DST=192.168.8.42 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=45123 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0\n")

	if _, err := runOpenWrtImport(openWrtImportConfig{
		DNSLogPath:      dnsPath,
		FirewallLogPath: firewallPath,
		OutDir:          outDir,
		BaseTime:        time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("runOpenWrtImport: %v", err)
	}
	security := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(security) != 1 || !security[0].Timestamp.Equal(time.Date(2026, 9, 26, 12, 0, 2, 0, time.UTC)) || security[0].DstPort != 23 {
		t.Fatalf("security=%+v, want logread timestamp 2026-09-26T12:00:02Z", security)
	}
	observations := readJSONLLines[analyzer.ObservationRecord](t, filepath.Join(outDir, "observations.jsonl"))
	found := false
	for _, observation := range observations {
		if observation.Kind == "dns_query" && observation.DNSQuery == "example.com" {
			found = observation.Timestamp.Equal(time.Date(2026, 9, 26, 12, 0, 1, 0, time.UTC))
		}
	}
	if !found {
		t.Fatalf("observations=%+v, want DNS query at logread timestamp", observations)
	}
}

func TestParseOpenWrtConntrackProtocolFormats(t *testing.T) {
	base := time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC)
	cases := []struct {
		line     string
		protocol string
		dstPort  uint16
	}{
		{"tcp      6 431999 ESTABLISHED src=192.168.8.42 dst=198.51.100.10 sport=50000 dport=443 src=198.51.100.10 dst=203.0.113.5 sport=443 dport=50000 [ASSURED] mark=0 use=1", "tcp", 443},
		{"ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.8.42 dst=198.51.100.10 sport=50000 dport=443 src=198.51.100.10 dst=203.0.113.5 sport=443 dport=50000 [ASSURED] mark=0 zone=0 use=2", "tcp", 443},
		{"ipv4     2 udp      17 29 src=192.168.8.42 dst=8.8.8.8 sport=53000 dport=53 src=8.8.8.8 dst=203.0.113.5 sport=53 dport=53000 mark=0 zone=0 use=2", "udp", 53},
		{"ipv6     10 udp      17 25 src=fd00::42 dst=2001:db8::53 sport=40000 dport=53 src=2001:db8::53 dst=fd00::42 sport=53 dport=40000 mark=0 zone=0 use=2", "udp", 53},
	}
	for _, tc := range cases {
		record, ok := parseOpenWrtConntrackLine(tc.line, base)
		if !ok || record.Protocol != tc.protocol || record.DstPort != tc.dstPort {
			t.Fatalf("line=%q record=%+v ok=%v, want protocol=%s dport=%d", tc.line, record, ok, tc.protocol, tc.dstPort)
		}
	}
}

func TestRunOpenWrtImportSkipsOverlongLines(t *testing.T) {
	dir := t.TempDir()
	firewallPath := filepath.Join(dir, "firewall.log")
	outDir := filepath.Join(dir, "out")
	longLine := "Sat Sep 26 12:00:00 2026 kern.warn kernel: " + strings.Repeat("A", 70*1024)
	hugeLine := strings.Repeat("B", openWrtMaxLineBytes+10)
	valid := "Sat Sep 26 12:00:02 2026 kern.warn kernel: [12345.678] DROP wan in: IN=eth1 OUT=br-lan SRC=203.0.113.9 DST=192.168.8.42 PROTO=TCP SPT=45123 DPT=23 SYN"
	writeTestFile(t, firewallPath, longLine+"\n"+hugeLine+"\n"+valid+"\n")

	result, err := runOpenWrtImport(openWrtImportConfig{FirewallLogPath: firewallPath, OutDir: outDir, BaseTime: time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("runOpenWrtImport: %v", err)
	}
	if result.SecurityEventCount != 1 || result.SkippedLineCount != 1 {
		t.Fatalf("result=%+v, want 70KB line read, >16MB line skipped, valid line imported", result)
	}
}

func TestParseOpenWrtDHCPLeaseUsesReferenceTime(t *testing.T) {
	base := time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC)
	active, ok := parseOpenWrtDHCPLease("1790454600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff", base)
	if !ok || active.State != "active" || !active.ExpiresAt.Equal(time.Unix(1790454600, 0)) {
		t.Fatalf("lease=%+v, want active lease expiring at epoch", active)
	}
	// The same lease replayed against a later reference time is expired, independent of the wall clock.
	expired, _ := parseOpenWrtDHCPLease("1790454600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff", time.Unix(1790454600, 0).Add(time.Hour))
	if expired.State != "expired" {
		t.Fatalf("lease=%+v, want expired against later reference time", expired)
	}
	infinite, ok := parseOpenWrtDHCPLease("0 aa:bb:cc:dd:ee:01 192.168.8.43 plug-01 *", base)
	if !ok || infinite.State != "infinite" || !infinite.ExpiresAt.IsZero() {
		t.Fatalf("lease=%+v, want infinite lease without expiry", infinite)
	}
}

func TestRunOpenWrtImportLeaseInventoryTimes(t *testing.T) {
	dir := t.TempDir()
	dhcpPath := filepath.Join(dir, "dhcp.leases")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, dhcpPath, "1790454600 aa:bb:cc:dd:ee:ff 192.168.8.42 camera-01 01:aa:bb:cc:dd:ee:ff\n0 aa:bb:cc:dd:ee:01 192.168.8.43 plug-01 *\n")
	base := time.Date(2026, 9, 26, 12, 30, 0, 0, time.UTC)
	if _, err := runOpenWrtImport(openWrtImportConfig{DHCPLeasesPath: dhcpPath, OutDir: outDir, BaseTime: base}); err != nil {
		t.Fatalf("runOpenWrtImport: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(outDir, "device_inventory.json"))
	if err != nil {
		t.Fatalf("read inventory: %v", err)
	}
	var report analyzer.DeviceInventoryReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("unmarshal inventory: %v", err)
	}
	if len(report.Devices) != 2 {
		t.Fatalf("devices=%+v, want two leases", report.Devices)
	}
	camera, plug := report.Devices[0], report.Devices[1]
	expiry := time.Unix(1790454600, 0).UTC().Format(time.RFC3339)
	if camera.DHCPLeaseExpiresAt != expiry || camera.LastSeen != "2026-09-26T12:30:00Z" || camera.LastSeen == expiry || camera.DHCPLeaseState != "active" {
		t.Fatalf("camera=%+v, want expiry kept separate from reference seen time", camera)
	}
	if plug.DHCPLeaseExpiresAt != "" || plug.DHCPLeaseState != "infinite" || strings.HasPrefix(plug.FirstSeen, "1970") || plug.LastSeen != "2026-09-26T12:30:00Z" {
		t.Fatalf("plug=%+v, want infinite lease without 1970 timestamps", plug)
	}
}

func TestRunOpenWrtCollectRejectsOptionLikeHost(t *testing.T) {
	dir := t.TempDir()
	sshPath := filepath.Join(dir, "fake-ssh")
	marker := filepath.Join(dir, "ssh-called")
	writeTestFile(t, sshPath, "#!/bin/sh\ntouch "+shellQuote(marker)+"\n")
	if err := os.Chmod(sshPath, 0755); err != nil {
		t.Fatalf("chmod fake ssh: %v", err)
	}
	_, err := runOpenWrtCollect(openWrtCollectConfig{
		Host:    "-oProxyCommand=touch /tmp/pwned",
		SSHBin:  sshPath,
		OutDir:  filepath.Join(dir, "out"),
		Timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "must not start with '-'") {
		t.Fatalf("err=%v, want option-like host rejected", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("ssh was executed for an option-like host")
	}
}

func TestRunOpenWrtSSHCommandEndsOptionsBeforeHost(t *testing.T) {
	dir := t.TempDir()
	sshPath := filepath.Join(dir, "fake-ssh")
	writeTestFile(t, sshPath, "#!/bin/sh\nfor arg in \"$@\"; do printf '%s\\n' \"$arg\"; done\n")
	if err := os.Chmod(sshPath, 0755); err != nil {
		t.Fatalf("chmod fake ssh: %v", err)
	}
	output, err := runOpenWrtSSHCommand(openWrtCollectConfig{
		Host:       "root@192.0.2.1",
		SSHBin:     sshPath,
		SSHOptions: []string{"-oBatchMode=yes"},
		Timeout:    time.Second,
	}, "true")
	if err != nil {
		t.Fatalf("runOpenWrtSSHCommand: %v", err)
	}
	if got := strings.TrimSpace(string(output)); got != "-oBatchMode=yes\n--\nroot@192.0.2.1\ntrue" {
		t.Fatalf("ssh argv=%q, want options, --, host, command", got)
	}
}

func TestReadSuricataEVEKeepsLargeFlowIDsExact(t *testing.T) {
	dir := t.TempDir()
	evePath := filepath.Join(dir, "eve.json")
	writeTestFile(t, evePath,
		`{"timestamp":"2026-09-26T12:00:00.000000+0000","flow_id":1234567890123456789,"event_type":"flow","src_ip":"192.168.8.42","src_port":50000,"dest_ip":"198.51.100.10","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":3,"pkts_toclient":2,"bytes_toserver":300,"bytes_toclient":200}}`+"\n"+
			`{"timestamp":"2026-09-26T12:00:00.000000+0000","flow_id":1234567890123456790,"event_type":"flow","src_ip":"192.168.8.42","src_port":50001,"dest_ip":"198.51.100.10","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":3,"pkts_toclient":2,"bytes_toserver":300,"bytes_toclient":200}}`+"\n")
	records, err := readSuricataEVE(evePath)
	if err != nil {
		t.Fatalf("readSuricataEVE: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%d, want 2", len(records))
	}
	first, _ := flowFromSuricataEVE(records[0])
	second, _ := flowFromSuricataEVE(records[1])
	if first.FlowKey != "1234567890123456789" || second.FlowKey != "1234567890123456790" {
		t.Fatalf("flow keys=%q,%q, want exact 64-bit flow ids", first.FlowKey, second.FlowKey)
	}
}

func TestRunSnortImportParsesSnort3AlertJSON(t *testing.T) {
	dir := t.TempDir()
	alertPath := filepath.Join(dir, "alert_json.txt")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, alertPath,
		`{ "timestamp" : "09/26-12:00:02.123456", "pkt_num" : 42, "proto" : "TCP", "pkt_gen" : "raw", "pkt_len" : 60, "dir" : "C2S", "src_ap" : "203.0.113.9:45124", "dst_ap" : "192.168.8.42:80", "rule" : "1:1000001:1", "action" : "allow", "msg" : "ET SCAN HTTP Probe", "class" : "Attempted Information Leak", "priority" : 2, "src_addr" : "203.0.113.9", "src_port" : "45124", "dst_addr" : "192.168.8.42", "dst_port" : "80", "gid" : 1, "sid" : 1000001, "rev" : 1 }`+"\n"+
			`{ "timestamp" : "26/09/26-12:00:03.500000", "proto" : "TCP", "msg" : "ET SCAN Telnet Probe", "class" : "Attempted Recon", "priority" : 2, "src_addr" : "203.0.113.9", "src_port" : 45125, "dst_addr" : "192.168.8.42", "dst_port" : 23, "sid" : 1000002 }`+"\n")

	var out bytes.Buffer
	if err := runSnortImportCLI([]string{"--alerts", alertPath, "--out-dir", outDir, "--now", "2026-09-26T12:30:00Z"}, &out); err != nil {
		t.Fatalf("runSnortImportCLI: %v", err)
	}
	events := readJSONLLines[reportapi.SecurityEvent](t, filepath.Join(outDir, "security_events.jsonl"))
	if len(events) != 2 {
		t.Fatalf("events=%+v, want both Snort 3 alerts", events)
	}
	if !events[0].Timestamp.Equal(time.Date(2026, 9, 26, 12, 0, 2, 123456000, time.UTC)) || events[0].ClassType != "Attempted Information Leak" || events[0].SrcPort != 45124 || events[0].DstPort != 80 || events[0].SID != "1000001" {
		t.Fatalf("event=%+v, want Snort 3 timestamp, class and string ports", events[0])
	}
	if !events[1].Timestamp.Equal(time.Date(2026, 9, 26, 12, 0, 3, 500000000, time.UTC)) || events[1].ClassType != "Attempted Recon" || events[1].DstPort != 23 {
		t.Fatalf("event=%+v, want -y timestamp and numeric ports", events[1])
	}
}

func TestParseSnortFastTimestampUsesReferenceYear(t *testing.T) {
	base := time.Date(2030, 1, 1, 0, 5, 0, 0, time.UTC)
	if got := parseSnortFastTimestamp("12/31-23:59:59.000000", base); !got.Equal(time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC)) {
		t.Fatalf("timestamp=%s, want previous year relative to reference", got)
	}
	if got := parseSnortFastTimestamp("01/01-00:01:00.000000", base); !got.Equal(time.Date(2030, 1, 1, 0, 1, 0, 0, time.UTC)) {
		t.Fatalf("timestamp=%s, want reference year", got)
	}
	line := "09/26-12:00:03.000000 [**] [1:1000001:1] ET SCAN HTTP Probe [**] [Classification: Attempted Recon] [Priority: 2] {TCP} 203.0.113.9:45124 -> 192.168.8.42:80"
	event, ok := parseSnortFastAlert(line, time.Date(2031, 9, 27, 0, 0, 0, 0, time.UTC))
	if !ok || event.Timestamp.Year() != 2031 {
		t.Fatalf("event=%+v, want fast alert year from reference time", event)
	}
}

func TestRunZeekImportJSONLogs(t *testing.T) {
	dir := t.TempDir()
	connPath := filepath.Join(dir, "conn.log")
	dnsPath := filepath.Join(dir, "dns.log")
	httpPath := filepath.Join(dir, "http.log")
	sslPath := filepath.Join(dir, "ssl.log")
	outDir := filepath.Join(dir, "out")
	writeTestFile(t, connPath, `{"ts":1790409600.25,"uid":"CJ1","id.orig_h":"192.168.8.42","id.orig_p":50000,"id.resp_h":"198.51.100.10","id.resp_p":443,"proto":"tcp","service":"ssl","duration":1.5,"orig_bytes":120,"resp_bytes":500,"conn_state":"SF","local_orig":true,"orig_pkts":2,"resp_pkts":3,"tunnel_parents":[]}`+"\n")
	writeTestFile(t, dnsPath, `{"ts":"2026-09-26T12:00:01.000000Z","uid":"DJ1","id.orig_h":"192.168.8.42","id.orig_p":53000,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"api.camera.example","qtype_name":"A","answers":["198.51.100.10"],"TTLs":[60.0]}`+"\n")
	writeTestFile(t, httpPath, `{"ts":1790409602.0,"uid":"HJ1","id.orig_h":"192.168.8.42","id.orig_p":50001,"id.resp_h":"198.51.100.11","id.resp_p":80,"method":"GET","host":"camera-cloud.example","uri":"/ping","status_code":200}`+"\n")
	writeTestFile(t, sslPath, `{"ts":1790409603.0,"uid":"SJ1","id.orig_h":"192.168.8.42","id.orig_p":50002,"id.resp_h":"198.51.100.12","id.resp_p":443,"version":"TLSv13","server_name":"tls.camera.example","established":true}`+"\n")

	if _, err := runZeekImport(zeekImportConfig{ConnPath: connPath, DNSPath: dnsPath, HTTPPath: httpPath, SSLPath: sslPath, OutDir: outDir}); err != nil {
		t.Fatalf("runZeekImport: %v", err)
	}
	flows := readJSONLLines[analyzer.FlowRecord](t, filepath.Join(outDir, "flows.jsonl"))
	if len(flows) != 3 {
		t.Fatalf("flows=%+v, want conn/http/tls flows", flows)
	}
	conn := flows[0]
	if conn.FlowKey != "CJ1" || conn.SrcIP != "192.168.8.42" || conn.DstPort != 443 || conn.Protocol != "tcp" || conn.BytesOut != 120 || conn.PacketCount != 5 ||
		!conn.Timestamp.Equal(time.Date(2026, 9, 26, 8, 0, 0, 250000000, time.UTC)) {
		t.Fatalf("conn flow=%+v, want fields from Zeek JSON", conn)
	}
	observations := readJSONLLines[analyzer.ObservationRecord](t, filepath.Join(outDir, "observations.jsonl"))
	if !zeekObservationExists(observations, "dns_query", "api.camera.example") ||
		!zeekObservationExists(observations, "http_request", "camera-cloud.example") ||
		!zeekObservationExists(observations, "tls_sni", "tls.camera.example") {
		t.Fatalf("observations=%+v, want DNS/HTTP/TLS observations from JSON logs", observations)
	}
}

func TestAssembleEvidenceRunMergesDeviceInventories(t *testing.T) {
	dir := t.TempDir()
	openwrtDir := filepath.Join(dir, "openwrt")
	otherDir := filepath.Join(dir, "other")
	outDir := filepath.Join(dir, "assembled")
	mustMkdir(t, openwrtDir)
	mustMkdir(t, otherDir)
	writeTestFile(t, filepath.Join(openwrtDir, "device_inventory.json"), `{"generated_at":"2026-09-26T12:30:00Z","devices":[{"ip":"192.168.8.42","mac_address":"aa:bb:cc:dd:ee:ff","hostname":"camera-01","dhcp_lease_state":"active","first_seen":"2026-09-26T12:00:01Z","last_seen":"2026-09-26T12:30:00Z","observed_protocols":["dns"],"observed_ports":[53]}]}`)
	writeTestFile(t, filepath.Join(otherDir, "device_inventory.json"), `{"generated_at":"2026-09-26T12:31:00Z","devices":[{"ip":"192.168.8.42","first_seen":"2026-09-26T11:59:00Z","last_seen":"2026-09-26T12:10:00Z","observed_protocols":["tls"],"observed_ports":[443],"category_candidate":"Camera"},{"ip":"192.168.8.50","observed_ports":[80]}]}`)

	if _, err := assembleEvidenceRun([]evidenceSourceDir{{name: "other", path: otherDir}, {name: "openwrt", path: openwrtDir}}, outDir); err != nil {
		t.Fatalf("assembleEvidenceRun: %v", err)
	}
	inventory, err := reportapi.LoadInventory(filepath.Join(outDir, "device_inventory.json"))
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if len(inventory.Devices) != 2 || inventory.GeneratedAt != "2026-09-26T12:31:00Z" {
		t.Fatalf("inventory=%+v, want two merged devices", inventory)
	}
	camera := inventory.Devices[0]
	if camera.MACAddress != "aa:bb:cc:dd:ee:ff" || camera.Hostname != "camera-01" || camera.CategoryCandidate != "Camera" ||
		camera.FirstSeen != "2026-09-26T11:59:00Z" || camera.LastSeen != "2026-09-26T12:30:00Z" ||
		strings.Join(camera.ObservedProtocols, ",") != "dns,tls" || len(camera.ObservedPorts) != 2 {
		t.Fatalf("camera=%+v, want identity from OpenWrt merged with other source", camera)
	}
}
