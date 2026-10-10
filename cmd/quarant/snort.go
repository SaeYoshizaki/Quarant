package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"quarant/internal/reportapi"
)

type snortImportConfig struct {
	AlertsPath            string
	OutDir                string
	SecurityEventsOutPath string
	AttackEvidenceOutPath string
}

type snortImportResult struct {
	SecurityEventCount int
	AttackFindingCount int
}

type snortAlertJSON struct {
	Timestamp   string `json:"timestamp"`
	Ts          string `json:"ts"`
	SID         any    `json:"sid"`
	Signature   string `json:"signature"`
	Msg         string `json:"msg"`
	ClassType   string `json:"classtype"`
	Category    string `json:"category"`
	Priority    int    `json:"priority"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	DestIP      string `json:"dest_ip"`
	DestPort    uint16 `json:"dest_port"`
	Protocol    string `json:"proto"`
	Action      string `json:"action"`
	AlertAction string `json:"alert_action"`
}

var snortFastAlertPattern = regexp.MustCompile(`^(\S+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+(?:\[Classification:\s*([^\]]+)\]\s+)?(?:\[Priority:\s*(\d+)\]\s+)?\{(\w+)\}\s+([^:\s]+):?(\d+)?\s+->\s+([^:\s]+):?(\d+)?`)

func runSnort(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("snort requires subcommand: import")
	}
	switch args[0] {
	case "import":
		return runSnortImportCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown snort subcommand %q; use import", args[0])
	}
}

func runSnortImportCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("snort import", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := snortImportConfig{}
	fs.StringVar(&cfg.AlertsPath, "alerts", "", "Snort alert JSONL or fast alert log path")
	fs.StringVar(&cfg.OutDir, "out-dir", "snort-run", "directory to write Quarant JSON outputs")
	fs.StringVar(&cfg.SecurityEventsOutPath, "security-events-out", "", "security events JSONL output path (default: out-dir/security_events.jsonl)")
	fs.StringVar(&cfg.AttackEvidenceOutPath, "attack-evidence-out", "", "attack evidence report JSON output path (default: out-dir/attack_evidence_report.json)")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse snort import flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("snort import accepts flags only")
	}
	result, err := runSnortImport(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Snort import complete: security_events=%d attack_findings=%d out=%s\n", result.SecurityEventCount, result.AttackFindingCount, cfg.OutDir)
	return nil
}

func runSnortImport(cfg snortImportConfig) (snortImportResult, error) {
	if strings.TrimSpace(cfg.AlertsPath) == "" {
		return snortImportResult{}, fmt.Errorf("--alerts is required")
	}
	if strings.TrimSpace(cfg.OutDir) == "" {
		return snortImportResult{}, fmt.Errorf("--out-dir is required")
	}
	if err := os.MkdirAll(cfg.OutDir, 0755); err != nil {
		return snortImportResult{}, err
	}
	events, err := readSnortAlerts(cfg.AlertsPath)
	if err != nil {
		return snortImportResult{}, err
	}
	securityEventsPath := defaultSibling(cfg.SecurityEventsOutPath, cfg.OutDir, "security_events.jsonl")
	attackEvidencePath := defaultSibling(cfg.AttackEvidenceOutPath, cfg.OutDir, "attack_evidence_report.json")
	if err := writeJSONL(securityEventsPath, events); err != nil {
		return snortImportResult{}, err
	}
	attackEvidence := reportapi.BuildAttackEvidenceReport(events)
	attackEvidence.Source.SecurityEvents = securityEventsPath
	if err := writePrettyJSON(attackEvidencePath, attackEvidence); err != nil {
		return snortImportResult{}, err
	}
	return snortImportResult{SecurityEventCount: len(events), AttackFindingCount: len(attackEvidence.Findings)}, nil
}

func readSnortAlerts(path string) ([]reportapi.SecurityEvent, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	events := []reportapi.SecurityEvent{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if event, ok := parseSnortAlertJSON(line); ok {
			events = append(events, event)
			continue
		}
		if event, ok := parseSnortFastAlert(line); ok {
			events = append(events, event)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return events, nil
}

func parseSnortAlertJSON(line string) (reportapi.SecurityEvent, bool) {
	var alert snortAlertJSON
	if err := json.Unmarshal([]byte(line), &alert); err != nil {
		return reportapi.SecurityEvent{}, false
	}
	dstIP := firstNonEmptyString(alert.DstIP, alert.DestIP)
	dstPort := alert.DstPort
	if dstPort == 0 {
		dstPort = alert.DestPort
	}
	signature := firstNonEmptyString(alert.Signature, alert.Msg)
	if alert.SrcIP == "" || dstIP == "" || signature == "" {
		return reportapi.SecurityEvent{}, false
	}
	return snortSecurityEvent(
		parseSensorTimestamp(firstNonEmptyString(alert.Timestamp, alert.Ts)),
		scalarString(alert.SID),
		signature,
		firstNonEmptyString(alert.ClassType, alert.Category),
		alert.Priority,
		firstNonEmptyString(alert.Action, alert.AlertAction, "alert"),
		alert.SrcIP,
		alert.SrcPort,
		dstIP,
		dstPort,
		alert.Protocol,
	), true
}

func parseSnortFastAlert(line string) (reportapi.SecurityEvent, bool) {
	matches := snortFastAlertPattern.FindStringSubmatch(line)
	if len(matches) == 0 {
		return reportapi.SecurityEvent{}, false
	}
	priority, _ := strconv.Atoi(matches[7])
	srcPort := uint16FromString(matches[10])
	dstPort := uint16FromString(matches[12])
	return snortSecurityEvent(
		parseSnortFastTimestamp(matches[1]),
		matches[3],
		matches[5],
		matches[6],
		priority,
		"alert",
		matches[9],
		srcPort,
		matches[11],
		dstPort,
		matches[8],
	), true
}

func snortSecurityEvent(ts time.Time, sid, signature, classtype string, priority int, action, srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string) reportapi.SecurityEvent {
	direction := securityDirection(srcIP, dstIP)
	deviceIP := privateEndpoint(srcIP, dstIP)
	event := reportapi.SecurityEvent{
		Timestamp:       ts,
		Source:          "snort",
		SourceFormat:    "snort_alert",
		Sensor:          "snort",
		EventType:       "ids_alert",
		AttackCategory:  firstNonEmptyString(classtype, "ids_alert"),
		AttackTechnique: suricataAttackTechnique(classtype, signature),
		Severity:        idsSeverity(priority),
		Confidence:      "medium",
		SID:             sid,
		Signature:       signature,
		ClassType:       classtype,
		Priority:        priority,
		Engine:          "snort",
		RuleSource:      "snort_alert",
		AlertAction:     action,
		Action:          strings.ToUpper(action),
		Verdict:         "observed",
		Direction:       direction,
		SrcIP:           srcIP,
		SrcPort:         srcPort,
		DstIP:           dstIP,
		DstPort:         dstPort,
		Protocol:        strings.ToLower(strings.TrimSpace(protocol)),
		DeviceIP:        deviceIP,
		AssetRole:       assetRole(deviceIP),
		Evidence: map[string]string{
			"parser":       "snort_alert_v1",
			"sid":          sid,
			"signature":    signature,
			"classtype":    classtype,
			"priority":     strconv.Itoa(priority),
			"alert_action": action,
		},
	}
	event.AggregationKey = strings.Join([]string{event.SrcIP, firstNonEmptyString(event.DeviceIP, event.DstIP), event.Protocol}, "|")
	return event
}

func parseSnortFastTimestamp(value string) time.Time {
	now := time.Now().UTC()
	for _, layout := range []string{"01/02-15:04:05.999999", "01/02-15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		}
	}
	return parseSensorTimestamp(value)
}
