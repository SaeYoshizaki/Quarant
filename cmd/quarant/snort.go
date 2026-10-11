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
	TaxonomyPolicyPath    string
	MetadataReportOutPath string
	RulesPaths            []string
}

type snortImportResult struct {
	SecurityEventCount      int
	AttackFindingCount      int
	MetadataEnrichmentCount int
	RuleMetadataCount       int
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
	SrcAddr     string `json:"src_addr"`
	DstAddr     string `json:"dst_addr"`
	SrcAP       string `json:"src_ap"`
	DstAP       string `json:"dst_ap"`
	Protocol    string `json:"proto"`
	IPProto     string `json:"ip_proto"`
	Action      string `json:"action"`
	AlertAction string `json:"alert_action"`
}

type snortRuleMetadata struct {
	SID        string
	Msg        string
	ClassType  string
	Priority   int
	Metadata   string
	References []string
	Revision   string
	Raw        string
}

type snortMetadataReport struct {
	GeneratedAt string                    `json:"generated_at"`
	Version     string                    `json:"version"`
	Source      snortMetadataReportSource `json:"source"`
	Metrics     snortMetadataMetrics      `json:"metrics"`
	Limitations []string                  `json:"limitations,omitempty"`
}

type snortMetadataReportSource struct {
	Alerts string   `json:"alerts,omitempty"`
	Rules  []string `json:"rules,omitempty"`
}

type snortMetadataMetrics struct {
	SecurityEventCount      int     `json:"security_event_count"`
	RuleMetadataCount       int     `json:"rule_metadata_count"`
	SIDMissingCount         int     `json:"sid_missing_count"`
	SignatureMissingCount   int     `json:"signature_missing_count"`
	ClassTypeMissingCount   int     `json:"classtype_missing_count"`
	PriorityMissingCount    int     `json:"priority_missing_count"`
	MetadataEnrichedCount   int     `json:"metadata_enriched_count"`
	MetadataEnrichmentRate  float64 `json:"metadata_enrichment_rate,omitempty"`
	GenericIDSFallbackCount int     `json:"generic_ids_fallback_count"`
}

var snortFastAlertPattern = regexp.MustCompile(`^(\S+)\s+\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]\s+(.+?)\s+\[\*\*\]\s+(?:\[Classification:\s*([^\]]+)\]\s+)?(?:\[Priority:\s*(\d+)\]\s+)?\{(\w+)\}\s+(.+?)\s+->\s+(.+)$`)

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
	var rulesPaths stringListFlag
	fs.StringVar(&cfg.AlertsPath, "alerts", "", "Snort alert JSONL or fast alert log path")
	fs.StringVar(&cfg.OutDir, "out-dir", "snort-run", "directory to write Quarant JSON outputs")
	fs.StringVar(&cfg.SecurityEventsOutPath, "security-events-out", "", "security events JSONL output path (default: out-dir/security_events.jsonl)")
	fs.StringVar(&cfg.AttackEvidenceOutPath, "attack-evidence-out", "", "attack evidence report JSON output path (default: out-dir/attack_evidence_report.json)")
	fs.StringVar(&cfg.MetadataReportOutPath, "metadata-report-out", "", "Snort metadata quality report JSON output path (default: out-dir/snort_metadata_report.json)")
	fs.StringVar(&cfg.TaxonomyPolicyPath, "taxonomy-policy", "", "taxonomy policy JSON path, empty for built-in default")
	fs.Var(&rulesPaths, "rules", "Snort .rules file for sid/msg/classtype/priority metadata enrichment; may be repeated")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse snort import flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("snort import accepts flags only")
	}
	cfg.RulesPaths = rulesPaths
	result, err := runSnortImport(cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Snort import complete: security_events=%d attack_findings=%d enriched=%d rules=%d out=%s\n", result.SecurityEventCount, result.AttackFindingCount, result.MetadataEnrichmentCount, result.RuleMetadataCount, cfg.OutDir)
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
	rules, err := readSnortRuleMetadataFiles(cfg.RulesPaths)
	if err != nil {
		return snortImportResult{}, err
	}
	events, enriched := enrichSnortEvents(events, rules)
	taxonomyPolicy, err := reportapi.LoadSecurityTaxonomyPolicy(cfg.TaxonomyPolicyPath)
	if err != nil {
		return snortImportResult{}, err
	}
	events = reportapi.NormalizeSecurityEventsWithPolicy(events, taxonomyPolicy)
	securityEventsPath := defaultSibling(cfg.SecurityEventsOutPath, cfg.OutDir, "security_events.jsonl")
	attackEvidencePath := defaultSibling(cfg.AttackEvidenceOutPath, cfg.OutDir, "attack_evidence_report.json")
	metadataReportPath := defaultSibling(cfg.MetadataReportOutPath, cfg.OutDir, "snort_metadata_report.json")
	if err := writeJSONL(securityEventsPath, events); err != nil {
		return snortImportResult{}, err
	}
	attackEvidence := reportapi.BuildAttackEvidenceReportWithPolicy(events, taxonomyPolicy)
	attackEvidence.Source.SecurityEvents = securityEventsPath
	if err := writePrettyJSON(attackEvidencePath, attackEvidence); err != nil {
		return snortImportResult{}, err
	}
	metadataReport := buildSnortMetadataReport(cfg.AlertsPath, cfg.RulesPaths, events, rules, enriched)
	if err := writePrettyJSON(metadataReportPath, metadataReport); err != nil {
		return snortImportResult{}, err
	}
	return snortImportResult{SecurityEventCount: len(events), AttackFindingCount: len(attackEvidence.Findings), MetadataEnrichmentCount: enriched, RuleMetadataCount: len(rules)}, nil
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
	var raw map[string]any
	_ = json.Unmarshal([]byte(line), &raw)
	srcIP := firstNonEmptyString(alert.SrcIP, alert.SrcAddr, snortMapString(raw, "src_ip", "src_addr", "source_ip", "source.address"))
	dstIP := firstNonEmptyString(alert.DstIP, alert.DestIP, alert.DstAddr, snortMapString(raw, "dst_ip", "dest_ip", "dst_addr", "destination_ip", "destination.address"))
	srcPort := firstNonZeroUint16(alert.SrcPort, snortMapUint16(raw, "src_port", "source_port", "source.port"))
	dstPort := alert.DstPort
	if dstPort == 0 {
		dstPort = alert.DestPort
	}
	dstPort = firstNonZeroUint16(dstPort, snortMapUint16(raw, "dst_port", "dest_port", "destination_port", "destination.port"))
	if apIP, apPort := splitSnortEndpoint(alert.SrcAP); srcIP == "" && apIP != "" {
		srcIP = apIP
		if srcPort == 0 {
			srcPort = apPort
		}
	} else if apPort != 0 && srcPort == 0 {
		srcPort = apPort
	}
	if apIP, apPort := splitSnortEndpoint(alert.DstAP); dstIP == "" && apIP != "" {
		dstIP = apIP
		if dstPort == 0 {
			dstPort = apPort
		}
	} else if apPort != 0 && dstPort == 0 {
		dstPort = apPort
	}
	signature := firstNonEmptyString(alert.Signature, alert.Msg, snortMapString(raw, "signature", "msg", "message", "alert.signature"))
	sid := firstNonEmptyString(scalarString(alert.SID), snortMapString(raw, "sid", "signature_id", "alert.signature_id", "rule.sid"))
	classtype := firstNonEmptyString(alert.ClassType, alert.Category, snortMapString(raw, "classtype", "class_type", "category", "alert.category", "rule.classtype"))
	priority := firstNonZeroInt(alert.Priority, snortMapInt(raw, "priority", "alert.severity", "rule.priority"))
	protocol := firstNonEmptyString(alert.Protocol, alert.IPProto, snortMapString(raw, "proto", "protocol", "ip_proto"))
	action := firstNonEmptyString(alert.Action, alert.AlertAction, snortMapString(raw, "action", "alert_action"), "alert")
	if srcIP == "" || dstIP == "" || (signature == "" && sid == "") {
		return reportapi.SecurityEvent{}, false
	}
	return snortSecurityEvent(
		parseSensorTimestamp(firstNonEmptyString(alert.Timestamp, alert.Ts)),
		sid,
		signature,
		classtype,
		priority,
		action,
		srcIP,
		srcPort,
		dstIP,
		dstPort,
		protocol,
	), true
}

func parseSnortFastAlert(line string) (reportapi.SecurityEvent, bool) {
	matches := snortFastAlertPattern.FindStringSubmatch(line)
	if len(matches) == 0 {
		return reportapi.SecurityEvent{}, false
	}
	priority, _ := strconv.Atoi(matches[7])
	srcIP, srcPort := splitSnortEndpoint(matches[9])
	dstIP, dstPort := splitSnortEndpoint(matches[10])
	return snortSecurityEvent(
		parseSnortFastTimestamp(matches[1]),
		matches[3],
		matches[5],
		matches[6],
		priority,
		"alert",
		srcIP,
		srcPort,
		dstIP,
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

func readSnortRuleMetadataFiles(paths []string) (map[string]snortRuleMetadata, error) {
	out := map[string]snortRuleMetadata{}
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		items, err := readSnortRuleMetadataFile(path)
		if err != nil {
			return nil, err
		}
		for sid, item := range items {
			out[sid] = item
		}
	}
	return out, nil
}

func readSnortRuleMetadataFile(path string) (map[string]snortRuleMetadata, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rules %s: %w", path, err)
	}
	defer file.Close()
	out := map[string]snortRuleMetadata{}
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "(") || !strings.Contains(line, ")") {
			continue
		}
		if item, ok := parseSnortRuleMetadata(line); ok {
			out[item.SID] = item
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan rules %s: %w", path, err)
	}
	return out, nil
}

func parseSnortRuleMetadata(line string) (snortRuleMetadata, bool) {
	start := strings.Index(line, "(")
	end := strings.LastIndex(line, ")")
	if start < 0 || end <= start {
		return snortRuleMetadata{}, false
	}
	options := parseSnortRuleOptions(line[start+1 : end])
	item := snortRuleMetadata{
		SID:       options.get("sid"),
		Msg:       options.get("msg"),
		ClassType: options.get("classtype"),
		Metadata:  options.get("metadata"),
		Revision:  options.get("rev"),
		Raw:       line,
	}
	item.Priority, _ = strconv.Atoi(options.get("priority"))
	for _, ref := range options["reference"] {
		item.References = append(item.References, ref)
	}
	if item.SID == "" {
		return snortRuleMetadata{}, false
	}
	return item, true
}

type snortRuleOptions map[string][]string

func (o snortRuleOptions) get(key string) string {
	values := o[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func parseSnortRuleOptions(value string) snortRuleOptions {
	out := snortRuleOptions{}
	for _, part := range splitSnortRuleOptions(value) {
		key, val, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"`)
		if key != "" {
			out[key] = append(out[key], val)
		}
	}
	return out
}

func splitSnortRuleOptions(value string) []string {
	out := []string{}
	var b strings.Builder
	inQuote := false
	escaped := false
	for _, r := range value {
		switch {
		case escaped:
			b.WriteRune(r)
			escaped = false
		case r == '\\':
			b.WriteRune(r)
			escaped = true
		case r == '"':
			b.WriteRune(r)
			inQuote = !inQuote
		case r == ';' && !inQuote:
			if part := strings.TrimSpace(b.String()); part != "" {
				out = append(out, part)
			}
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if part := strings.TrimSpace(b.String()); part != "" {
		out = append(out, part)
	}
	return out
}

func enrichSnortEvents(events []reportapi.SecurityEvent, rules map[string]snortRuleMetadata) ([]reportapi.SecurityEvent, int) {
	enriched := 0
	for i := range events {
		rule := rules[strings.TrimSpace(events[i].SID)]
		if rule.SID == "" {
			continue
		}
		changed := false
		if events[i].Evidence == nil {
			events[i].Evidence = map[string]string{}
		}
		if events[i].Signature == "" && rule.Msg != "" {
			events[i].Signature = rule.Msg
			events[i].Evidence["signature"] = rule.Msg
			changed = true
		}
		if events[i].ClassType == "" && rule.ClassType != "" {
			events[i].ClassType = rule.ClassType
			events[i].AttackCategory = rule.ClassType
			events[i].Evidence["classtype"] = rule.ClassType
			changed = true
		}
		if events[i].Priority == 0 && rule.Priority != 0 {
			events[i].Priority = rule.Priority
			events[i].Severity = idsSeverity(rule.Priority)
			events[i].Evidence["priority"] = strconv.Itoa(rule.Priority)
			changed = true
		}
		if rule.Msg != "" {
			events[i].Evidence["rule_msg"] = rule.Msg
		}
		if rule.Metadata != "" {
			events[i].Evidence["rule_metadata"] = rule.Metadata
			changed = true
		}
		if len(rule.References) > 0 {
			events[i].Evidence["rule_references"] = strings.Join(rule.References, ";")
			changed = true
		}
		if rule.Revision != "" {
			events[i].Evidence["rule_rev"] = rule.Revision
		}
		events[i].Evidence["rule_metadata_source"] = "snort_rules"
		events[i].RuleSource = "snort_alert+rules"
		if changed {
			enriched++
		}
	}
	return events, enriched
}

func buildSnortMetadataReport(alertsPath string, rulesPaths []string, events []reportapi.SecurityEvent, rules map[string]snortRuleMetadata, enriched int) snortMetadataReport {
	report := snortMetadataReport{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     "snort-metadata-v1",
		Source:      snortMetadataReportSource{Alerts: alertsPath, Rules: rulesPaths},
		Limitations: []string{
			"Snort alert logs may omit rule metadata; enrichment depends on matching sid values in the provided .rules files.",
			"Rule metadata improves classification explainability but does not prove exploitability or compromise.",
		},
	}
	report.Metrics.SecurityEventCount = len(events)
	report.Metrics.RuleMetadataCount = len(rules)
	report.Metrics.MetadataEnrichedCount = enriched
	for _, event := range events {
		if strings.TrimSpace(event.SID) == "" {
			report.Metrics.SIDMissingCount++
		}
		if strings.TrimSpace(event.Signature) == "" {
			report.Metrics.SignatureMissingCount++
		}
		if strings.TrimSpace(event.ClassType) == "" {
			report.Metrics.ClassTypeMissingCount++
		}
		if event.Priority == 0 {
			report.Metrics.PriorityMissingCount++
		}
		if strings.EqualFold(event.AttackTechnique, "ids_alert") || snortOnlyGenericTaxonomy(event.Taxonomy) {
			report.Metrics.GenericIDSFallbackCount++
		}
	}
	if len(events) > 0 {
		report.Metrics.MetadataEnrichmentRate = float64(enriched) / float64(len(events))
	}
	return report
}

func snortOnlyGenericTaxonomy(values []string) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "attack_like", "ids_alert":
		default:
			return false
		}
	}
	return true
}

func parseSnortFastTimestamp(value string) time.Time {
	now := time.Now().UTC()
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02-15:04:05.999999", "2006-01-02-15:04:05", "01/02-15:04:05.999999", "01/02-15:04:05"} {
		if t, err := time.Parse(layout, strings.TrimSpace(value)); err == nil {
			if t.Year() > 0 {
				return t.UTC()
			}
			return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		}
	}
	return parseSensorTimestamp(value)
}

func splitSnortEndpoint(value string) (string, uint16) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", 0
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.LastIndex(value, "]"); end > 0 {
			ip := strings.Trim(value[1:end], "[]")
			port := uint16(0)
			if len(value) > end+1 && value[end+1] == ':' {
				port = uint16FromString(value[end+2:])
			}
			return ip, port
		}
	}
	idx := strings.LastIndex(value, ":")
	if idx > 0 && idx < len(value)-1 && strings.Count(value, ":") == 1 {
		return strings.TrimSpace(value[:idx]), uint16FromString(value[idx+1:])
	}
	return value, 0
}

func snortMapString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		value, ok := snortMapValue(raw, key)
		if !ok {
			continue
		}
		if out := scalarString(value); out != "" {
			return out
		}
	}
	return ""
}

func snortMapUint16(raw map[string]any, keys ...string) uint16 {
	for _, key := range keys {
		value, ok := snortMapValue(raw, key)
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return uint16(v)
		case int:
			return uint16(v)
		case string:
			return uint16FromString(v)
		}
	}
	return 0
}

func snortMapInt(raw map[string]any, keys ...string) int {
	for _, key := range keys {
		value, ok := snortMapValue(raw, key)
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

func snortMapValue(raw map[string]any, key string) (any, bool) {
	if raw == nil || key == "" {
		return nil, false
	}
	parts := strings.Split(key, ".")
	var current any = raw
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func firstNonZeroUint16(values ...uint16) uint16 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonZeroInt(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
