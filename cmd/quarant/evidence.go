package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"quarant/analyzer"
	"quarant/analyzer/device"
	"quarant/internal/reportapi"
)

type evidenceSourceDir struct {
	name string
	path string
}

func runEvidence(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("evidence requires subcommand: assemble")
	}
	switch args[0] {
	case "assemble":
		return runEvidenceAssembleCLI(args[1:], out)
	default:
		return fmt.Errorf("unknown evidence subcommand %q; use assemble", args[0])
	}
}

func runEvidenceAssembleCLI(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("evidence assemble", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var openwrtDirs, suricataDirs, zeekDirs, snortDirs, sourceDirs stringListFlag
	outDir := fs.String("out", "runs/assembled", "directory to write assembled Quarant run")
	taxonomyPolicyPath := fs.String("taxonomy-policy", "", "taxonomy policy JSON path, empty for built-in default")
	fs.Var(&openwrtDirs, "openwrt", "OpenWrt run directory; may be repeated")
	fs.Var(&suricataDirs, "suricata", "Suricata run directory; may be repeated")
	fs.Var(&zeekDirs, "zeek", "Zeek run directory; may be repeated")
	fs.Var(&snortDirs, "snort", "Snort run directory; may be repeated")
	fs.Var(&sourceDirs, "source", "generic source as name=path; may be repeated")
	if err := fs.Parse(normalizeFlagArgs(fs, args)); err != nil {
		return fmt.Errorf("parse evidence assemble flags: %w", err)
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("evidence assemble accepts flags only")
	}
	sources := evidenceSourceDirs(openwrtDirs, suricataDirs, zeekDirs, snortDirs, sourceDirs)
	result, err := assembleEvidenceRunWithPolicy(sources, *outDir, *taxonomyPolicyPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Evidence assemble complete: sources=%d events=%d security_events=%d flows=%d observations=%d attack_findings=%d out=%s coverage=%s\n",
		result.Metrics.SourceCount,
		result.Metrics.EventCount,
		result.Metrics.SecurityEventCount,
		result.Metrics.FlowCount,
		result.Metrics.ObservationCount,
		result.Metrics.AttackFindingCount,
		*outDir,
		result.Outputs.SourceCoverageReport,
	)
	return nil
}

func evidenceSourceDirs(openwrtDirs, suricataDirs, zeekDirs, snortDirs, sourceDirs []string) []evidenceSourceDir {
	out := []evidenceSourceDir{}
	add := func(name string, dirs []string) {
		for _, dir := range dirs {
			if strings.TrimSpace(dir) != "" {
				out = append(out, evidenceSourceDir{name: name, path: dir})
			}
		}
	}
	add("openwrt", openwrtDirs)
	add("suricata", suricataDirs)
	add("zeek", zeekDirs)
	add("snort", snortDirs)
	for _, value := range sourceDirs {
		name, path, ok := strings.Cut(value, "=")
		if ok && strings.TrimSpace(path) != "" {
			out = append(out, evidenceSourceDir{name: strings.TrimSpace(name), path: strings.TrimSpace(path)})
		}
	}
	return out
}

func assembleEvidenceRun(sources []evidenceSourceDir, outDir string) (reportapi.EvidenceManifest, error) {
	return assembleEvidenceRunWithPolicy(sources, outDir, "")
}

func assembleEvidenceRunWithPolicy(sources []evidenceSourceDir, outDir, taxonomyPolicyPath string) (reportapi.EvidenceManifest, error) {
	if len(sources) == 0 {
		return reportapi.EvidenceManifest{}, fmt.Errorf("at least one source directory is required")
	}
	if strings.TrimSpace(outDir) == "" {
		return reportapi.EvidenceManifest{}, fmt.Errorf("--out is required")
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	taxonomyPolicy, err := reportapi.LoadSecurityTaxonomyPolicy(taxonomyPolicyPath)
	if err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	events := []analyzer.Event{}
	securityEvents := []reportapi.SecurityEvent{}
	flows := []reportapi.FlowRecord{}
	observations := []reportapi.ObservationRecord{}
	manifest := reportapi.EvidenceManifest{GeneratedAt: time.Now().UTC().Format(time.RFC3339), Version: "evidence-manifest-v1"}
	var rawEventCount, rawSecurityCount, rawFlowCount, rawObservationCount int
	coverageInputs := []reportapi.SourceCoverageInput{}
	inventories := []analyzer.DeviceInventoryReport{}
	for _, source := range sources {
		inventory, ok, err := loadDeviceInventoryReport(filepath.Join(source.path, "device_inventory.json"))
		if err != nil {
			return reportapi.EvidenceManifest{}, err
		}
		if ok {
			inventories = append(inventories, inventory)
		}
		sourceEvents, err := loadAnalyzerEvents(filepath.Join(source.path, "events.jsonl"))
		if err != nil {
			return reportapi.EvidenceManifest{}, err
		}
		sourceSecurity, err := reportapi.LoadSecurityEvents(filepath.Join(source.path, "security_events.jsonl"))
		if err != nil {
			return reportapi.EvidenceManifest{}, err
		}
		sourceFlows, err := reportapi.LoadFlows(filepath.Join(source.path, "flows.jsonl"))
		if err != nil {
			return reportapi.EvidenceManifest{}, err
		}
		sourceObservations, err := reportapi.LoadObservations(filepath.Join(source.path, "observations.jsonl"))
		if err != nil {
			return reportapi.EvidenceManifest{}, err
		}
		rawEventCount += len(sourceEvents)
		rawSecurityCount += len(sourceSecurity)
		rawFlowCount += len(sourceFlows)
		rawObservationCount += len(sourceObservations)
		events = append(events, sourceEvents...)
		securityEvents = append(securityEvents, tagSecurityEventsSource(sourceSecurity, source.name)...)
		flows = append(flows, sourceFlows...)
		observations = append(observations, sourceObservations...)
		coverageInputs = append(coverageInputs, reportapi.SourceCoverageInput{
			Source:       source.name,
			Security:     sourceSecurity,
			Flows:        sourceFlows,
			Observations: sourceObservations,
		})
		manifest.Sources = append(manifest.Sources, reportapi.EvidenceManifestSource{
			Name:         source.name,
			Path:         source.path,
			Events:       len(sourceEvents),
			Security:     len(sourceSecurity),
			Flows:        len(sourceFlows),
			Observations: len(sourceObservations),
		})
	}
	events = dedupeSlice(events, eventAssemblyKey)
	securityEvents = dedupeSlice(securityEvents, securityEventAssemblyKey)
	securityEvents = reportapi.NormalizeSecurityEventsWithPolicy(securityEvents, taxonomyPolicy)
	flows = dedupeSlice(flows, flowAssemblyKey)
	observations = dedupeSlice(observations, observationAssemblyKey)
	eventsPath := filepath.Join(outDir, "events.jsonl")
	securityEventsPath := filepath.Join(outDir, "security_events.jsonl")
	flowsPath := filepath.Join(outDir, "flows.jsonl")
	observationsPath := filepath.Join(outDir, "observations.jsonl")
	attackEvidencePath := filepath.Join(outDir, "attack_evidence_report.json")
	coveragePath := filepath.Join(outDir, "source_coverage_report.json")
	taxonomyCoveragePath := filepath.Join(outDir, "taxonomy_coverage_report.json")
	manifestPath := filepath.Join(outDir, "evidence_manifest.json")
	inventoryPath := filepath.Join(outDir, "device_inventory.json")
	if len(inventories) > 0 {
		generatedAt, devices := mergeDeviceInventories(inventories)
		if err := analyzer.WriteDeviceInventoryJSON(inventoryPath, generatedAt, devices); err != nil {
			return reportapi.EvidenceManifest{}, err
		}
	}
	if err := writeJSONL(eventsPath, events); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	if err := writeJSONL(securityEventsPath, securityEvents); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	if err := writeJSONL(flowsPath, flows); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	if err := writeJSONL(observationsPath, observations); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	attackEvidence := reportapi.BuildAttackEvidenceReportWithPolicy(securityEvents, taxonomyPolicy)
	attackEvidence.Source.SecurityEvents = securityEventsPath
	if err := writePrettyJSON(attackEvidencePath, attackEvidence); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	coverage := reportapi.BuildSourceCoverageReportFromInputs(coverageInputs)
	if err := writePrettyJSON(coveragePath, coverage); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	taxonomyCoverage := reportapi.BuildTaxonomyCoverageReport(securityEvents, taxonomyPolicy)
	taxonomyCoverage.Source.SecurityEvents = securityEventsPath
	taxonomyCoverage.Source.Policy = taxonomyPolicyPath
	if err := writePrettyJSON(taxonomyCoveragePath, taxonomyCoverage); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	manifest.Outputs = reportapi.EvidenceManifestOutputs{
		Events:                 eventsPath,
		SecurityEvents:         securityEventsPath,
		Flows:                  flowsPath,
		Observations:           observationsPath,
		AttackEvidenceReport:   attackEvidencePath,
		SourceCoverageReport:   coveragePath,
		TaxonomyCoverageReport: taxonomyCoveragePath,
	}
	manifest.Metrics = reportapi.EvidenceManifestMetrics{
		SourceCount:             len(sources),
		EventCount:              len(events),
		SecurityEventCount:      len(securityEvents),
		FlowCount:               len(flows),
		ObservationCount:        len(observations),
		AttackFindingCount:      len(attackEvidence.Findings),
		DedupedEventCount:       rawEventCount - len(events),
		DedupedSecurityCount:    rawSecurityCount - len(securityEvents),
		DedupedFlowCount:        rawFlowCount - len(flows),
		DedupedObservationCount: rawObservationCount - len(observations),
	}
	if err := writePrettyJSON(manifestPath, manifest); err != nil {
		return reportapi.EvidenceManifest{}, err
	}
	return manifest, nil
}

func loadAnalyzerEvents(path string) ([]analyzer.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	out := []analyzer.Event{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var event analyzer.Event
		if err := json.Unmarshal([]byte(line), &event); err == nil {
			out = append(out, event)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return out, nil
}

// loadDeviceInventoryReport reads a sensor's device_inventory.json; ok is false when the file is absent.
func loadDeviceInventoryReport(path string) (analyzer.DeviceInventoryReport, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return analyzer.DeviceInventoryReport{}, false, nil
		}
		return analyzer.DeviceInventoryReport{}, false, fmt.Errorf("read %s: %w", path, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return analyzer.DeviceInventoryReport{}, false, nil
	}
	// Malformed inventories are skipped, matching reportapi.LoadInventory.
	var report analyzer.DeviceInventoryReport
	if err := json.Unmarshal(data, &report); err != nil {
		return analyzer.DeviceInventoryReport{}, false, nil
	}
	return report, true, nil
}

// mergeDeviceInventories merges sensor inventories by IP so DHCP identity (MAC,
// hostname) survives assembly. Entries carrying MAC/hostname win identity fields,
// other fields are filled when empty, seen times widen and observed sets are unioned.
// The returned time is the latest input generated_at, keeping replays deterministic.
func mergeDeviceInventories(reports []analyzer.DeviceInventoryReport) (time.Time, []device.InventorySnapshot) {
	var generatedAt time.Time
	byIP := map[string]*device.InventorySnapshot{}
	for _, report := range reports {
		if t, err := time.Parse(time.RFC3339, report.GeneratedAt); err == nil && t.After(generatedAt) {
			generatedAt = t
		}
		for _, item := range report.Devices {
			ip := strings.TrimSpace(item.IP)
			if ip == "" {
				continue
			}
			current := byIP[ip]
			if current == nil {
				copied := item
				copied.IP = ip
				byIP[ip] = &copied
				continue
			}
			mergeInventorySnapshot(current, item)
		}
	}
	out := make([]device.InventorySnapshot, 0, len(byIP))
	for _, item := range byIP {
		out = append(out, *item)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].IP < out[b].IP })
	return generatedAt, out
}

func mergeInventorySnapshot(dst *device.InventorySnapshot, src device.InventorySnapshot) {
	srcHasIdentity := src.MACAddress != "" || src.Hostname != ""
	dstHasIdentity := dst.MACAddress != "" || dst.Hostname != ""
	if srcHasIdentity && !dstHasIdentity {
		merged := src
		merged.IP = dst.IP
		mergeInventorySnapshot(&merged, *dst)
		*dst = merged
		return
	}
	fill := func(target *string, value string) {
		if strings.TrimSpace(*target) == "" {
			*target = value
		}
	}
	fill(&dst.MACAddress, src.MACAddress)
	fill(&dst.Hostname, src.Hostname)
	fill(&dst.DHCPLeaseExpiresAt, src.DHCPLeaseExpiresAt)
	fill(&dst.DHCPLeaseState, src.DHCPLeaseState)
	fill(&dst.CategoryCandidate, src.CategoryCandidate)
	fill(&dst.CategoryConfidence, src.CategoryConfidence)
	fill(&dst.VendorCandidate, src.VendorCandidate)
	fill(&dst.VendorConfidence, src.VendorConfidence)
	fill(&dst.FamilyCandidate, src.FamilyCandidate)
	fill(&dst.FamilyConfidence, src.FamilyConfidence)
	dst.FirstSeen = inventoryTimeBound(dst.FirstSeen, src.FirstSeen, true)
	dst.LastSeen = inventoryTimeBound(dst.LastSeen, src.LastSeen, false)
	dst.ObservedProtocols = unionSortedStrings(dst.ObservedProtocols, src.ObservedProtocols)
	dst.ObservedHosts = unionSortedStrings(dst.ObservedHosts, src.ObservedHosts)
	dst.ObservedSNI = unionSortedStrings(dst.ObservedSNI, src.ObservedSNI)
	ports := map[uint16]bool{}
	for _, port := range append(append([]uint16{}, dst.ObservedPorts...), src.ObservedPorts...) {
		ports[port] = true
	}
	dst.ObservedPorts = sortedOpenWrtPortSet(ports)
}

func inventoryTimeBound(current, candidate string, earliest bool) string {
	if strings.TrimSpace(candidate) == "" {
		return current
	}
	if strings.TrimSpace(current) == "" {
		return candidate
	}
	a, errA := time.Parse(time.RFC3339, current)
	b, errB := time.Parse(time.RFC3339, candidate)
	if errA != nil || errB != nil {
		return current
	}
	if (earliest && b.Before(a)) || (!earliest && b.After(a)) {
		return candidate
	}
	return current
}

func unionSortedStrings(a, b []string) []string {
	set := map[string]bool{}
	for _, value := range append(append([]string{}, a...), b...) {
		set[value] = true
	}
	out := sortedOpenWrtStringSet(set)
	if len(out) == 0 {
		return nil
	}
	return out
}

func tagSecurityEventsSource(events []reportapi.SecurityEvent, source string) []reportapi.SecurityEvent {
	for i := range events {
		if events[i].Evidence == nil {
			events[i].Evidence = map[string]string{}
		}
		events[i].Evidence["assembled_source"] = source
	}
	return events
}

func dedupeSlice[T any](items []T, keyFn func(T) string) []T {
	seen := map[string]bool{}
	out := make([]T, 0, len(items))
	for _, item := range items {
		key := keyFn(item)
		if key == "" {
			key = assemblyHash(item)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, item)
	}
	return out
}

func eventAssemblyKey(event analyzer.Event) string {
	return strings.Join([]string{event.Timestamp.UTC().Format(time.RFC3339Nano), event.RuleID, event.Type, event.SrcIP, event.DstIP, fmt.Sprintf("%d", event.DstPort)}, "|")
}

func securityEventAssemblyKey(event reportapi.SecurityEvent) string {
	return strings.Join([]string{event.EventID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Source, event.SID, event.Signature, event.SrcIP, event.DstIP, fmt.Sprintf("%d", event.DstPort)}, "|")
}

func flowAssemblyKey(flow reportapi.FlowRecord) string {
	return strings.Join([]string{flow.FlowKey, flow.Timestamp.UTC().Format(time.RFC3339Nano), flow.SrcIP, flow.DstIP, fmt.Sprintf("%d", flow.DstPort), flow.AppProtocol}, "|")
}

func observationAssemblyKey(observation reportapi.ObservationRecord) string {
	return strings.Join([]string{observation.Timestamp.UTC().Format(time.RFC3339Nano), observation.Kind, observation.FlowKey, observation.SrcIP, observation.DstIP, fmt.Sprintf("%d", observation.DstPort), observation.ObservedDestination}, "|")
}

func assemblyHash(value any) string {
	data, _ := json.Marshal(value)
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}
