package reportapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

type ObservationRecord struct {
	Timestamp           time.Time `json:"ts"`
	Kind                string    `json:"kind"`
	FlowKey             string    `json:"flow_key,omitempty"`
	SrcIP               string    `json:"src_ip,omitempty"`
	SrcPort             uint16    `json:"src_port,omitempty"`
	DstIP               string    `json:"dst_ip,omitempty"`
	DstPort             uint16    `json:"dst_port,omitempty"`
	Protocol            string    `json:"protocol,omitempty"`
	AppProtocol         string    `json:"app_protocol,omitempty"`
	Direction           string    `json:"direction,omitempty"`
	DeviceCategory      string    `json:"device_category,omitempty"`
	ObservedDestination string    `json:"observed_destination,omitempty"`
	Host                string    `json:"host,omitempty"`
	SNI                 string    `json:"sni,omitempty"`
	HTTPMethod          string    `json:"http_method,omitempty"`
	HTTPPath            string    `json:"http_path,omitempty"`
	DNSQuery            string    `json:"dns_query,omitempty"`
	FirstSeen           bool      `json:"first_seen,omitempty"`
	Noise               bool      `json:"noise,omitempty"`
	BytesOut            int64     `json:"bytes_out,omitempty"`
	BytesIn             int64     `json:"bytes_in,omitempty"`
	PacketCount         int       `json:"packet_count,omitempty"`
}

type ObservationSOC struct {
	Source      string                  `json:"source"`
	Window      Window                  `json:"window"`
	Metrics     ObservationMetrics      `json:"metrics"`
	AttackLike  AttackLikeActivity      `json:"attack_like"`
	Timeline    []ObservationTimeBucket `json:"timeline"`
	TopLists    ObservationTopLists     `json:"top_lists"`
	Limitations []string                `json:"limitations"`
}

type ObservationMetrics struct {
	TotalObservations     int `json:"total_observations"`
	ExternalCount         int `json:"external_count"`
	LocalCount            int `json:"local_count"`
	DNSCount              int `json:"dns_count"`
	HTTPCount             int `json:"http_count"`
	TLSCount              int `json:"tls_count"`
	NoiseCount            int `json:"noise_count"`
	UniqueSources         int `json:"unique_sources"`
	UniqueDestinations    int `json:"unique_destinations"`
	UniqueDNSQueries      int `json:"unique_dns_queries"`
	UniqueSNI             int `json:"unique_sni"`
	UniqueHTTPHosts       int `json:"unique_http_hosts"`
	AttackLikeCount       int `json:"attack_like_count"`
	AttackLikeSourceCount int `json:"attack_like_source_count"`
}

type AttackLikeActivity struct {
	Score       int                       `json:"score"`
	Level       string                    `json:"level"`
	TotalCount  int                       `json:"total_count"`
	ByReason    []AttackLikeReason        `json:"by_reason"`
	TopSources  []ObservationTopListEntry `json:"top_sources"`
	RecentItems []AttackLikeObservation   `json:"recent_items"`
}

type AttackLikeReason struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

type AttackLikeObservation struct {
	Timestamp   string   `json:"ts"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Port        uint16   `json:"port,omitempty"`
	Protocol    string   `json:"protocol,omitempty"`
	Kind        string   `json:"kind"`
	Reasons     []string `json:"reasons"`
}

type ObservationTimeBucket struct {
	Hour            string `json:"hour"`
	TotalCount      int    `json:"total_count"`
	ExternalCount   int    `json:"external_count"`
	DNSCount        int    `json:"dns_count"`
	HTTPCount       int    `json:"http_count"`
	TLSCount        int    `json:"tls_count"`
	NoiseCount      int    `json:"noise_count"`
	AttackLikeCount int    `json:"attack_like_count"`
}

type ObservationTopLists struct {
	Destinations  []ObservationTopListEntry `json:"destinations"`
	DNSQueries    []ObservationTopListEntry `json:"dns_queries"`
	SNI           []ObservationTopListEntry `json:"sni"`
	HTTPHosts     []ObservationTopListEntry `json:"http_hosts"`
	SourceDevices []ObservationTopListEntry `json:"source_devices"`
}

type ObservationTopListEntry struct {
	Key       string `json:"key"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Sources   int    `json:"sources,omitempty"`
}

type observationTopAccumulator struct {
	count   int
	first   time.Time
	last    time.Time
	sources map[string]bool
}

type portScanAccumulator struct {
	ports map[uint16]bool
	hosts map[string]bool
}

func LoadObservationSOC(path string) (ObservationSOC, error) {
	observations, err := LoadObservations(path)
	if err != nil {
		return ObservationSOC{}, err
	}
	return BuildObservationSOC(path, observations), nil
}

func LoadObservations(path string) ([]ObservationRecord, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)

	var observations []ObservationRecord
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var observation ObservationRecord
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			continue
		}
		observations = append(observations, observation)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return observations, nil
}

func BuildObservationSOC(source string, observations []ObservationRecord) ObservationSOC {
	sort.SliceStable(observations, func(i, j int) bool {
		return observations[i].Timestamp.Before(observations[j].Timestamp)
	})

	summary := ObservationSOC{
		Source:   source,
		Timeline: []ObservationTimeBucket{},
		Limitations: []string{
			"Passive observation records metadata, not encrypted HTTPS payload content.",
			"Attack-like counts are research signals and should be reviewed before treating them as confirmed compromise.",
			"Visibility depends on where packet capture or router logs are collected.",
		},
	}

	sourceSet := map[string]bool{}
	destinationSet := map[string]bool{}
	dnsSet := map[string]bool{}
	sniSet := map[string]bool{}
	httpHostSet := map[string]bool{}
	seenDestinations := map[string]bool{}
	attackSourceSet := map[string]bool{}
	reasonCounts := map[string]int{}
	attackSourceCounts := map[string]*observationTopAccumulator{}
	destinations := map[string]*observationTopAccumulator{}
	dnsQueries := map[string]*observationTopAccumulator{}
	sniValues := map[string]*observationTopAccumulator{}
	httpHosts := map[string]*observationTopAccumulator{}
	sourceDevices := map[string]*observationTopAccumulator{}
	timeline := map[string]*ObservationTimeBucket{}
	portScans := map[string]*portScanAccumulator{}
	var attackItems []AttackLikeObservation
	var first time.Time
	var last time.Time

	for _, observation := range observations {
		if observation.Timestamp.IsZero() {
			continue
		}
		if first.IsZero() || observation.Timestamp.Before(first) {
			first = observation.Timestamp
		}
		if observation.Timestamp.After(last) {
			last = observation.Timestamp
		}

		summary.Metrics.TotalObservations++
		source := strings.TrimSpace(observation.SrcIP)
		destination := normalizedObservationDestination(observation)
		protocol := normalizedObservationProtocol(observation)
		hourKey := observation.Timestamp.UTC().Truncate(time.Hour).Format(time.RFC3339)
		bucket := ensureObservationBucket(timeline, hourKey)
		bucket.TotalCount++

		if source != "" {
			sourceSet[source] = true
			addObservationTop(sourceDevices, source, source, observation.Timestamp)
		}
		if destination != "" {
			destinationSet[destination] = true
			addObservationTop(destinations, destination, source, observation.Timestamp)
		}

		if observation.Noise {
			summary.Metrics.NoiseCount++
			bucket.NoiseCount++
		}
		if isObservationExternal(observation) {
			summary.Metrics.ExternalCount++
			bucket.ExternalCount++
		} else if isObservationLocal(observation) {
			summary.Metrics.LocalCount++
		}
		if isObservationDNS(observation) {
			summary.Metrics.DNSCount++
			bucket.DNSCount++
			if query := strings.TrimSpace(observation.DNSQuery); query != "" {
				dnsSet[query] = true
				addObservationTop(dnsQueries, query, source, observation.Timestamp)
			}
		}
		if isObservationHTTP(observation) {
			summary.Metrics.HTTPCount++
			bucket.HTTPCount++
			if host := strings.TrimSpace(observation.Host); host != "" {
				httpHostSet[host] = true
				addObservationTop(httpHosts, host, source, observation.Timestamp)
			}
		}
		if isObservationTLS(observation) {
			summary.Metrics.TLSCount++
			bucket.TLSCount++
			if sni := strings.TrimSpace(observation.SNI); sni != "" {
				sniSet[sni] = true
				addObservationTop(sniValues, sni, source, observation.Timestamp)
			}
		}

		reasons := attackLikeReasons(observation, seenDestinations)
		for _, reason := range reasons {
			reasonCounts[reason]++
		}
		if len(reasons) > 0 {
			summary.Metrics.AttackLikeCount++
			bucket.AttackLikeCount++
			if source != "" {
				attackSourceSet[source] = true
				addObservationTop(attackSourceCounts, source, source, observation.Timestamp)
			}
			attackItems = append(attackItems, AttackLikeObservation{
				Timestamp:   observation.Timestamp.UTC().Format(time.RFC3339),
				Source:      firstNonEmpty(source, "-"),
				Destination: firstNonEmpty(destination, "-"),
				Port:        observation.DstPort,
				Protocol:    protocol,
				Kind:        observation.Kind,
				Reasons:     attackReasonLabels(reasons),
			})
		}
		if shouldTrackPortScan(observation) && source != "" {
			scanKey := source + "|" + hourKey
			acc := portScans[scanKey]
			if acc == nil {
				acc = &portScanAccumulator{ports: map[uint16]bool{}, hosts: map[string]bool{}}
				portScans[scanKey] = acc
			}
			if observation.DstPort != 0 {
				acc.ports[observation.DstPort] = true
			}
			if destination != "" {
				acc.hosts[destination] = true
			}
		}

		if destination != "" && !observation.Noise {
			seenDestinations[destination] = true
		}
	}

	for scanKey, scan := range portScans {
		if len(scan.ports) < 8 && len(scan.hosts) < 12 {
			continue
		}
		parts := strings.Split(scanKey, "|")
		source := parts[0]
		hour := ""
		if len(parts) > 1 {
			hour = parts[1]
		}
		reasonCounts["scan_like_burst"]++
		summary.Metrics.AttackLikeCount++
		if source != "" {
			attackSourceSet[source] = true
			if t, ok := parseRFC3339(hour); ok {
				addObservationTop(attackSourceCounts, source, source, t)
			}
		}
		if bucket := timeline[hour]; bucket != nil {
			bucket.AttackLikeCount++
		}
		attackItems = append(attackItems, AttackLikeObservation{
			Timestamp:   hour,
			Source:      firstNonEmpty(source, "-"),
			Destination: fmt.Sprintf("%d ports / %d destinations", len(scan.ports), len(scan.hosts)),
			Kind:        "scan_like_burst",
			Reasons:     []string{attackReasonLabel("scan_like_burst")},
		})
	}

	if !first.IsZero() {
		summary.Window.Start = first.UTC().Format(time.RFC3339)
	}
	if !last.IsZero() {
		summary.Window.End = last.UTC().Format(time.RFC3339)
	}
	summary.Metrics.UniqueSources = len(sourceSet)
	summary.Metrics.UniqueDestinations = len(destinationSet)
	summary.Metrics.UniqueDNSQueries = len(dnsSet)
	summary.Metrics.UniqueSNI = len(sniSet)
	summary.Metrics.UniqueHTTPHosts = len(httpHostSet)
	summary.Metrics.AttackLikeSourceCount = len(attackSourceSet)

	summary.Timeline = observationTimeline(timeline)
	summary.TopLists = ObservationTopLists{
		Destinations:  observationTopList(destinations, 10),
		DNSQueries:    observationTopList(dnsQueries, 10),
		SNI:           observationTopList(sniValues, 10),
		HTTPHosts:     observationTopList(httpHosts, 10),
		SourceDevices: observationTopList(sourceDevices, 10),
	}
	summary.AttackLike = AttackLikeActivity{
		Score:       observationAttackScore(summary.Metrics.AttackLikeCount, summary.Metrics.TotalObservations, len(reasonCounts)),
		TotalCount:  summary.Metrics.AttackLikeCount,
		ByReason:    attackReasons(reasonCounts),
		TopSources:  observationTopList(attackSourceCounts, 5),
		RecentItems: recentAttackItems(attackItems, 8),
	}
	summary.AttackLike.Level = observationAttackLevel(summary.AttackLike.Score)
	return summary
}

func normalizedObservationDestination(observation ObservationRecord) string {
	for _, candidate := range []string{observation.ObservedDestination, observation.DNSQuery, observation.SNI, observation.Host, observation.DstIP} {
		candidate = strings.TrimSpace(candidate)
		if candidate != "" && candidate != "-" {
			return candidate
		}
	}
	return ""
}

func normalizedObservationProtocol(observation ObservationRecord) string {
	return strings.ToUpper(strings.TrimSpace(firstNonEmpty(observation.AppProtocol, observation.Protocol)))
}

func ensureObservationBucket(timeline map[string]*ObservationTimeBucket, hour string) *ObservationTimeBucket {
	bucket := timeline[hour]
	if bucket != nil {
		return bucket
	}
	bucket = &ObservationTimeBucket{Hour: hour}
	timeline[hour] = bucket
	return bucket
}

func addObservationTop(items map[string]*observationTopAccumulator, key, source string, ts time.Time) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	item := items[key]
	if item == nil {
		item = &observationTopAccumulator{sources: map[string]bool{}}
		items[key] = item
	}
	item.count++
	if item.first.IsZero() || ts.Before(item.first) {
		item.first = ts
	}
	if ts.After(item.last) {
		item.last = ts
	}
	if source = strings.TrimSpace(source); source != "" {
		item.sources[source] = true
	}
}

func observationTopList(items map[string]*observationTopAccumulator, limit int) []ObservationTopListEntry {
	out := make([]ObservationTopListEntry, 0, len(items))
	for key, item := range items {
		if item == nil {
			continue
		}
		entry := ObservationTopListEntry{
			Key:     key,
			Count:   item.count,
			Sources: len(item.sources),
		}
		if !item.first.IsZero() {
			entry.FirstSeen = item.first.UTC().Format(time.RFC3339)
		}
		if !item.last.IsZero() {
			entry.LastSeen = item.last.UTC().Format(time.RFC3339)
		}
		out = append(out, entry)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if limit > 0 && len(out) > limit {
		return out[:limit]
	}
	return out
}

func observationTimeline(items map[string]*ObservationTimeBucket) []ObservationTimeBucket {
	out := make([]ObservationTimeBucket, 0, len(items))
	for _, item := range items {
		if item != nil {
			out = append(out, *item)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Hour < out[j].Hour
	})
	return out
}

func isObservationExternal(observation ObservationRecord) bool {
	if strings.EqualFold(strings.TrimSpace(observation.Direction), "external") {
		return true
	}
	if observation.DstIP == "" {
		return false
	}
	return !isLocalDeviceIP(observation.DstIP) && !isMulticastOrBroadcastIP(observation.DstIP)
}

func isObservationLocal(observation ObservationRecord) bool {
	if strings.EqualFold(strings.TrimSpace(observation.Direction), "local") {
		return true
	}
	return isLocalDeviceIP(observation.DstIP) || isMulticastOrBroadcastIP(observation.DstIP)
}

func isObservationDNS(observation ObservationRecord) bool {
	kind := strings.ToLower(strings.TrimSpace(observation.Kind))
	protocol := strings.ToLower(strings.TrimSpace(observation.AppProtocol))
	return kind == "dns_query" || kind == "mdns_query" || protocol == "dns" || protocol == "mdns" || strings.TrimSpace(observation.DNSQuery) != ""
}

func isObservationHTTP(observation ObservationRecord) bool {
	kind := strings.ToLower(strings.TrimSpace(observation.Kind))
	protocol := strings.ToLower(strings.TrimSpace(observation.AppProtocol))
	return strings.HasPrefix(kind, "http_") || protocol == "http" || strings.TrimSpace(observation.Host) != "" || strings.TrimSpace(observation.HTTPMethod) != ""
}

func isObservationTLS(observation ObservationRecord) bool {
	kind := strings.ToLower(strings.TrimSpace(observation.Kind))
	protocol := strings.ToLower(strings.TrimSpace(observation.AppProtocol))
	return kind == "tls_sni" || protocol == "tls" || protocol == "https" || strings.TrimSpace(observation.SNI) != ""
}

func attackLikeReasons(observation ObservationRecord, seenDestinations map[string]bool) []string {
	if observation.Noise {
		return nil
	}
	reasons := map[string]bool{}
	destination := normalizedObservationDestination(observation)
	protocol := strings.ToLower(strings.TrimSpace(firstNonEmpty(observation.AppProtocol, observation.Protocol)))

	if isObservationExternal(observation) {
		reasons["external_observation"] = true
		if destination != "" && !seenDestinations[destination] {
			reasons["first_seen_external_destination"] = true
		}
		if isPublicIPLiteral(destination) && observation.SNI == "" && observation.Host == "" && observation.DNSQuery == "" {
			reasons["direct_ip_external"] = true
		}
	}
	if protocol == "http" || observation.DstPort == 80 || strings.HasPrefix(strings.ToLower(observation.Kind), "http_") {
		reasons["plaintext_http"] = true
	}
	if isRiskyPort(observation.DstPort) {
		reasons["risky_port"] = true
	}
	if looksSuspiciousDNS(observation.DNSQuery) {
		reasons["suspicious_dns"] = true
	}

	out := make([]string, 0, len(reasons))
	for reason := range reasons {
		out = append(out, reason)
	}
	sort.Strings(out)
	return out
}

func isPublicIPLiteral(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

func isRiskyPort(port uint16) bool {
	switch port {
	case 21, 22, 23, 2323, 445, 3389, 5900, 5901, 7547, 8080:
		return true
	default:
		return false
	}
}

func looksSuspiciousDNS(query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return false
	}
	riskyTokens := []string{
		"duckdns.org",
		"no-ip.",
		"dynu.",
		"servehttp.",
		"hopto.org",
		"ddns.",
		"pastebin.",
		"ngrok.",
		"onion.",
	}
	for _, token := range riskyTokens {
		if strings.Contains(query, token) {
			return true
		}
	}
	labels := strings.Split(query, ".")
	for _, label := range labels {
		if len(label) >= 24 && highDigitRatio(label) {
			return true
		}
	}
	return false
}

func highDigitRatio(value string) bool {
	if value == "" {
		return false
	}
	digits := 0
	for _, r := range value {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return float64(digits)/float64(len(value)) >= 0.35
}

func shouldTrackPortScan(observation ObservationRecord) bool {
	return !observation.Noise && isObservationExternal(observation) && observation.DstPort != 0
}

func attackReasons(counts map[string]int) []AttackLikeReason {
	out := make([]AttackLikeReason, 0, len(counts))
	for key, count := range counts {
		if count <= 0 {
			continue
		}
		out = append(out, AttackLikeReason{Key: key, Label: attackReasonLabel(key), Count: count})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	return out
}

func attackReasonLabels(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		out = append(out, attackReasonLabel(reason))
	}
	return out
}

func attackReasonLabel(reason string) string {
	switch reason {
	case "external_observation":
		return "ノイズではない外部通信"
	case "first_seen_external_destination":
		return "初めて観測した外部通信先"
	case "direct_ip_external":
		return "ドメイン名なしの外部IP直通信"
	case "plaintext_http":
		return "平文HTTP通信"
	case "risky_port":
		return "管理・遠隔操作系ポート"
	case "suspicious_dns":
		return "不審なDNS問い合わせ"
	case "scan_like_burst":
		return "短時間のスキャン様通信"
	default:
		return reason
	}
}

func recentAttackItems(items []AttackLikeObservation, limit int) []AttackLikeObservation {
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].Timestamp > items[j].Timestamp
	})
	if limit > 0 && len(items) > limit {
		return items[:limit]
	}
	return items
}

func observationAttackScore(attackLike, total, reasonKinds int) int {
	if total <= 0 || attackLike <= 0 {
		return 0
	}
	ratioScore := int((float64(attackLike) / float64(total)) * 100)
	volumeScore := minInt(attackLike*3, 55)
	diversityScore := minInt(reasonKinds*8, 24)
	return clampInt(maxInt(ratioScore, volumeScore)+diversityScore, 0, 100)
}

func observationAttackLevel(score int) string {
	switch {
	case score >= 75:
		return "high"
	case score >= 45:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "quiet"
	}
}
