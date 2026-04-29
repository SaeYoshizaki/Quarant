package reportapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type FlowRecord struct {
	Timestamp           time.Time `json:"ts"`
	FlowKey             string    `json:"flow_key"`
	SrcIP               string    `json:"src_ip"`
	SrcPort             uint16    `json:"src_port"`
	DstIP               string    `json:"dst_ip"`
	DstPort             uint16    `json:"dst_port"`
	Protocol            string    `json:"protocol"`
	AppProtocol         string    `json:"app_protocol"`
	Host                string    `json:"host"`
	SNI                 string    `json:"sni"`
	HTTPMethod          string    `json:"http_method"`
	HTTPPath            string    `json:"http_path"`
	BytesOut            int64     `json:"bytes_out"`
	BytesIn             int64     `json:"bytes_in"`
	PacketCount         int       `json:"packet_count"`
	Direction           string    `json:"direction"`
	DeviceLabel         string    `json:"device_label"`
	DeviceCategory      string    `json:"device_category"`
	ObservedDestination string    `json:"observed_destination"`
}

type ActivitySummaryResponse struct {
	Summary         ActivitySummary         `json:"summary"`
	TrafficByHour   []TrafficByHour         `json:"traffic_by_hour"`
	TrafficByDevice []TrafficByDevice       `json:"traffic_by_device"`
	TopDestinations []DestinationTraffic    `json:"top_destinations"`
	NewDestinations []NewDestination        `json:"new_destinations"`
	RiskByCategory  []RiskCategoryBreakdown `json:"risk_by_category"`
	RiskByHour      []RiskByHour            `json:"risk_by_hour"`
}

type ActivitySummary struct {
	DeviceCount         int   `json:"device_count"`
	ExternalFlowCount   int   `json:"external_flow_count"`
	NewDestinationCount int   `json:"new_destination_count"`
	RiskEventCount      int   `json:"risk_event_count"`
	TotalBytesOut       int64 `json:"total_bytes_out"`
	TotalBytesIn        int64 `json:"total_bytes_in"`
}

type TrafficByHour struct {
	Hour       string `json:"hour"`
	FlowCount  int    `json:"flow_count"`
	BytesTotal int64  `json:"bytes_total"`
}

type TrafficByDevice struct {
	Device     string `json:"device"`
	Label      string `json:"label"`
	FlowCount  int    `json:"flow_count"`
	BytesTotal int64  `json:"bytes_total"`
}

type DestinationTraffic struct {
	Destination string `json:"destination"`
	FlowCount   int    `json:"flow_count"`
	BytesTotal  int64  `json:"bytes_total"`
	Direction   string `json:"direction"`
}

type NewDestination struct {
	Device      string `json:"device"`
	Destination string `json:"destination"`
	FirstSeen   string `json:"first_seen"`
	FlowCount   int    `json:"flow_count"`
}

type RiskCategoryBreakdown struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Count    int    `json:"count"`
}

type RiskByHour struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type flowCumulative struct {
	bytesOut    int64
	bytesIn     int64
	packetCount int
}

type deviceStats struct {
	label    string
	bytes    int64
	flowKeys map[string]bool
}

type destinationStats struct {
	bytes     int64
	direction string
	flowKeys  map[string]bool
}

type newDestinationStats struct {
	device      string
	destination string
	firstSeen   time.Time
	flowCount   int
}

type activityEvent struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	RuleID    string    `json:"rule_id,omitempty"`
	Category  string    `json:"category,omitempty"`
	Debug     bool      `json:"debug,omitempty"`
}

func LoadActivitySummary(eventsPath, flowsPath string) (ActivitySummaryResponse, error) {
	// This API normalizes "today" in UTC so hourly buckets are deterministic regardless of host local timezone.
	now := time.Now().UTC()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	dayEnd := dayStart.Add(24 * time.Hour)

	flows, err := loadFlowRecords(flowsPath)
	if err != nil {
		return ActivitySummaryResponse{}, err
	}
	events, err := loadActivityEvents(eventsPath)
	if err != nil {
		return ActivitySummaryResponse{}, err
	}

	return buildActivitySummary(flows, events, dayStart, dayEnd), nil
}

func buildActivitySummary(flows []FlowRecord, events []activityEvent, dayStart, dayEnd time.Time) ActivitySummaryResponse {
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].Timestamp.Before(flows[j].Timestamp)
	})
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	resp := ActivitySummaryResponse{
		TrafficByHour:  makeTrafficByHour(dayStart),
		RiskByCategory: []RiskCategoryBreakdown{},
		RiskByHour:     makeRiskByHour(dayStart),
	}

	deviceSet := map[string]bool{}
	externalFlowKeys := map[string]bool{}
	seenDeviceDestination := map[string]time.Time{}
	seenTodayDeviceDestination := map[string]*newDestinationStats{}
	prevByFlowKey := map[string]flowCumulative{}
	deviceStatsByIP := map[string]*deviceStats{}
	destStatsByName := map[string]*destinationStats{}

	for _, flow := range flows {
		if flow.Timestamp.IsZero() || strings.TrimSpace(flow.FlowKey) == "" {
			continue
		}

		prev := prevByFlowKey[flow.FlowKey]
		deltaOut := cumulativeDelta(flow.BytesOut, prev.bytesOut)
		deltaIn := cumulativeDelta(flow.BytesIn, prev.bytesIn)
		totalDeltaBytes := deltaOut + deltaIn
		prevByFlowKey[flow.FlowKey] = flowCumulative{
			bytesOut:    maxInt64(flow.BytesOut, prev.bytesOut),
			bytesIn:     maxInt64(flow.BytesIn, prev.bytesIn),
			packetCount: maxInt(flow.PacketCount, prev.packetCount),
		}

		device := strings.TrimSpace(flow.SrcIP)
		destination := normalizedDestination(flow)
		pairKey := device + "|" + destination
		firstSeenAt, seenBefore := seenDeviceDestination[pairKey]
		if !seenBefore {
			seenDeviceDestination[pairKey] = flow.Timestamp
			firstSeenAt = flow.Timestamp
		}

		if flow.Timestamp.Before(dayStart) || !flow.Timestamp.Before(dayEnd) {
			continue
		}
		if device != "" {
			deviceSet[device] = true
		}
		if flow.Direction == "external" {
			externalFlowKeys[flow.FlowKey] = true
		}

		if !firstSeenAt.Before(dayStart) && firstSeenAt.Before(dayEnd) && device != "" && destination != "" {
			if _, ok := seenTodayDeviceDestination[pairKey]; !ok {
				seenTodayDeviceDestination[pairKey] = &newDestinationStats{
					device:      device,
					destination: destination,
					firstSeen:   firstSeenAt,
				}
			}
			seenTodayDeviceDestination[pairKey].flowCount++
		}

		resp.Summary.TotalBytesOut += deltaOut
		resp.Summary.TotalBytesIn += deltaIn

		hourIndex := int(flow.Timestamp.Sub(dayStart) / time.Hour)
		if hourIndex >= 0 && hourIndex < len(resp.TrafficByHour) {
			resp.TrafficByHour[hourIndex].BytesTotal += totalDeltaBytes
			resp.TrafficByHour[hourIndex].FlowCount++
		}

		if device != "" {
			stats := deviceStatsByIP[device]
			if stats == nil {
				stats = &deviceStats{label: strings.TrimSpace(flow.DeviceLabel), flowKeys: map[string]bool{}}
				deviceStatsByIP[device] = stats
			}
			if stats.label == "" {
				stats.label = strings.TrimSpace(flow.DeviceLabel)
			}
			stats.bytes += totalDeltaBytes
			stats.flowKeys[flow.FlowKey] = true
		}

		if flow.Direction == "external" && destination != "" {
			stats := destStatsByName[destination]
			if stats == nil {
				stats = &destinationStats{direction: "external", flowKeys: map[string]bool{}}
				destStatsByName[destination] = stats
			}
			stats.bytes += totalDeltaBytes
			stats.flowKeys[flow.FlowKey] = true
		}
	}

	resp.Summary.DeviceCount = len(deviceSet)
	resp.Summary.ExternalFlowCount = len(externalFlowKeys)

	for _, event := range events {
		if event.Debug || event.Timestamp.Before(dayStart) || !event.Timestamp.Before(dayEnd) {
			continue
		}
		resp.Summary.RiskEventCount++

		hourIndex := int(event.Timestamp.Sub(dayStart) / time.Hour)
		if hourIndex >= 0 && hourIndex < len(resp.RiskByHour) {
			resp.RiskByHour[hourIndex].Count++
		}

		category := normalizedRiskCategory(event)
		addRiskCategoryCount(&resp.RiskByCategory, category)
	}

	resp.TrafficByDevice = makeTrafficByDevice(deviceStatsByIP)
	resp.TopDestinations = makeTopDestinations(destStatsByName)
	resp.NewDestinations = makeNewDestinations(seenTodayDeviceDestination)
	resp.Summary.NewDestinationCount = len(resp.NewDestinations)
	sort.SliceStable(resp.RiskByCategory, func(i, j int) bool {
		if resp.RiskByCategory[i].Count == resp.RiskByCategory[j].Count {
			return resp.RiskByCategory[i].Category < resp.RiskByCategory[j].Category
		}
		return resp.RiskByCategory[i].Count > resp.RiskByCategory[j].Count
	})

	return resp
}

func loadFlowRecords(path string) ([]FlowRecord, error) {
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
	var flows []FlowRecord
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var flow FlowRecord
		if err := json.Unmarshal([]byte(line), &flow); err != nil {
			continue
		}
		flows = append(flows, flow)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return flows, nil
}

func loadActivityEvents(path string) ([]activityEvent, error) {
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
	var events []activityEvent
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var event activityEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			continue
		}
		events = append(events, event)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return events, nil
}

func makeTrafficByHour(dayStart time.Time) []TrafficByHour {
	out := make([]TrafficByHour, 24)
	for i := 0; i < 24; i++ {
		out[i] = TrafficByHour{
			Hour: dayStart.Add(time.Duration(i) * time.Hour).Format("15:04"),
		}
	}
	return out
}

func makeRiskByHour(dayStart time.Time) []RiskByHour {
	out := make([]RiskByHour, 24)
	for i := 0; i < 24; i++ {
		out[i] = RiskByHour{
			Hour: dayStart.Add(time.Duration(i) * time.Hour).Format("15:04"),
		}
	}
	return out
}

func makeTrafficByDevice(stats map[string]*deviceStats) []TrafficByDevice {
	out := make([]TrafficByDevice, 0, len(stats))
	for device, stat := range stats {
		if stat == nil {
			continue
		}
		out = append(out, TrafficByDevice{
			Device:     device,
			Label:      stat.label,
			FlowCount:  len(stat.flowKeys),
			BytesTotal: stat.bytes,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].BytesTotal == out[j].BytesTotal {
			return out[i].Device < out[j].Device
		}
		return out[i].BytesTotal > out[j].BytesTotal
	})
	return out
}

func makeTopDestinations(stats map[string]*destinationStats) []DestinationTraffic {
	out := make([]DestinationTraffic, 0, len(stats))
	for destination, stat := range stats {
		if stat == nil {
			continue
		}
		out = append(out, DestinationTraffic{
			Destination: destination,
			FlowCount:   len(stat.flowKeys),
			BytesTotal:  stat.bytes,
			Direction:   stat.direction,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].BytesTotal == out[j].BytesTotal {
			return out[i].Destination < out[j].Destination
		}
		return out[i].BytesTotal > out[j].BytesTotal
	})
	return out
}

func makeNewDestinations(stats map[string]*newDestinationStats) []NewDestination {
	out := make([]NewDestination, 0, len(stats))
	for _, stat := range stats {
		if stat == nil {
			continue
		}
		out = append(out, NewDestination{
			Device:      stat.device,
			Destination: stat.destination,
			FirstSeen:   stat.firstSeen.UTC().Format(time.RFC3339),
			FlowCount:   stat.flowCount,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FirstSeen == out[j].FirstSeen {
			if out[i].Device == out[j].Device {
				return out[i].Destination < out[j].Destination
			}
			return out[i].Device < out[j].Device
		}
		return out[i].FirstSeen < out[j].FirstSeen
	})
	return out
}

func addRiskCategoryCount(out *[]RiskCategoryBreakdown, category string) {
	for i := range *out {
		if (*out)[i].Category == category {
			(*out)[i].Count++
			return
		}
	}
	*out = append(*out, RiskCategoryBreakdown{
		Category: category,
		Label:    riskCategoryLabel(category),
		Count:    1,
	})
}

func normalizedDestination(flow FlowRecord) string {
	if value := strings.TrimSpace(flow.ObservedDestination); value != "" {
		return value
	}
	if value := strings.TrimSpace(flow.SNI); value != "" {
		return value
	}
	if value := strings.TrimSpace(flow.Host); value != "" {
		return value
	}
	return strings.TrimSpace(flow.DstIP)
}

func normalizedRiskCategory(event activityEvent) string {
	if category := normalizeRiskCategoryToken(event.Category); category != "" {
		return category
	}
	if category := categoryFromIdentifier(event.RuleID); category != "" {
		return category
	}
	if category := categoryFromIdentifier(event.Type); category != "" {
		return category
	}
	return "unknown"
}

func normalizeRiskCategoryToken(value string) string {
	token := strings.ToUpper(strings.TrimSpace(value))
	switch token {
	case "I2", "I4", "I5", "I6", "I7", "I8":
		return token
	default:
		return ""
	}
}

func categoryFromIdentifier(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		return ""
	}
	if idx := strings.IndexByte(value, '_'); idx > 0 {
		value = value[:idx]
	}
	return normalizeRiskCategoryToken(value)
}

func riskCategoryLabel(category string) string {
	switch category {
	case "I2":
		return "危険なサービス"
	case "I4":
		return "更新リスク"
	case "I5":
		return "既知脆弱性の可能性"
	case "I6":
		return "プライバシーリスク"
	case "I7":
		return "平文通信"
	case "I8":
		return "新規・未登録端末"
	default:
		return "その他"
	}
}

func cumulativeDelta(current, previous int64) int64 {
	if current < previous {
		return current
	}
	return current - previous
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
