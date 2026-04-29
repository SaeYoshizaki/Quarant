package analyzer

import (
	"net"
	"strings"
	"time"

	"quarant/analyzer/device"
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

func observedDestination(sni, host, dstIP string) string {
	if value := strings.TrimSpace(sni); value != "" {
		return value
	}
	if value := strings.TrimSpace(host); value != "" {
		return value
	}
	return strings.TrimSpace(dstIP)
}

func flowDirection(dstIP string) string {
	ip := net.ParseIP(strings.TrimSpace(dstIP))
	if ip == nil || ip.IsUnspecified() {
		return "unknown"
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return "local"
	}
	return "external"
}

func normalizeDeviceCategory(d *device.DeviceProfile) string {
	if d == nil {
		return ""
	}
	category := strings.TrimSpace(d.Classification.NormalizedCategory())
	if category == "" || category == "GenericIoT" {
		return ""
	}
	return category
}
