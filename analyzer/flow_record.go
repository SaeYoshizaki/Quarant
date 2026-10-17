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
	DNSName             string    `json:"dns_name,omitempty"`
	HTTPMethod          string    `json:"http_method"`
	HTTPPath            string    `json:"http_path"`
	BytesOut            int64     `json:"bytes_out"`
	BytesIn             int64     `json:"bytes_in"`
	PacketCount         int       `json:"packet_count"`
	Direction           string    `json:"direction"`
	DeviceLabel         string    `json:"device_label"`
	DeviceCategory      string    `json:"device_category"`
	ObservedDestination string    `json:"observed_destination"`
	// Reassembly counters for the payload-captured directions: gaps are
	// bytes the receiver acknowledged but the capture never saw (or that
	// were given up on), so content in them could not be analysed.
	CaptureGaps        int `json:"capture_gaps,omitempty"`
	CaptureGapBytes    int `json:"capture_gap_bytes,omitempty"`
	RetransmittedBytes int `json:"retransmitted_bytes,omitempty"`
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

func firstNonEmptyString(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
