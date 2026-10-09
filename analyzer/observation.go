package analyzer

import (
	"strings"
	"time"

	"github.com/google/gopacket/layers"
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

func (h *FlowHandler) writeObservation(obs ObservationRecord) {
	if h == nil || h.observationSink == nil {
		return
	}
	_ = h.observationSink.WriteObservation(obs)
}

func (h *FlowHandler) writeFlowObservations(record FlowRecord) {
	if h == nil || h.observationSink == nil {
		return
	}
	base := ObservationRecord{
		Timestamp:           record.Timestamp,
		Kind:                "flow_snapshot",
		FlowKey:             record.FlowKey,
		SrcIP:               record.SrcIP,
		SrcPort:             record.SrcPort,
		DstIP:               record.DstIP,
		DstPort:             record.DstPort,
		Protocol:            record.Protocol,
		AppProtocol:         record.AppProtocol,
		Direction:           record.Direction,
		DeviceCategory:      record.DeviceCategory,
		ObservedDestination: record.ObservedDestination,
		Host:                record.Host,
		SNI:                 record.SNI,
		HTTPMethod:          record.HTTPMethod,
		HTTPPath:            record.HTTPPath,
		Noise:               isObservationNoise(record.AppProtocol, record.Protocol, record.DstPort, record.DstIP),
		BytesOut:            record.BytesOut,
		BytesIn:             record.BytesIn,
		PacketCount:         record.PacketCount,
	}
	h.writeObservation(base)

	if record.Direction == "external" {
		external := base
		external.Kind = "external_connection"
		h.writeObservation(external)
	} else if record.Direction == "local" {
		local := base
		local.Kind = "local_connection"
		h.writeObservation(local)
	}
	if strings.TrimSpace(record.SNI) != "" {
		sni := base
		sni.Kind = "tls_sni"
		h.writeObservation(sni)
	}
	if strings.TrimSpace(record.Host) != "" {
		host := base
		host.Kind = "http_host"
		h.writeObservation(host)
	}
	if strings.TrimSpace(record.HTTPMethod) != "" || strings.TrimSpace(record.HTTPPath) != "" {
		httpReq := base
		httpReq.Kind = "http_request"
		h.writeObservation(httpReq)
	}
	if strings.TrimSpace(record.AppProtocol) != "" || strings.TrimSpace(record.Protocol) != "" {
		protocol := base
		protocol.Kind = "protocol_observed"
		h.writeObservation(protocol)
	}
}

func (h *FlowHandler) writeUDPPacketObservations(now time.Time, srcIP, dstIP string, srcPort, dstPort uint16, payloadLen int, dns *layers.DNS) {
	if h == nil || h.observationSink == nil {
		return
	}
	appProtocol := udpAppProtocol(srcPort, dstPort, dns)
	direction := flowDirection(dstIP)
	noise := isObservationNoise(appProtocol, "udp", dstPort, dstIP)
	base := ObservationRecord{
		Timestamp:           now,
		Kind:                "udp_packet",
		SrcIP:               srcIP,
		SrcPort:             srcPort,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Protocol:            "udp",
		AppProtocol:         appProtocol,
		Direction:           direction,
		ObservedDestination: dstIP,
		Noise:               noise,
		BytesOut:            int64(payloadLen),
		PacketCount:         1,
	}
	h.writeObservation(base)

	switch appProtocol {
	case "dns", "mdns":
		if dns != nil {
			for _, question := range dns.Questions {
				query := strings.TrimSuffix(string(question.Name), ".")
				if query == "" {
					continue
				}
				obs := base
				obs.Kind = "dns_query"
				if appProtocol == "mdns" {
					obs.Kind = "mdns_query"
				}
				obs.DNSQuery = query
				obs.ObservedDestination = query
				h.writeObservation(obs)
			}
		}
	case "ssdp":
		obs := base
		obs.Kind = "ssdp_discovery"
		h.writeObservation(obs)
	case "dhcp":
		obs := base
		obs.Kind = "dhcp_activity"
		h.writeObservation(obs)
	case "ntp":
		obs := base
		obs.Kind = "ntp_sync"
		h.writeObservation(obs)
	}
}

func udpAppProtocol(srcPort, dstPort uint16, dns *layers.DNS) string {
	switch {
	case dns != nil && (srcPort == 5353 || dstPort == 5353):
		return "mdns"
	case dns != nil:
		return "dns"
	case srcPort == 1900 || dstPort == 1900:
		return "ssdp"
	case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
		return "dhcp"
	case srcPort == 123 || dstPort == 123:
		return "ntp"
	case srcPort == 5353 || dstPort == 5353:
		return "mdns"
	case srcPort == 5355 || dstPort == 5355:
		return "llmnr"
	default:
		return ""
	}
}

func isObservationNoise(appProtocol, protocol string, dstPort uint16, dstIP string) bool {
	if flowDirection(dstIP) == "local" && (strings.HasPrefix(dstIP, "224.") || strings.HasPrefix(dstIP, "239.") || strings.HasSuffix(dstIP, ".255")) {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(appProtocol)) {
	case "mdns", "ssdp", "dhcp", "ntp", "llmnr", "nbns", "arp":
		return true
	}
	switch dstPort {
	case 67, 68, 123, 137, 138, 1900, 5353, 5355:
		return true
	default:
		return false
	}
}
