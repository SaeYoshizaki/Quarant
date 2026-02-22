package analyzer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"quarant/analyzer/rules"
)

type FlowHandler struct {
	sink  *JSONLSink
	cache *FlowCache
}

func NewFlowHandler(sink *JSONLSink) *FlowHandler {
	return &FlowHandler{
		sink:  sink,
		cache: NewFlowCache(16*1024, 1*time.Hour),
	}
}

func (h *FlowHandler) HandlePacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if ipLayer == nil || tcpLayer == nil {
		return
	}

	ip := ipLayer.(*layers.IPv4)
	tcp := tcpLayer.(*layers.TCP)

	now := time.Now()

	flowKey := fmt.Sprintf(
		"tcp|%s:%d->%s:%d",
		ip.SrcIP.String(),
		uint16(tcp.SrcPort),
		ip.DstIP.String(),
		uint16(tcp.DstPort),
	)

	st := h.cache.GetOrCreate(flowKey, now)

	if !st.FlowReported {
		ev := Event{
			Timestamp: now,
			Type:      "FLOW_DETECTED",
			Severity:  SeverityInfo,

			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),

			DstIP:   ip.DstIP.String(),
			DstPort: uint16(tcp.DstPort),

			Message: "TCP flow detected",
		}
		_ = h.sink.Write(ev)
		st.FlowReported = true
	}

	h.cache.AppendUpToLimit(st, tcp.Payload)

	if !st.HTTPReported && rules.LooksLikeHTTP(st.Data) {
		ev := Event{
			Timestamp: now,
			Type:      "INSECURE_HTTP",
			Severity:  SeverityWarning,

			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),

			DstIP:   ip.DstIP.String(),
			DstPort: uint16(tcp.DstPort),

			Message: "Plaintext HTTP detected (first 16KB)",
		}
		_ = h.sink.Write(ev)
		st.HTTPReported = true
	}

	if now.Unix()%10 == 0 {
		h.cache.Cleanup(now)
	}
	payload := tcp.Payload
	if len(payload) > 0 {
		if uint16(tcp.DstPort) == 80 && len(tcp.Payload) > 0 {
			h.sink.Write(Event{
				Timestamp: time.Now(),
				Type:      "PAYLOAD_DEBUG",
				Severity:  SeverityInfo,
				SrcIP:     ip.SrcIP.String(),
				SrcPort:   uint16(tcp.SrcPort),
				DstIP:     ip.DstIP.String(),
				DstPort:   uint16(tcp.DstPort),
				Message:   fmt.Sprintf("payload=%q", string(tcp.Payload)),
			})
		}
	}
}
