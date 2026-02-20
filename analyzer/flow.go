package analyzer

import (
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	sink *JSONLSink
}

func NewFlowHandler(sink *JSONLSink) *FlowHandler {
	return &FlowHandler{
		sink: sink,
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

	event := Event {
		Timestamp: time.Now(),
		Type: "FLOW_DETECTED",
		Severity: SeverityInfo,

		SrcIP: ip.SrcIP.String(),
		SrcPort: uint16(tcp.SrcPort),

		DstIP: ip.DstIP.String(),
		DstPort: uint16(tcp.DstPort),

		Message: "TCP flow detexted",
	}
	h.sink.Write(event)
}