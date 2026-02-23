package analyzer

import (
	"bytes"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	sink  *JSONLSink
	cache *FlowCache
	debug bool
}

func NewFlowHandler(sink *JSONLSink, debug bool) *FlowHandler {
	return &FlowHandler{
		sink:  sink,
		cache: NewFlowCache(16*1024, 1*time.Hour),
		debug: debug,
	}
}

func flowKeyTCP(ipSrc string, srcPort uint16, ipDst string, dstPort uint16) string {
	a := fmt.Sprintf("%s:%d", ipSrc, srcPort)
	b := fmt.Sprintf("%s:%d", ipDst, dstPort)
	if a < b {
		return "tcp|" + a + "<->" + b
	}
	return "tcp|" + b + "<->" + a
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

	key := flowKeyTCP(
		ip.SrcIP.String(), uint16(tcp.SrcPort),
		ip.DstIP.String(), uint16(tcp.DstPort),
	)

	st := h.cache.GetOrCreate(key, now)

	isClientToServer := uint16(tcp.DstPort) == 80

	if len(tcp.Payload) > 0 {
		h.cache.AppendUpToLimit(st, tcp.Payload)
	}

	if isClientToServer && !st.HTTPReported {
		// Appendした結果から先頭だけ見て「リクエスト行」を確定させる
		if bytes.HasPrefix(st.Data, []byte("GET ")) ||
			bytes.HasPrefix(st.Data, []byte("POST ")) ||
			bytes.HasPrefix(st.Data, []byte("PUT ")) ||
			bytes.HasPrefix(st.Data, []byte("DELETE ")) ||
			bytes.HasPrefix(st.Data, []byte("HEAD ")) ||
			bytes.HasPrefix(st.Data, []byte("OPTIONS ")) ||
			bytes.HasPrefix(st.Data, []byte("PATCH ")) {

			// デバッグ（任意）
			if h.debug {
				prefixLen := 32
				if len(st.Data) < prefixLen {
					prefixLen = len(st.Data)
				}
				_ = h.sink.Write(Event{
					Timestamp: now,
					Type:      "HTTP_DEBUG_KEY",
					Severity:  SeverityInfo,
					SrcIP:     ip.SrcIP.String(),
					SrcPort:   uint16(tcp.SrcPort),
					DstIP:     ip.DstIP.String(),
					DstPort:   uint16(tcp.DstPort),
					Message:   fmt.Sprintf("key=%s prefix=%q", key, string(st.Data[:prefixLen])),
				})
			}

			_ = h.sink.Write(Event{
				Timestamp: now,
				Type:      "INSECURE_HTTP",
				Severity:  SeverityWarning,
				SrcIP:     ip.SrcIP.String(),
				SrcPort:   uint16(tcp.SrcPort),
				DstIP:     ip.DstIP.String(),
				DstPort:   uint16(tcp.DstPort),
				Message:   "Plaintext HTTP detected (first 16KB)",
			})
			st.HTTPReported = true
		}
	}

	if now.Unix()%10 == 0 {
		h.cache.Cleanup(now)
	}
	if h.debug && uint16(tcp.DstPort) == 80 && len(tcp.Payload) > 0 {
		p := tcp.Payload
		if len(p) > 256 {
			p = p[:256]
		}
		_ = h.sink.Write(Event{
			Timestamp: time.Now(),
			Type:      "PAYLOAD_DEBUG",
			Severity:  SeverityInfo,
			SrcIP:     ip.SrcIP.String(),
			SrcPort:   uint16(tcp.SrcPort),
			DstIP:     ip.DstIP.String(),
			DstPort:   uint16(tcp.DstPort),
			Message:   fmt.Sprintf("payload_head=%q", string(p)),
		})
	}
}
