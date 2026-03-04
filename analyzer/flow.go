package analyzer

import (
	"fmt"
	"time"

	"quarant/analyzer/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	sink  *JSONLSink
	cache *FlowCache
	debug bool
}

func flowKeyTCP(ipSrc string, srcPort uint16, ipDst string, dstPort uint16) string {
	a := fmt.Sprintf("%s:%d", ipSrc, srcPort)
	b := fmt.Sprintf("%s:%d", ipDst, dstPort)
	if a < b {
		return "tcp|" + a + "<->" + b
	}
	return "tcp|" + b + "<->" + a
}

func isTLSPort(p uint16) bool {
	switch p {
	case 443, 8443, 9443, 10443, 8883:
		return true
	default:
		return false
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

	key := flowKeyTCP(
		ip.SrcIP.String(), uint16(tcp.SrcPort),
		ip.DstIP.String(), uint16(tcp.DstPort),
	)
	st := h.cache.GetOrCreate(key, now)

	dstPort := uint16(tcp.DstPort)
	isHTTPClientToServer := dstPort == 80
	isTLSClientToServer := isTLSPort(dstPort)

	// payload蓄積
	if (isHTTPClientToServer || isTLSClientToServer) && len(tcp.Payload) > 0 {
		h.cache.AppendUpToLimit(st, tcp.Payload)
	}

	// ルール実行（重複防止のゲートは flow が持つ：まずはこれでOK）
	shouldRunTLS := isTLSClientToServer && !st.TLSReported
	shouldRunHTTP := isHTTPClientToServer && !st.HTTPReported

	if shouldRunTLS || shouldRunHTTP {
		ctx := &rules.Context{
			NowUnix: now.Unix(),
			FlowKey: key,
			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstIP:   ip.DstIP.String(),
			DstPort: dstPort,
			Payload: st.Data,
			Debug:   h.debug,
		}

		matches := rules.Run(ctx)

		for _, m := range matches {
			// ゲート条件に合わないものは捨てる（今は2系統だけ運用）
			if m.Type == "TLS_CLIENT_HELLO" && !shouldRunTLS {
				continue
			}
			if m.Type == "INSECURE_HTTP" && !shouldRunHTTP {
				continue
			}

			_ = h.sink.Write(Event{
				Timestamp: now,
				Type:      m.Type,
				Severity:  Severity(m.Severity),

				RuleID:   m.RuleID,
				Category: m.Category,
				FlowKey:  key,
				Evidence: m.Evidence,

				SrcIP:   ip.SrcIP.String(),
				SrcPort: uint16(tcp.SrcPort),
				DstIP:   ip.DstIP.String(),
				DstPort: dstPort,

				Message: m.Message,
			})

			// 1回だけ出すフラグ
			if m.Type == "TLS_CLIENT_HELLO" {
				st.TLSReported = true
			}
			if m.Type == "INSECURE_HTTP" {
				st.HTTPReported = true
			}
		}
	}

	// cleanup
	if now.Unix()%10 == 0 {
		h.cache.Cleanup(now)
	}

	// payload debug（これは好み。残してOK）
	if h.debug && (isHTTPClientToServer || isTLSClientToServer) && len(tcp.Payload) > 0 {
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
			DstPort:   dstPort,
			Message:   fmt.Sprintf("payload_head=%q", string(p)),
		})
	}
}
