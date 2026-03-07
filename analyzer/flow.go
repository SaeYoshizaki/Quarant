package analyzer

import (
	"fmt"
	"time"

	"quarant/analyzer/device"
	"quarant/analyzer/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	sink    *JSONLSink
	cache   *FlowCache
	debug   bool
	devices *device.Store
}

func NewFlowHandler(sink *JSONLSink, debug bool) *FlowHandler {
	return &FlowHandler{
		sink:    sink,
		cache:   NewFlowCache(16*1024, 1*time.Hour),
		debug:   debug,
		devices: device.NewStore(),
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

	if (isHTTPClientToServer || isTLSClientToServer) && len(tcp.Payload) > 0 {
		h.cache.AppendUpToLimit(st, tcp.Payload)
	}

	if isHTTPClientToServer || isTLSClientToServer {
		var httpInfo *rules.HTTPInfo
		if rules.LooksLikeHTTP(st.Data) {
			if hi, ok := rules.ParseHTTP(st.Data); ok {
				httpInfo = hi
			}
		}
		if isTLSClientToServer {
			if tlsInfo, ok := rules.DetectTLSClientHello(st.Data); ok {
				d := h.devices.GetOrCreate(ip.SrcIP.String())
				device.EnrichFromTLS(d, tlsInfo)

				if h.debug {
					_ = h.sink.Write(Event{
						Timestamp: now,
						Type:      "DEVICE_DEBUG",
						Severity:  SeverityInfo,
						SrcIP:     ip.SrcIP.String(),
						Message: fmt.Sprintf(
							"device_type=%s vendor=%s model=%s confidence=%.2f ja3=%s evidence=%v",
							d.DeviceType,
							d.Vendor,
							d.Model,
							d.Confidence,
							d.JA3,
							d.Evidence,
						),
					})
				}
			}
		}

		if httpInfo != nil {
			d := h.devices.GetOrCreate(ip.SrcIP.String())
			device.EnrichFromHTTP(d, httpInfo.Headers)

			if h.debug {
				_ = h.sink.Write(Event{
					Timestamp: now,
					Type:      "DEVICE_DEBUG",
					Severity:  SeverityInfo,
					SrcIP:     ip.SrcIP.String(),
					Message: fmt.Sprintf(
						"device_type=%s vendor=%s model=%s confidence=%.2f evidence=%v",
						d.DeviceType,
						d.Vendor,
						d.Model,
						d.Confidence,
						d.Evidence,
					),
				})
			}
		}

		ctx := &rules.Context{
			NowUnix: now.Unix(),
			FlowKey: key,
			SrcIP:   ip.SrcIP.String(),
			SrcPort: uint16(tcp.SrcPort),
			DstIP:   ip.DstIP.String(),
			DstPort: dstPort,
			Payload: st.Data,
			Debug:   h.debug,
			HTTP:    httpInfo,
		}

		matches := rules.Run(ctx)

		for _, m := range matches {
			if m.RuleID != "" && st.Reported[m.RuleID] {
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

			if m.RuleID != "" {
				st.Reported[m.RuleID] = true
			}
		}
	}

	if now.Unix()%10 == 0 {
		h.cache.Cleanup(now)
	}

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
