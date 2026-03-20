package analyzer

import (
	"fmt"
	"time"

	"quarant/analyzer/device"
	"quarant/analyzer/knowledge"
	"quarant/analyzer/rules"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FlowHandler struct {
	sink      *JSONLSink
	cache     *FlowCache
	debug     bool
	devices   *device.Store
	knowledge *knowledge.DB
}

func NewFlowHandler(sink *JSONLSink, debug bool, db *knowledge.DB) *FlowHandler {
	return &FlowHandler{
		sink:      sink,
		cache:     NewFlowCache(16*1024, 1*time.Hour),
		debug:     debug,
		devices:   device.NewStore(),
		knowledge: db,
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

func isI2RiskEvent(eventType string) bool {
	switch eventType {
	case "I2_TELNET_SERVICE_OBSERVED",
		"I2_FTP_SERVICE_OBSERVED",
		"I2_RTSP_SERVICE_OBSERVED",
		"I2_MQTT_SERVICE_OBSERVED",
		"I2_COAP_SERVICE_OBSERVED",
		"I2_TELNET_PROTOCOL_EVIDENCE",
		"I2_FTP_PROTOCOL_EVIDENCE",
		"I2_RTSP_PROTOCOL_EVIDENCE",
		"I2_MQTT_PROTOCOL_EVIDENCE",
		"I2_HTTP_ADMIN_INTERFACE_SUSPECTED",
		"I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK",
		"I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED":
		return true
	default:
		return false
	}
}

func (h *FlowHandler) updateDeviceRiskFromMatch(srcIP string, m rules.Match) {
	d := h.devices.GetOrCreate(srcIP)

	switch m.Type {
	case "I2_TELNET_SERVICE_OBSERVED", "I2_TELNET_PROTOCOL_EVIDENCE":
		d.AddObservedService("telnet")
		d.AddInsecureService("telnet")
		d.AddRiskReason("telnet observed")

	case "I2_FTP_SERVICE_OBSERVED", "I2_FTP_PROTOCOL_EVIDENCE":
		d.AddObservedService("ftp")
		d.AddInsecureService("ftp")
		d.AddRiskReason("ftp observed")

	case "I2_RTSP_SERVICE_OBSERVED", "I2_RTSP_PROTOCOL_EVIDENCE":
		d.AddObservedService("rtsp")
		d.AddInsecureService("rtsp")
		d.AddRiskReason("rtsp observed")

	case "I2_MQTT_SERVICE_OBSERVED", "I2_MQTT_PROTOCOL_EVIDENCE":
		d.AddObservedService("mqtt")
		d.AddInsecureService("mqtt")
		d.AddRiskReason("mqtt observed")

	case "I2_COAP_SERVICE_OBSERVED":
		d.AddObservedService("coap")
		d.AddInsecureService("coap")
		d.AddRiskReason("coap observed")

	case "I2_HTTP_ADMIN_INTERFACE_SUSPECTED":
		d.AddObservedService("http")
		d.MarkAdminSuspected()
		d.AddRiskReason("http admin interface suspected")

	case "I2_INSECURE_SERVICE_TO_PUBLIC_NETWORK":
		d.MarkExternalExposure()
		d.AddRiskReason("insecure service toward public network")

	case "I2_HTTP_ADMIN_EXTERNAL_ACCESS_SUSPECTED":
		d.AddObservedService("http")
		d.MarkAdminSuspected()
		d.MarkExternalExposure()
		d.AddRiskReason("http admin interface over public network")
	}

	d.RecalculateRiskScore()
}

func (h *FlowHandler) writeDeviceDebug(now time.Time, srcIP string, d *device.DeviceProfile) {
	if !h.debug {
		return
	}

	_ = h.sink.Write(Event{
		Timestamp: now,
		Type:      "DEVICE_DEBUG",
		Severity:  SeverityInfo,
		SrcIP:     srcIP,
		Message: fmt.Sprintf(
			"device_type=%s vendor=%s model=%s confidence=%.2f ja3=%s evidence=%v risk_score=%d observed=%v insecure=%v admin=%t external=%t reasons=%v",
			d.DeviceType,
			d.Vendor,
			d.Model,
			d.Confidence,
			d.JA3,
			d.Evidence,
			d.RiskScore,
			d.ObservedServices,
			d.InsecureServices,
			d.AdminSuspected,
			d.ExternalExposureSuspected,
			d.RiskReasons,
		),
	})
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

	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	key := flowKeyTCP(srcIP, srcPort, dstIP, dstPort)
	st := h.cache.GetOrCreate(key, now)
	if st.DstIP == "" {
		st.DstIP = dstIP
		st.DstPort = dstPort
	}

	capturePayload := rules.NeedsPayloadCapture(dstPort) || rules.NeedsPayloadCapture(srcPort)
	isHTTPClientToServer := rules.IsHTTPPort(dstPort)
	isTLSClientToServer := rules.IsTLSPort(dstPort)
	isTLSServerToClient := rules.IsTLSPort(srcPort)

	if len(tcp.Payload) > 0 {
		if rules.NeedsPayloadCapture(dstPort) {
			h.cache.AppendClientUpToLimit(st, tcp.Payload)
		}
		if rules.NeedsPayloadCapture(srcPort) {
			h.cache.AppendServerUpToLimit(st, tcp.Payload)
		}
	}

	if isTLSServerToClient && !st.TLSServerSeen {
		if serverInfo, ok := rules.DetectTLSServerHello(st.ServerData); ok {
			st.TLSServerSeen = true
			st.TLSServerInfo = serverInfo

			if h.debug {
				msg := fmt.Sprintf(
					"tls_server version=0x%04x cipher=0x%04x",
					serverInfo.ServerVersion,
					serverInfo.SelectedCipher,
				)

				if serverInfo.Cert != nil {
					msg += fmt.Sprintf(
						" subject=%q issuer=%q sans=%v self_signed=%t",
						serverInfo.Cert.Subject,
						serverInfo.Cert.Issuer,
						serverInfo.Cert.SANs,
						serverInfo.Cert.SelfSigned,
					)
				} else {
					msg += " cert=nil"
				}

				_ = h.sink.Write(Event{
					Timestamp: now,
					Type:      "TLS_SERVER_DEBUG",
					Severity:  SeverityInfo,
					SrcIP:     srcIP,
					SrcPort:   srcPort,
					DstIP:     dstIP,
					DstPort:   dstPort,
					Message:   msg,
				})
			}
		}
	}

	var httpInfo *rules.HTTPInfo
	if isHTTPClientToServer && rules.LooksLikeHTTP(st.ClientData) {
		if hi, ok := rules.ParseHTTP(st.ClientData); ok {
			httpInfo = hi
		}
	}

	if isTLSClientToServer && !st.TLSClientSeen {
		if tlsInfo, ok := rules.DetectTLSClientHello(st.ClientData); ok {
			st.TLSClientSeen = true
			st.TLSClientInfo = &tlsInfo

			d := h.devices.GetOrCreate(srcIP)
			device.EnrichFromTLS(d, tlsInfo)
			h.writeDeviceDebug(now, srcIP, d)
		}
	}

	if httpInfo != nil {
		d := h.devices.GetOrCreate(srcIP)
		device.EnrichFromHTTP(d, httpInfo.Headers)
		h.writeDeviceDebug(now, srcIP, d)
	}

	d := h.devices.GetOrCreate(srcIP)

	deviceCategory := rules.MapDeviceTypeToCategory(d.DeviceType)
	if deviceCategory == "Unknown" {
		deviceCategory = "GenericIoT"
	}

	ctx := &rules.Context{
		NowUnix:        now.Unix(),
		FlowKey:        key,
		SrcIP:          srcIP,
		SrcPort:        srcPort,
		DstIP:          dstIP,
		DstPort:        dstPort,
		Payload:        st.ClientData,
		Debug:          h.debug,
		HTTP:           httpInfo,
		TLS:            isTLSClientToServer,
		DeviceCategory: deviceCategory,
	}

	if h.debug {
		_ = h.sink.Write(Event{
			Timestamp: now,
			Type:      "I6_DEBUG",
			Severity:  SeverityInfo,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Message: fmt.Sprintf(
				"local_device_category=%q ctx_device_category=%q device_type=%q",
				deviceCategory,
				ctx.DeviceCategory,
				h.devices.GetOrCreate(srcIP).DeviceType,
			),
		})
	}

	matches := rules.Run(ctx)

	if h.knowledge != nil {
		i6Rule := rules.NewI6PrivacyRule(h.knowledge)
		if m, ok := i6Rule.Apply(ctx); ok {
			matches = append(matches, m)
		}
	}

	for _, m := range matches {
		if m.RuleID != "" && st.Reported[m.RuleID] {
			continue
		}

		_ = h.sink.Write(Event{
			Timestamp: now,
			Type:      m.Type,
			Severity:  Severity(m.Severity),
			RuleID:    m.RuleID,
			Category:  m.Category,
			FlowKey:   key,
			Evidence:  m.Evidence,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Message:   m.Message,
		})

		if isI2RiskEvent(m.Type) {
			h.updateDeviceRiskFromMatch(srcIP, m)
			h.writeDeviceDebug(now, srcIP, h.devices.GetOrCreate(srcIP))
		}

		if m.RuleID != "" {
			st.Reported[m.RuleID] = true
		}
	}

	if now.Unix()%10 == 0 {
		h.cache.Cleanup(now)
	}

	if h.debug && capturePayload && len(tcp.Payload) > 0 {
		p := tcp.Payload
		if len(p) > 256 {
			p = p[:256]
		}
		_ = h.sink.Write(Event{
			Timestamp: now,
			Type:      "PAYLOAD_DEBUG",
			Severity:  SeverityInfo,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Message:   fmt.Sprintf("payload_head=%q", string(p)),
		})
	}
}
