package analyzer

import (
	"fmt"
	"sort"
	"strings"
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
	a := flowEndpoint(ipSrc, srcPort)
	b := flowEndpoint(ipDst, dstPort)
	if a < b {
		return "tcp|" + a + "<->" + b
	}
	return "tcp|" + b + "<->" + a
}

func flowEndpoint(ip string, port uint16) string {
	if strings.Contains(ip, ":") {
		return fmt.Sprintf("[%s]:%d", ip, port)
	}
	return fmt.Sprintf("%s:%d", ip, port)
}

func packetIPStrings(packet gopacket.Packet) (string, string, bool) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String(), true
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String(), true
	}
	return "", "", false
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

	reasons := d.Classification.Reasons
	inferenceSource := string(d.Classification.InferenceSource)
	if inferenceSource == "" {
		inferenceSource = string(device.InferenceSourceUnknown)
	}
	inferredScores := d.Classification.Scores
	summary := deviceDebugSummary(d.Classification, d.DeviceType)
	detailReasons := humanizeReasons(reasons)
	identity := d.Identity

	_ = h.sink.Write(Event{
		Timestamp: now,
		Type:      "DEVICE_DEBUG",
		Severity:  SeverityInfo,
		SrcIP:     srcIP,
		Message: fmt.Sprintf(
			"summary=%q detail=%q identity_state=%s identity_category=%s identity_category_confidence=%s identity_vendor=%s identity_vendor_confidence=%s identity_family=%s identity_family_confidence=%s identity_reasons=%v identity_top_category_scores=%v identity_top_vendor_scores=%v identity_top_family_scores=%v device_type=%s vendor=%s model=%s category=%s inference_source=%s confidence=%s inference_reasons=%v inferred_scores=%v ja3=%s evidence=%v risk_score=%d observed=%v insecure=%v admin=%t external=%t reasons=%v",
			summary,
			fmt.Sprintf("category=%s source=%s confidence=%s reasons=%v", d.Classification.NormalizedCategory(), inferenceSource, d.Classification.ConfidenceSummary(), detailReasons),
			identityDebugState(identity),
			identity.CategoryCandidate,
			identity.CategoryConfidence,
			identity.VendorCandidate,
			identity.VendorConfidence,
			identity.FamilyCandidate,
			identity.FamilyConfidence,
			identityDebugReasons(identity),
			topScores(identity.CategoryScores, 3),
			topScores(identity.VendorScores, 3),
			topScores(identity.FamilyScores, 3),
			d.DeviceType,
			d.Vendor,
			d.Model,
			d.Classification.NormalizedCategory(),
			inferenceSource,
			d.Classification.ConfidenceSummary(),
			detailReasons,
			inferredScores,
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

func identityDebugState(identity device.DeviceIdentity) string {
	familyRank := debugConfidenceRank(identity.FamilyConfidence)
	vendorRank := debugConfidenceRank(identity.VendorConfidence)
	hasFamily := strings.TrimSpace(identity.FamilyCandidate) != ""
	hasVendor := strings.TrimSpace(identity.VendorCandidate) != ""
	switch {
	case hasFamily && familyRank >= debugConfidenceRank("medium"):
		return "concrete_family"
	case hasVendor && vendorRank >= debugConfidenceRank("medium"):
		return "vendor_without_concrete_family"
	case hasFamily:
		return "family_uncertain"
	default:
		return "identity_weak"
	}
}

func identityDebugReasons(identity device.DeviceIdentity) []string {
	reasons := []string{}
	reasons = append(reasons, limitPrefixedReasons("category", identity.CategoryReasons, 2)...)
	reasons = append(reasons, limitPrefixedReasons("vendor", identity.VendorReasons, 2)...)
	reasons = append(reasons, limitPrefixedReasons("family", identity.FamilyReasons, 3)...)
	return reasons
}

func limitPrefixedReasons(prefix string, reasons []string, limit int) []string {
	out := []string{}
	for _, reason := range reasons {
		if strings.TrimSpace(reason) == "" {
			continue
		}
		out = append(out, prefix+":"+reason)
		if len(out) >= limit {
			return out
		}
	}
	return out
}

func inferenceView(category, deviceType, source, confidence string, reasons []string) rules.InferenceView {
	return rules.InferenceView{
		Category:   category,
		DeviceType: deviceType,
		Source:     source,
		Confidence: confidence,
		Reasons:    reasons,
	}
}

func humanizeReasons(reasons []string) []string {
	if len(reasons) == 0 {
		return reasons
	}

	out := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		trimmed := strings.TrimSpace(reason)
		if trimmed == "" {
			continue
		}
		switch trimmed {
		case "insufficient_evidence":
			out = append(out, "no strong known match and inferred score below threshold")
		default:
			out = append(out, trimmed)
		}
	}
	return out
}

func compactClassification(category, source, confidence string) string {
	return fmt.Sprintf("%s(%s,%s)", category, source, confidence)
}

func topScores(scores map[string]float64, limit int) []string {
	if len(scores) == 0 || limit <= 0 {
		return nil
	}
	type scoreEntry struct {
		label string
		score float64
	}
	entries := make([]scoreEntry, 0, len(scores))
	for label, score := range scores {
		if score <= 0 {
			continue
		}
		entries = append(entries, scoreEntry{label: label, score: score})
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].score == entries[j].score {
			return entries[i].label < entries[j].label
		}
		return entries[i].score > entries[j].score
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		out = append(out, fmt.Sprintf("%s=%.2f", entry.label, entry.score))
	}
	return out
}

func debugConfidenceRank(label string) int {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "strong":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func classificationSourcePhrase(source string) string {
	switch source {
	case string(device.InferenceSourceKnown):
		return "known"
	case string(device.InferenceSourceInferred):
		return "inferred"
	default:
		return "unknown"
	}
}

func deviceDebugSummary(classification device.Classification, deviceType string) string {
	category := classification.NormalizedCategory()
	source := string(classification.InferenceSource)
	if source == "" {
		source = string(device.InferenceSourceUnknown)
	}

	switch source {
	case string(device.InferenceSourceKnown):
		if deviceType != "" {
			return fmt.Sprintf("known %s device classified as %s", deviceType, category)
		}
		return fmt.Sprintf("known device classified as %s", category)
	case string(device.InferenceSourceInferred):
		return fmt.Sprintf("inferred %s device from communication hints", category)
	default:
		return "unknown device with insufficient evidence"
	}
}

func i6DebugSummary(localCategory, flowCategory, ctxCategory, localSource, flowSource, ctxSource string) string {
	if localSource == string(device.InferenceSourceUnknown) &&
		flowSource == string(device.InferenceSourceUnknown) &&
		ctxSource == string(device.InferenceSourceUnknown) &&
		localCategory == "GenericIoT" &&
		flowCategory == "GenericIoT" &&
		ctxCategory == "GenericIoT" {
		return "unknown device with insufficient evidence"
	}

	if localCategory == flowCategory && flowCategory == ctxCategory {
		return fmt.Sprintf(
			"%s %s device, flow also classified as %s",
			classificationSourcePhrase(localSource),
			localCategory,
			flowCategory,
		)
	}

	return fmt.Sprintf(
		"%s %s device, flow classified as %s, ctx=%s",
		classificationSourcePhrase(localSource),
		localCategory,
		flowCategory,
		ctxCategory,
	)
}

func i6DebugDetail(localCategory, flowCategory, ctxCategory, localSource, flowSource, ctxSource, localConfidence, flowConfidence, ctxConfidence string, localReasons, flowReasons, ctxReasons []string) string {
	return fmt.Sprintf(
		"local=%s flow=%s ctx=%s local_reasons=%v flow_reasons=%v ctx_reasons=%v",
		compactClassification(localCategory, localSource, localConfidence),
		compactClassification(flowCategory, flowSource, flowConfidence),
		compactClassification(ctxCategory, ctxSource, ctxConfidence),
		humanizeReasons(localReasons),
		humanizeReasons(flowReasons),
		humanizeReasons(ctxReasons),
	)
}

func mapKeys(values map[string]bool) []string {
	if len(values) == 0 {
		return nil
	}

	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return keys
}

func i4UpdateVisibility(d *device.DeviceProfile) string {
	if d == nil {
		return "unknown"
	}

	observedMetadata := false
	for host := range d.Hosts {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication("", host, "") {
			return "seen"
		}
	}
	for path := range d.Paths {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication(path, "", "") {
			return "seen"
		}
	}
	for sni := range d.SNIValues {
		observedMetadata = true
		if rules.I4LooksLikeObservedUpdateCommunication("", "", sni) {
			return "seen"
		}
	}

	if !observedMetadata {
		return "unknown"
	}
	return "not_seen"
}

func i4LegacySignals(d *device.DeviceProfile) []string {
	if d == nil {
		return nil
	}

	signals := make([]string, 0, 5)
	if d.InsecureServices["telnet"] {
		signals = append(signals, "telnet_observed")
	}
	if d.InsecureServices["ftp"] {
		signals = append(signals, "ftp_observed")
	}
	if d.AdminSuspected {
		signals = append(signals, "admin_interface")
	}
	if d.ExternalExposureSuspected {
		signals = append(signals, "external_exposure")
	}
	if d.Protocols["http"] && !d.Protocols["https"] && !d.Protocols["tls"] {
		signals = append(signals, "http_only_management")
	}

	return signals
}

func (h *FlowHandler) HandlePacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	srcIP, dstIP, ok := packetIPStrings(packet)
	if !ok || tcpLayer == nil {
		return
	}

	tcp := tcpLayer.(*layers.TCP)
	now := time.Now()

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
	isTelnetClientToServer := rules.IsTelnetPort(dstPort)
	isMQTTClientToServer := rules.IsMQTTPort(dstPort)
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

	var mqttInfo *rules.MQTTInfo
	if isMQTTClientToServer {
		if mi, ok := rules.ParseMQTT(st.ClientData); ok {
			mqttInfo = mi
		}
	}

	var telnetInfo *rules.TelnetInfo
	if isTelnetClientToServer {
		if ti, ok := rules.ParseTelnet(st.ClientData, st.ServerData); ok {
			telnetInfo = ti
		}
	}

	if isTLSClientToServer && !st.TLSClientSeen {
		if tlsInfo, ok := rules.DetectTLSClientHello(st.ClientData); ok {
			st.TLSClientSeen = true
			st.TLSClientInfo = &tlsInfo

			d := h.devices.GetOrCreate(srcIP)
			device.EnrichFromTLS(d, tlsInfo)
			device.AddTLSBehaviorHints(d, dstPort)
			h.writeDeviceDebug(now, srcIP, d)
		}
	}

	if httpInfo != nil {
		d := h.devices.GetOrCreate(srcIP)
		device.EnrichFromHTTP(d, httpInfo.Headers)
		device.AddHTTPBehaviorHints(d, httpInfo, dstPort, isTLSClientToServer)
		h.writeDeviceDebug(now, srcIP, d)
	}

	d := h.devices.GetOrCreate(srcIP)
	localClassification := d.Classification
	localDeviceCategory := localClassification.NormalizedCategory()
	localInferenceSource := string(localClassification.InferenceSource)
	if localInferenceSource == "" {
		localInferenceSource = string(device.InferenceSourceUnknown)
	}
	localInferenceConfidence := localClassification.ConfidenceSummary()
	localInferenceReasons := localClassification.Reasons

	flowClassification := device.Classification{
		Category:        "GenericIoT",
		InferenceSource: device.InferenceSourceUnknown,
		ConfidenceLabel: "very_low",
		Reasons:         []string{"insufficient_evidence"},
	}
	if httpInfo != nil {
		flowProfile := device.InferFlowFromHTTP(httpInfo.Headers)
		device.AddHTTPBehaviorHints(flowProfile, httpInfo, dstPort, isTLSClientToServer)
		flowClassification = flowProfile.Classification
	} else if st.TLSClientSeen && st.TLSClientInfo != nil {
		flowProfile := device.InferFlowFromTLS(*st.TLSClientInfo)
		device.AddTLSBehaviorHints(flowProfile, dstPort)
		flowClassification = flowProfile.Classification
	}
	flowDeviceCategory := flowClassification.NormalizedCategory()
	flowDeviceType := flowClassification.DeviceType
	flowInferenceSource := string(flowClassification.InferenceSource)
	if flowInferenceSource == "" {
		flowInferenceSource = string(device.InferenceSourceUnknown)
	}
	flowInferenceConfidence := flowClassification.ConfidenceSummary()
	flowInferenceReasons := flowClassification.Reasons

	deviceCategory := flowDeviceCategory
	if deviceCategory == "GenericIoT" {
		deviceCategory = localDeviceCategory
	}
	deviceInferenceSource := flowInferenceSource
	deviceInferenceConfidence := flowInferenceConfidence
	deviceInferenceReasons := flowInferenceReasons
	if deviceCategory == localDeviceCategory && flowDeviceCategory == "GenericIoT" {
		deviceInferenceSource = localInferenceSource
		deviceInferenceConfidence = localInferenceConfidence
		deviceInferenceReasons = localInferenceReasons
	}

	ctx := &rules.Context{
		NowUnix:                   now.Unix(),
		FlowKey:                   key,
		SrcIP:                     srcIP,
		SrcPort:                   srcPort,
		DstIP:                     dstIP,
		DstPort:                   dstPort,
		Payload:                   st.ClientData,
		ServerPayload:             st.ServerData,
		Debug:                     h.debug,
		UploadBytes:               estimateUploadBytes(httpInfo),
		HTTP:                      httpInfo,
		MQTT:                      mqttInfo,
		Telnet:                    telnetInfo,
		TLS:                       isTLSClientToServer,
		TLSInfo:                   st.TLSClientInfo,
		TLSServerInfo:             st.TLSServerInfo,
		DeviceCategory:            deviceCategory,
		LocalDeviceCategory:       localDeviceCategory,
		FlowDeviceCategory:        flowDeviceCategory,
		CategoryCandidate:         d.Identity.CategoryCandidate,
		VendorCandidate:           d.Identity.VendorCandidate,
		FamilyCandidate:           d.Identity.FamilyCandidate,
		CategoryConfidence:        d.Identity.CategoryConfidence,
		VendorConfidence:          d.Identity.VendorConfidence,
		FamilyConfidence:          d.Identity.FamilyConfidence,
		CategoryReasons:           d.Identity.CategoryReasons,
		VendorReasons:             d.Identity.VendorReasons,
		FamilyReasons:             d.Identity.FamilyReasons,
		ObservedHosts:             mapKeys(d.Hosts),
		ObservedUserAgents:        mapKeys(d.UserAgents),
		ObservedSNIValues:         mapKeys(d.SNIValues),
		UpdateVisibility:          i4UpdateVisibility(d),
		LegacySignals:             i4LegacySignals(d),
		DeviceInferenceSource:     deviceInferenceSource,
		LocalInferenceSource:      localInferenceSource,
		FlowInferenceSource:       flowInferenceSource,
		DeviceInferenceConfidence: deviceInferenceConfidence,
		LocalInferenceConfidence:  localInferenceConfidence,
		FlowInferenceConfidence:   flowInferenceConfidence,
		DeviceInferenceReasons:    deviceInferenceReasons,
		LocalInferenceReasons:     localInferenceReasons,
		FlowInferenceReasons:      flowInferenceReasons,
		ContextClassification: inferenceView(
			deviceCategory,
			func() string {
				if deviceCategory == localDeviceCategory && flowDeviceCategory == "GenericIoT" {
					return d.DeviceType
				}
				return flowDeviceType
			}(),
			deviceInferenceSource,
			deviceInferenceConfidence,
			deviceInferenceReasons,
		),
		LocalClassification: inferenceView(
			localDeviceCategory,
			d.DeviceType,
			localInferenceSource,
			localInferenceConfidence,
			localInferenceReasons,
		),
		FlowClassification: inferenceView(
			flowDeviceCategory,
			flowDeviceType,
			flowInferenceSource,
			flowInferenceConfidence,
			flowInferenceReasons,
		),
	}
	h.annotateI6StorageObservation(ctx, d)
	h.annotateI6PIIUseObservation(ctx, d)

	if h.debug {
		summary := i6DebugSummary(
			localDeviceCategory,
			flowDeviceCategory,
			ctx.DeviceCategory,
			localInferenceSource,
			flowInferenceSource,
			deviceInferenceSource,
		)
		detail := i6DebugDetail(
			localDeviceCategory,
			flowDeviceCategory,
			ctx.DeviceCategory,
			localInferenceSource,
			flowInferenceSource,
			deviceInferenceSource,
			localInferenceConfidence,
			flowInferenceConfidence,
			deviceInferenceConfidence,
			localInferenceReasons,
			flowInferenceReasons,
			deviceInferenceReasons,
		)

		_ = h.sink.Write(Event{
			Timestamp: now,
			Type:      "I6_DEBUG",
			Severity:  SeverityInfo,
			SrcIP:     srcIP,
			SrcPort:   srcPort,
			DstIP:     dstIP,
			DstPort:   dstPort,
			Message: fmt.Sprintf(
				"summary=%q detail=%q local_device_category=%q flow_device_category=%q ctx_device_category=%q local_device_type=%q flow_device_type=%q local_inference_source=%q flow_inference_source=%q ctx_inference_source=%q local_confidence=%q flow_confidence=%q ctx_confidence=%q local_reasons=%v flow_reasons=%v ctx_reasons=%v local_classification=%+v flow_classification=%+v ctx_classification=%+v",
				summary,
				detail,
				localDeviceCategory,
				flowDeviceCategory,
				ctx.DeviceCategory,
				d.DeviceType,
				flowDeviceType,
				localInferenceSource,
				flowInferenceSource,
				deviceInferenceSource,
				localInferenceConfidence,
				flowInferenceConfidence,
				deviceInferenceConfidence,
				humanizeReasons(localInferenceReasons),
				humanizeReasons(flowInferenceReasons),
				humanizeReasons(deviceInferenceReasons),
				ctx.LocalClassification,
				ctx.FlowClassification,
				ctx.ContextClassification,
			),
		})
	}

	matches := rules.Run(ctx)

	if h.knowledge != nil {
		i6Rule := rules.NewI6PrivacyRule(h.knowledge)
		if i6Matches := i6Rule.ApplyAll(ctx); len(i6Matches) > 0 {
			matches = append(matches, i6Matches...)
		}

		i4EnrichmentRule := rules.NewI4FirmwareRiskEnrichmentRule(h.knowledge)
		if i4Matches := i4EnrichmentRule.ApplyAll(ctx); len(i4Matches) > 0 {
			matches = append(matches, i4Matches...)
		}

		i4EOLRule := rules.NewI4EOLReviewRule(h.knowledge)
		if i4Matches := i4EOLRule.ApplyAll(ctx); len(i4Matches) > 0 {
			matches = append(matches, i4Matches...)
		}

		i5Rule := rules.NewI5KnownVulnerableComponentRule(h.knowledge)
		if i5Matches := i5Rule.ApplyAll(ctx); len(i5Matches) > 0 {
			matches = append(matches, i5Matches...)
		}

		if !st.AlreadyReported(rules.I4I5CombinedRiskRuleID) {
			i4I5Rule := rules.NewI4I5CombinedRiskRule(h.knowledge)
			if i4I5Match, ok := i4I5Rule.Apply(ctx); ok {
				matches = append(matches, i4I5Match)
			}
		}
	}

	if composite := buildCompositeRiskMatch(ctx, matches); composite != nil {
		matches = append(matches, *composite)
	}

	for _, m := range matches {
		if st.AlreadyReported(m.RuleID) {
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

		st.MarkReported(m.RuleID)
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

func (h *FlowHandler) annotateI6StorageObservation(ctx *rules.Context, d *device.DeviceProfile) {
	if h == nil || h.knowledge == nil || h.knowledge.I6StorageSignals == nil || ctx == nil || d == nil || ctx.HTTP == nil {
		return
	}

	if endpointKey := rules.I6StorageCandidateEndpointKey(ctx, h.knowledge.I6StorageSignals.Patterns); endpointKey != "" {
		ctx.StorageEndpointRepeatCount = d.ObserveStorageSignalEndpoint(endpointKey, ctx.NowUnix)
	}

	for _, fingerprint := range rules.StableIdentifierFingerprints(ctx.HTTP) {
		count := d.ObserveStableIdentifierFingerprint(fingerprint, ctx.NowUnix)
		if count > ctx.StableIdentifierRepeatCount {
			ctx.StableIdentifierRepeatCount = count
		}
	}
}

func (h *FlowHandler) annotateI6PIIUseObservation(ctx *rules.Context, d *device.DeviceProfile) {
	if ctx == nil || d == nil || ctx.HTTP == nil {
		return
	}
	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	if host == "" {
		return
	}
	hits := rules.DetectPIIHits(ctx.HTTP, ctx.Payload)
	for _, piiType := range rules.PIIHitTypes(hits) {
		repeat, distinct := d.ObservePIIUseDestination(piiType, host, ctx.NowUnix)
		if repeat > ctx.PIIDestinationRepeatCount {
			ctx.PIIDestinationRepeatCount = repeat
		}
		if distinct > ctx.PIIDistinctDestinationCount {
			ctx.PIIDistinctDestinationCount = distinct
		}
	}
}

func estimateUploadBytes(httpInfo *rules.HTTPInfo) int {
	if httpInfo == nil {
		return 0
	}
	if v := strings.TrimSpace(httpInfo.Headers["content-length"]); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return len(httpInfo.Body)
}
