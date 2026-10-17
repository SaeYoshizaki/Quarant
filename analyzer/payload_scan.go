package analyzer

import (
	"fmt"
	"strings"
	"time"

	"quarant/analyzer/rules"
)

// Protocol-independent payload checks (D23). Quarant parses HTTP, MQTT and
// Telnet, but E11 found a camera receiving a cleartext login over a UDP P2P
// protocol and another sending JPEGs inside a proprietary TCP protocol.
// These checks read single packets and report only names, never values.

// payloadScanKey de-duplicates findings per device, peer and port.
func payloadScanKey(kind, device, peer string, port uint16) string {
	return fmt.Sprintf("%s|%s|%s|%d", kind, device, peer, port)
}

func (h *FlowHandler) reportOnce(key string) bool {
	if h.payloadReported == nil {
		h.payloadReported = map[string]bool{}
	}
	if h.payloadReported[key] {
		return false
	}
	h.payloadReported[key] = true
	return true
}

// scanUDPCredentials reports a password or token in a printable key=value
// list carried by UDP. The finding goes to the local device that receives
// it (its interface takes the credential); a local sender talking to a
// remote peer is the device that sends its own.
func (h *FlowHandler) scanUDPCredentials(now time.Time, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	if len(payload) < 12 || srcPort == 53 || dstPort == 53 || srcPort == 5353 || dstPort == 5353 {
		return
	}
	keys, ok := rules.DetectCleartextCredentialPairs(payload)
	if !ok {
		return
	}
	device, peer, port := dstIP, srcIP, dstPort
	if !h.isLocal(dstIP) {
		device, peer, port = srcIP, dstIP, dstPort
	}
	if !h.isLocal(device) || !h.reportOnce(payloadScanKey("udp_cred", device, peer, port)) {
		return
	}
	event := Event{
		Timestamp:      now,
		Type:           "INSECURE_UDP_CREDENTIALS",
		Severity:       SeverityCritical,
		RuleID:         "I7_UDP_CREDENTIALS",
		Category:       "I7",
		Confidence:     "medium",
		DeviceKey:      device,
		SrcIP:          srcIP,
		SrcPort:        srcPort,
		DstIP:          dstIP,
		DstPort:        dstPort,
		Evidence:       fmt.Sprintf("transport=udp keys=%s values=***", strings.Join(keys, ",")),
		ObservedFact:   "A UDP packet carried a printable key=value list with a password or token key and a non-empty value, without encryption.",
		Inference:      "Credentials may cross the network in cleartext (for example a camera's P2P login from its app).",
		Limitation:     "Only single packets are examined and the protocol is not parsed; the value is not checked, so it may be a placeholder or already hashed.",
		Recommendation: "Check whether the device or its app offers an encrypted connection, and change the password if it may have been exposed.",
		Message:        "Cleartext credential fields were observed in UDP traffic.",
	}
	h.enrichEvent(&event)
	_ = h.eventSink.Write(event)
}

// scanTCPMedia reports an image signature in a cleartext TCP payload that a
// local device sends to a public address, outside HTTP (which
// I6_MEDIA_UPLOAD_CLEARTEXT covers) and outside TLS.
func (h *FlowHandler) scanTCPMedia(now time.Time, st *FlowState, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	if st == nil || len(payload) < 11 || !h.isLocal(srcIP) || !rules.IsPublicIP(dstIP) {
		return
	}
	if st.TLSByContent || st.TLSClientSeen || rules.IsTLSPort(dstPort) || rules.IsTLSPort(srcPort) ||
		rules.IsHTTPPort(dstPort) || rules.IsHTTPPort(srcPort) || st.HTTPContent {
		return
	}
	kind, off, ok := rules.FindMediaSignature(payload)
	if !ok || !h.reportOnce(payloadScanKey("tcp_media", srcIP, dstIP, dstPort)) {
		return
	}
	event := Event{
		Timestamp:      now,
		Type:           "I6_MEDIA_UPLOAD_CLEARTEXT",
		Severity:       SeverityHigh,
		RuleID:         "I6_MEDIA_CLEARTEXT_TCP",
		Category:       "I6",
		Confidence:     "medium",
		DeviceKey:      srcIP,
		SrcIP:          srcIP,
		SrcPort:        srcPort,
		DstIP:          dstIP,
		DstPort:        dstPort,
		Evidence:       fmt.Sprintf("protocol=unparsed_tcp content_magic=%s offset=%d", kind, off),
		ObservedFact:   "A device sent a TCP payload containing an image file signature to a public address, outside HTTP and TLS.",
		Inference:      "Camera snapshots or other images may be readable by anyone on the network path.",
		Limitation:     "The protocol is not parsed and the image is not inspected or stored; whether it shows people or the home, or is protected inside the protocol, is not known.",
		Recommendation: "Check whether the device or its app offers encrypted upload, and whether cloud upload can be disabled.",
		Message:        "An image was sent to a remote service in cleartext over a non-HTTP protocol.",
	}
	h.enrichEvent(&event)
	_ = h.eventSink.Write(event)
}
