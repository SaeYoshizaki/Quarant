package analyzer

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket/layers"

	"quarant/analyzer/behavior"
)

const (
	// behaviorEvalInterval is how often (in capture time) detectors run
	// during long or live captures; they always run once more on Flush.
	behaviorEvalInterval = 5 * time.Minute
	// maxDNSAnswers bounds the IP -> name map built from DNS responses.
	maxDNSAnswers = 100000
)

// observeDNSAnswers remembers which name a local device resolved to which
// address, so later connections can be labelled with the name and
// connections to never-resolved addresses can be told apart.
func (h *FlowHandler) observeDNSAnswers(dstIP string, dns *layers.DNS) {
	if dns == nil || !dns.QR || !h.isLocal(dstIP) {
		return
	}
	if h.dnsNames == nil {
		h.dnsNames = map[string]string{}
	}
	for _, rr := range dns.Answers {
		if rr.Type != layers.DNSTypeA && rr.Type != layers.DNSTypeAAAA || rr.IP == nil {
			continue
		}
		if len(h.dnsNames) >= maxDNSAnswers {
			return
		}
		h.dnsNames[rr.IP.String()] = strings.TrimSuffix(string(rr.Name), ".")
	}
}

// recordConnection hands a finished TCP flow to the behaviour analyzer.
func (h *FlowHandler) recordConnection(st *FlowState) {
	if st == nil || !h.isLocal(st.SrcIP) {
		return
	}
	if h.behavior == nil {
		h.behavior = behavior.New(behavior.DefaultConfig())
	}
	plaintext := (st.HTTPSeen || st.MQTTSeen || st.TelnetSeen) && !st.TLSClientSeen && !st.TLSServerSeen
	h.behavior.Add(behavior.Conn{
		Start:     st.FirstSeen,
		DeviceIP:  st.SrcIP,
		DstIP:     st.DstIP,
		DstPort:   st.DstPort,
		Proto:     "tcp",
		Answered:  st.ServerResponded,
		DstName:   h.dnsNames[st.DstIP],
		BytesOut:  st.ClientBytes,
		BytesIn:   st.ServerBytes,
		Plaintext: plaintext,
		DstLocal:  h.isLocal(st.DstIP),
	})
}

// evaluateBehavior runs the detectors and writes their findings as events.
func (h *FlowHandler) evaluateBehavior(now time.Time) {
	h.lastBehaviorEval = now
	if h.behavior == nil {
		return
	}
	for _, f := range h.behavior.Evaluate() {
		event := Event{
			Timestamp:      f.Last,
			Type:           f.Type,
			Severity:       Severity(f.Severity),
			RuleID:         f.Type,
			Category:       "BEHAVIOR",
			Confidence:     f.Confidence,
			Basis:          BasisInferred,
			Evidence:       fmt.Sprintf("%s first_seen=%s last_seen=%s", f.Evidence, f.First.UTC().Format(time.RFC3339), f.Last.UTC().Format(time.RFC3339)),
			ObservedFact:   f.ObservedFact,
			Inference:      f.Inference,
			Limitation:     f.Limitation,
			Recommendation: f.Recommend,
			DeviceKey:      f.DeviceIP,
			SrcIP:          f.DeviceIP,
			DstIP:          f.DstIP,
			DstPort:        f.DstPort,
			Message:        f.ObservedFact,
		}
		h.enrichEvent(&event)
		_ = h.eventSink.Write(event)
		if d := h.localDevice(f.DeviceIP); d != nil {
			d.RecordRiskEvent(f.Last, f.Type, f.Severity, nil)
		}
	}
}
