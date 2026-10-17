package parserdiff

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"quarant/analyzer/rules"
)

// maxHelloBytes mirrors Quarant's per-flow payload buffer.
const maxHelloBytes = 16 * 1024

// Report holds the differential results for every protocol over one capture.
type Report struct {
	Packets int        `json:"packets"`
	TLS     TLSReport  `json:"tls"`
	HTTP    HTTPReport `json:"http"`
	MQTT    MQTTReport `json:"mqtt"`
}

// TLSReport summarises differential parsing over all TLS-looking client
// streams of a capture.
type TLSReport struct {
	Packets int `json:"packets"`
	// Streams whose first client payload byte is 0x16 (TLS handshake).
	TLSStreams int            `json:"tls_streams"`
	Classes    map[string]int `json:"classes"`
	// FieldMismatches counts mismatching fields across field_mismatch cases.
	FieldMismatches map[string]int `json:"field_mismatches,omitempty"`
	// MultiSegment: the ClientHello spans more than one TCP segment.
	MultiSegment int `json:"hello_spans_multiple_segments"`
	// OrderSensitive: concatenating segments in arrival order gives a
	// different result than sequence order.
	OrderSensitive int `json:"arrival_order_changes_result"`
	// NonTLSPort: valid ClientHellos on ports the analyzer does not treat as
	// TLS (rules.IsTLSPort).
	NonTLSPort      int            `json:"hellos_on_unparsed_ports"`
	NonTLSPortPorts map[uint16]int `json:"unparsed_ports,omitempty"`
	Examples        []Example      `json:"examples,omitempty"`
}

// MQTTReport summarises the MQTT differential over client streams.
type MQTTReport struct {
	Streams         int            `json:"mqtt_streams"`
	Classes         map[string]int `json:"classes"`
	FieldMismatches map[string]int `json:"field_mismatches,omitempty"`
	RefReasons      map[string]int `json:"reference_reject_reasons,omitempty"`
	MultiSegment    int            `json:"streams_with_multiple_segments"`
	OrderSensitive  int            `json:"arrival_order_changes_result"`
	Retransmitted   int            `json:"streams_with_retransmitted_segments"`
	// ArrivalBytesDiffer: as in HTTPReport.
	ArrivalBytesDiffer int `json:"arrival_bytes_differ"`
	// NonMQTTPort: streams the reference decodes as MQTT on ports other than
	// 1883, which the analyzer never parses as MQTT.
	NonMQTTPort      int            `json:"mqtt_on_unparsed_ports"`
	NonMQTTPortPorts map[uint16]int `json:"unparsed_ports,omitempty"`
	Examples         []Example      `json:"examples,omitempty"`
}

// Example records one disagreement for manual review (no payload bytes).
type Example struct {
	Flow   string `json:"flow"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
}

type streamKind int

const (
	kindOther streamKind = iota
	kindTLS
	kindHTTP
	kindMQTT
)

type stream struct {
	key           string
	dstPort       uint16
	kind          streamKind
	baseSeq       uint32
	segments      map[uint32][]byte
	arrival       []byte
	collected     int
	retransmitted bool
	done          bool
}

// classify decides from the first client payload which differential a
// stream goes to. TLS and HTTP are recognised by content on any port (HTTP
// results are split by port in the report). MQTT is taken on its port and,
// elsewhere, when the first byte is a CONNECT header.
func classify(first []byte, dstPort uint16) streamKind {
	switch {
	case len(first) > 0 && first[0] == 22:
		return kindTLS
	case rules.LooksLikeHTTP(first) || requestLineShape(first):
		return kindHTTP
	case rules.IsMQTTPort(dstPort):
		return kindMQTT
	case len(first) >= 2 && first[0] == 0x10:
		return kindMQTT
	}
	return kindOther
}

// requestLineShape reports whether the first line looks like
// "METHOD target HTTP/1.x", so that requests with methods outside the
// analyzer's list (SUBSCRIBE, NOTIFY, ...) reach the differential too.
func requestLineShape(b []byte) bool {
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	line = bytes.TrimRight(line, "\r")
	sp := bytes.IndexByte(line, ' ')
	if sp <= 0 {
		return false
	}
	for _, c := range line[:sp] {
		upper := c >= 'A' && c <= 'Z'
		if !upper && c != '-' && c != '_' {
			return false
		}
	}
	return bytes.HasSuffix(line, []byte(" HTTP/1.1")) || bytes.HasSuffix(line, []byte(" HTTP/1.0"))
}

// AnalyzePCAP runs the TLS differential over every client stream in path.
func AnalyzePCAP(path string) (TLSReport, error) {
	rep, err := AnalyzePCAPAll(path)
	return rep.TLS, err
}

// AnalyzePCAPAll runs the TLS, HTTP and MQTT differentials over every client
// stream in path. Streams are rebuilt in sequence order (dropping
// retransmitted overlap) for the comparison, and also in arrival order to
// count streams whose result depends on how segments are assembled.
func AnalyzePCAPAll(path string) (Report, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return Report{}, err
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.Lazy, src.NoCopy = true, true

	rep := Report{
		TLS:  TLSReport{Classes: map[string]int{}, FieldMismatches: map[string]int{}, NonTLSPortPorts: map[uint16]int{}},
		HTTP: HTTPReport{Classes: map[string]int{}, FieldMismatches: map[string]int{}, Leniency: map[string]int{}, GatedMethods: map[string]int{}, NonHTTPPortPorts: map[uint16]int{}, NonHTTPPortMethods: map[string]int{}},
		MQTT: MQTTReport{Classes: map[string]int{}, FieldMismatches: map[string]int{}, RefReasons: map[string]int{}, NonMQTTPortPorts: map[uint16]int{}},
	}
	streams := map[string]*stream{}
	for {
		p, err := src.NextPacket()
		if err != nil {
			if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) || rep.Packets > 0 {
				break
			}
			return rep, err
		}
		rep.Packets++
		tcpL := p.Layer(layers.LayerTypeTCP)
		if tcpL == nil {
			continue
		}
		tcp := tcpL.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}
		var srcIP, dstIP string
		if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
			srcIP, dstIP = ip4.SrcIP.String(), ip4.DstIP.String()
		} else if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
			srcIP, dstIP = ip6.SrcIP.String(), ip6.DstIP.String()
		} else {
			continue
		}
		fwd := fmt.Sprintf("%s:%d>%s:%d", srcIP, tcp.SrcPort, dstIP, tcp.DstPort)
		rev := fmt.Sprintf("%s:%d>%s:%d", dstIP, tcp.DstPort, srcIP, tcp.SrcPort)
		if _, ok := streams[rev]; ok {
			continue // server-to-client data of a known stream
		}
		st, ok := streams[fwd]
		if !ok {
			// The first side to send payload is treated as the client.
			st = &stream{key: fwd, dstPort: uint16(tcp.DstPort), baseSeq: tcp.Seq, segments: map[uint32][]byte{}, kind: classify(tcp.Payload, uint16(tcp.DstPort))}
			streams[fwd] = st
		}
		if st.done || st.kind == kindOther || st.collected >= maxHelloBytes {
			continue
		}
		payload := append([]byte(nil), tcp.Payload...)
		st.arrival = append(st.arrival, payload...)
		if st.overlaps(tcp.Seq, len(payload)) {
			st.retransmitted = true
		}
		if prev, dup := st.segments[tcp.Seq]; !dup || len(payload) > len(prev) {
			st.segments[tcp.Seq] = payload
		}
		st.collected += len(payload)
		if st.kind == kindTLS && helloComplete(st.ordered()) {
			finish(&rep, st)
		}
	}
	keys := make([]string, 0, len(streams))
	for k := range streams {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic example selection
	for _, k := range keys {
		if st := streams[k]; st.kind != kindOther && !st.done {
			finish(&rep, st)
		}
	}
	rep.TLS.Packets = rep.Packets
	return rep, nil
}

// overlaps reports whether a segment at seq re-sends bytes already held.
func (s *stream) overlaps(seq uint32, n int) bool {
	start := seq - s.baseSeq
	for q, seg := range s.segments {
		o := q - s.baseSeq
		if start < o+uint32(len(seg)) && o < start+uint32(n) {
			return true
		}
	}
	return false
}

// ordered concatenates segments by sequence number from the stream start,
// dropping retransmitted overlap.
func (s *stream) ordered() []byte {
	seqs := make([]uint32, 0, len(s.segments))
	for q := range s.segments {
		seqs = append(seqs, q)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i]-s.baseSeq < seqs[j]-s.baseSeq })
	var out []byte
	for _, q := range seqs {
		off := int(q - s.baseSeq)
		seg := s.segments[q]
		if off > len(out) {
			break // gap: missing segment
		}
		if off+len(seg) > len(out) {
			out = append(out, seg[len(out)-off:]...)
		}
		if len(out) >= maxHelloBytes {
			return out[:maxHelloBytes]
		}
	}
	return out
}

func helloComplete(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	return len(b) >= 5+int(b[3])<<8|int(b[4])
}

func finish(rep *Report, st *stream) {
	st.done = true
	switch st.kind {
	case kindTLS:
		finishTLS(&rep.TLS, st)
	case kindHTTP:
		rep.HTTP.add(st)
	case kindMQTT:
		rep.MQTT.add(st)
	}
}

func finishTLS(rep *TLSReport, st *stream) {
	rep.TLSStreams++
	ordered := st.ordered()
	if len(st.segments) > 1 {
		rep.MultiSegment++
	}
	res := CompareClientHello(ordered)
	class := res.Class()
	rep.Classes[class]++
	for _, m := range res.Mismatches {
		rep.FieldMismatches[m.Field]++
	}
	if class != "agree" && class != "both_reject" && len(rep.Examples) < 20 {
		detail := ""
		if len(res.Mismatches) > 0 {
			detail = fmt.Sprintf("%s quarant=%.60s reference=%.60s", res.Mismatches[0].Field, res.Mismatches[0].Quarant, res.Mismatches[0].Reference)
		}
		rep.Examples = append(rep.Examples, Example{Flow: st.key, Class: class, Detail: detail})
	}
	a, aok := rules.DetectTLSClientHello(st.arrival)
	o, ook := rules.DetectTLSClientHello(ordered)
	if aok != ook || fmt.Sprint(a) != fmt.Sprint(o) {
		rep.OrderSensitive++
	}
	if res.ReferenceOK && !rules.IsTLSPort(st.dstPort) {
		rep.NonTLSPort++
		rep.NonTLSPortPorts[st.dstPort]++
	}
}

func (r *MQTTReport) add(st *stream) {
	ordered := st.ordered()
	res := CompareMQTT(ordered)
	if !rules.IsMQTTPort(st.dstPort) {
		// Off-port streams are only counted when the reference decodes them
		// as MQTT; the analyzer does not parse them.
		if res.ReferenceOK {
			r.NonMQTTPort++
			r.NonMQTTPortPorts[st.dstPort]++
		}
		return
	}
	r.Streams++
	if len(st.segments) > 1 {
		r.MultiSegment++
	}
	if st.retransmitted {
		r.Retransmitted++
	}
	class := res.Class()
	r.Classes[class]++
	for _, m := range res.Mismatches {
		r.FieldMismatches[m.Field]++
	}
	if res.RefReason != "" {
		r.RefReasons[res.RefReason]++
	}
	if class != "agree" && class != "both_reject" && len(r.Examples) < 20 {
		detail := res.RefReason
		for i, m := range res.Mismatches {
			if i == 0 {
				detail = m.Field
			} else {
				detail += "," + m.Field
			}
		}
		r.Examples = append(r.Examples, Example{Flow: st.key, Class: class, Detail: detail})
	}
	if !bytes.Equal(capBytes(st.arrival), ordered) {
		r.ArrivalBytesDiffer++
	}
	a, aok := QuarantMQTT(st.arrival)
	o, ook := QuarantMQTT(ordered)
	if aok != ook || a != o {
		r.OrderSensitive++
	}
}
