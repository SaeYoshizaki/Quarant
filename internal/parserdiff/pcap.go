package parserdiff

import (
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
	// OrderSensitive: concatenating segments in arrival order (what the
	// analyzer does) gives a different result than sequence order.
	OrderSensitive int `json:"arrival_order_changes_result"`
	// NonTLSPort: valid ClientHellos on ports the analyzer does not treat as
	// TLS (rules.IsTLSPort), i.e. hellos the production path never parses.
	NonTLSPort      int            `json:"hellos_on_unparsed_ports"`
	NonTLSPortPorts map[uint16]int `json:"unparsed_ports,omitempty"`
	Examples        []Example      `json:"examples,omitempty"`
}

// Example records one disagreement for manual review (no payload bytes).
type Example struct {
	Flow   string `json:"flow"`
	Class  string `json:"class"`
	Detail string `json:"detail,omitempty"`
}

type stream struct {
	key       string
	dstPort   uint16
	baseSeq   uint32
	segments  map[uint32][]byte
	arrival   []byte
	collected int
	tls       bool
	done      bool
}

// AnalyzePCAP runs the TLS differential over every client stream in path.
func AnalyzePCAP(path string) (TLSReport, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return TLSReport{}, err
	}
	defer handle.Close()
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	src.Lazy, src.NoCopy = true, true

	rep := TLSReport{Classes: map[string]int{}, FieldMismatches: map[string]int{}, NonTLSPortPorts: map[uint16]int{}}
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
			st = &stream{key: fwd, dstPort: uint16(tcp.DstPort), baseSeq: tcp.Seq, segments: map[uint32][]byte{}, tls: tcp.Payload[0] == 22}
			streams[fwd] = st
		}
		if st.done || !st.tls || st.collected >= maxHelloBytes {
			continue
		}
		payload := append([]byte(nil), tcp.Payload...)
		st.arrival = append(st.arrival, payload...)
		if _, dup := st.segments[tcp.Seq]; !dup {
			st.segments[tcp.Seq] = payload
		}
		st.collected += len(payload)
		if helloComplete(st.ordered()) {
			finish(&rep, st)
		}
	}
	for _, st := range streams {
		if st.tls && !st.done {
			finish(&rep, st)
		}
	}
	return rep, nil
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

func finish(rep *TLSReport, st *stream) {
	st.done = true
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
