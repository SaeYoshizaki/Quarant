// Command trafficshape summarises, per MAC address, the shape of the traffic
// in one classic PCAP (read from a file or stdin): volumes by direction and
// by LAN/WAN, activity over time, sustained uploads, packet sizes, flows and
// their regularity. It only reads packet headers and never payloads.
//
// It is an assessment helper for the passive-signal audit (docs/EXPERIMENTS.md
// C2), not part of the analyzer.
//
//	tar -xzOf 16-09-23.tar.gz | go run ./scripts/assessment/trafficshape > shape.json
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Per-minute WAN upload thresholds for the longest sustained-upload run.
var uploadThresholds = []int64{1_000, 10_000, 100_000}

type flowKey struct {
	proto      uint8
	remote     string
	localPort  uint16
	remotePort uint16
}

type flowStat struct {
	first, last float64
	bytesOut    int64
	bytesIn     int64
}

type device struct {
	pktsOut, pktsIn   int64
	bytesOut, bytesIn int64
	wanOut, wanIn     int64
	lanOut            int64
	bigPktsOut        int64
	minuteOut         map[int64]bool
	minuteWANOut      map[int64]int64
	hours             map[int64]bool
	remotes           map[string]bool
	flows             map[flowKey]*flowStat
	portBytes         map[string]int64
	first, last       float64
}

type summary struct {
	First                string           `json:"first"`
	Last                 string           `json:"last"`
	PktsOut              int64            `json:"pkts_out"`
	PktsIn               int64            `json:"pkts_in"`
	BytesOut             int64            `json:"bytes_out"`
	BytesIn              int64            `json:"bytes_in"`
	WANBytesOut          int64            `json:"wan_bytes_out"`
	WANBytesIn           int64            `json:"wan_bytes_in"`
	LANBytesOut          int64            `json:"lan_bytes_out"`
	UploadRatio          float64          `json:"wan_upload_ratio"`
	MeanPktOut           float64          `json:"mean_pkt_out"`
	BigPktOutFrac        float64          `json:"big_pkt_out_frac"`
	ActiveMinutes        int              `json:"active_minutes"`
	WANActiveMinutes     int              `json:"wan_active_minutes"`
	ActiveHours          int              `json:"active_hours"`
	WANMinuteOutP50      int64            `json:"wan_minute_out_p50"`
	WANMinuteOutP95      int64            `json:"wan_minute_out_p95"`
	WANMinuteOutMax      int64            `json:"wan_minute_out_max"`
	SustainedUploadMin   map[string]int   `json:"sustained_upload_minutes"`
	RemoteIPs            int              `json:"remote_ips"`
	WANFlows             int              `json:"wan_flows"`
	MaxFlowSeconds       float64          `json:"max_flow_seconds"`
	FlowStartIntervalP50 float64          `json:"flow_start_interval_p50"`
	FlowStartIntervalCV  float64          `json:"flow_start_interval_cv"`
	TopPorts             map[string]int64 `json:"top_ports"`
}

func newDevice(ts float64) *device {
	return &device{
		minuteOut:    map[int64]bool{},
		minuteWANOut: map[int64]int64{},
		hours:        map[int64]bool{},
		remotes:      map[string]bool{},
		flows:        map[flowKey]*flowStat{},
		portBytes:    map[string]int64{},
		first:        ts,
		last:         ts,
	}
}

type packetReader interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
}

var privateNets []*net.IPNet

func init() {
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32", "0.0.0.0/32", "fc00::/7", "fe80::/10", "ff00::/8", "::1/128"} {
		_, n, _ := net.ParseCIDR(c)
		privateNets = append(privateNets, n)
	}
}

func isLocal(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func main() {
	flag.Parse()
	var in io.Reader = os.Stdin
	if flag.NArg() > 0 {
		f, err := os.Open(flag.Arg(0))
		if err != nil {
			fail(err)
		}
		defer f.Close()
		in = f
	}
	br := bufio.NewReaderSize(in, 1<<20)
	magic, err := br.Peek(4)
	if err != nil {
		fail(err)
	}
	var r packetReader
	if string(magic) == "\x0a\x0d\x0d\x0a" {
		r, err = pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
	} else {
		r, err = pcapgo.NewReader(br)
	}
	if err != nil {
		fail(err)
	}

	var (
		eth     layers.Ethernet
		ip4     layers.IPv4
		ip6     layers.IPv6
		tcp     layers.TCP
		udp     layers.UDP
		decoded []gopacket.LayerType
	)
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp)
	parser.IgnoreUnsupported = true

	devices := map[string]*device{}
	get := func(mac string, ts float64) *device {
		d := devices[mac]
		if d == nil {
			d = newDevice(ts)
			devices[mac] = d
		}
		if ts < d.first {
			d.first = ts
		}
		if ts > d.last {
			d.last = ts
		}
		return d
	}

	for {
		data, ci, err := r.ZeroCopyReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A truncated final record ends the capture.
			break
		}
		_ = parser.DecodeLayers(data, &decoded)
		hasEth := false
		var srcIP, dstIP net.IP
		var proto uint8
		var sport, dport uint16
		for _, lt := range decoded {
			switch lt {
			case layers.LayerTypeEthernet:
				hasEth = true
			case layers.LayerTypeIPv4:
				srcIP, dstIP, proto = ip4.SrcIP, ip4.DstIP, uint8(ip4.Protocol)
			case layers.LayerTypeIPv6:
				srcIP, dstIP, proto = ip6.SrcIP, ip6.DstIP, uint8(ip6.NextHeader)
			case layers.LayerTypeTCP:
				sport, dport = uint16(tcp.SrcPort), uint16(tcp.DstPort)
			case layers.LayerTypeUDP:
				sport, dport = uint16(udp.SrcPort), uint16(udp.DstPort)
			}
		}
		if !hasEth {
			continue
		}
		ts := float64(ci.Timestamp.UnixNano()) / 1e9
		size := int64(ci.Length)
		minute := int64(ts) / 60

		// Sender side.
		src := eth.SrcMAC.String()
		d := get(src, ts)
		d.pktsOut++
		d.bytesOut += size
		d.minuteOut[minute] = true
		d.hours[int64(ts)/3600] = true
		if size >= 1000 {
			d.bigPktsOut++
		}
		if srcIP != nil && dstIP != nil {
			if isLocal(dstIP) {
				d.lanOut += size
			} else {
				d.wanOut += size
				d.minuteWANOut[minute] += size
				d.remotes[dstIP.String()] = true
				k := flowKey{proto, dstIP.String(), sport, dport}
				f := d.flows[k]
				if f == nil {
					f = &flowStat{first: ts, last: ts}
					d.flows[k] = f
				}
				f.last = ts
				f.bytesOut += size
				d.portBytes[portLabel(proto, dport)] += size
			}
		}

		// Receiver side (unicast only).
		if eth.DstMAC[0]&1 == 0 {
			dst := eth.DstMAC.String()
			r := get(dst, ts)
			r.pktsIn++
			r.bytesIn += size
			if srcIP != nil && !isLocal(srcIP) {
				r.wanIn += size
				r.remotes[srcIP.String()] = true
				k := flowKey{proto, srcIP.String(), dport, sport}
				f := r.flows[k]
				if f == nil {
					f = &flowStat{first: ts, last: ts}
					r.flows[k] = f
				}
				f.last = ts
				f.bytesIn += size
				r.portBytes[portLabel(proto, sport)] += size
			}
		}
	}

	out := map[string]summary{}
	for mac, d := range devices {
		if d.pktsOut == 0 {
			continue
		}
		out[mac] = summarise(d)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		fail(err)
	}
}

func portLabel(proto uint8, port uint16) string {
	switch proto {
	case 6:
		return fmt.Sprintf("tcp/%d", port)
	case 17:
		return fmt.Sprintf("udp/%d", port)
	default:
		return fmt.Sprintf("ip/%d", proto)
	}
}

func summarise(d *device) summary {
	s := summary{
		First:              timeString(d.first),
		Last:               timeString(d.last),
		PktsOut:            d.pktsOut,
		PktsIn:             d.pktsIn,
		BytesOut:           d.bytesOut,
		BytesIn:            d.bytesIn,
		WANBytesOut:        d.wanOut,
		WANBytesIn:         d.wanIn,
		LANBytesOut:        d.lanOut,
		MeanPktOut:         round(float64(d.bytesOut) / float64(d.pktsOut)),
		BigPktOutFrac:      round(float64(d.bigPktsOut) / float64(d.pktsOut)),
		ActiveMinutes:      len(d.minuteOut),
		WANActiveMinutes:   len(d.minuteWANOut),
		ActiveHours:        len(d.hours),
		RemoteIPs:          len(d.remotes),
		SustainedUploadMin: map[string]int{},
		TopPorts:           map[string]int64{},
	}
	if d.wanOut+d.wanIn > 0 {
		s.UploadRatio = round(float64(d.wanOut) / float64(d.wanOut+d.wanIn))
	}

	// Per-minute WAN upload over the device's whole observed span, so that
	// idle minutes count as zero.
	firstMin, lastMin := int64(d.first)/60, int64(d.last)/60
	perMinute := make([]int64, 0, lastMin-firstMin+1)
	for m := firstMin; m <= lastMin; m++ {
		perMinute = append(perMinute, d.minuteWANOut[m])
	}
	for _, th := range uploadThresholds {
		best, run := 0, 0
		for _, v := range perMinute {
			if v >= th {
				run++
				if run > best {
					best = run
				}
			} else {
				run = 0
			}
		}
		s.SustainedUploadMin[fmt.Sprintf(">=%dB", th)] = best
	}
	sorted := append([]int64(nil), perMinute...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	if n := len(sorted); n > 0 {
		s.WANMinuteOutP50 = sorted[n/2]
		s.WANMinuteOutP95 = sorted[(n*95)/100]
		s.WANMinuteOutMax = sorted[n-1]
	}

	var starts []float64
	for _, f := range d.flows {
		s.WANFlows++
		if dur := f.last - f.first; dur > s.MaxFlowSeconds {
			s.MaxFlowSeconds = dur
		}
		starts = append(starts, f.first)
	}
	s.MaxFlowSeconds = round(s.MaxFlowSeconds)
	sort.Float64s(starts)
	if len(starts) >= 3 {
		gaps := make([]float64, 0, len(starts)-1)
		var sum, sq float64
		for i := 1; i < len(starts); i++ {
			g := starts[i] - starts[i-1]
			gaps = append(gaps, g)
			sum += g
			sq += g * g
		}
		sort.Float64s(gaps)
		mean := sum / float64(len(gaps))
		s.FlowStartIntervalP50 = round(gaps[len(gaps)/2])
		if mean > 0 {
			s.FlowStartIntervalCV = round(math.Sqrt(math.Max(sq/float64(len(gaps))-mean*mean, 0)) / mean)
		}
	}

	type pb struct {
		port  string
		bytes int64
	}
	var ports []pb
	for p, b := range d.portBytes {
		ports = append(ports, pb{p, b})
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].bytes > ports[j].bytes })
	for i := 0; i < len(ports) && i < 5; i++ {
		s.TopPorts[ports[i].port] = ports[i].bytes
	}
	return s
}

func timeString(ts float64) string {
	return time.Unix(int64(ts), 0).UTC().Format(time.RFC3339)
}

func round(v float64) float64 { return math.Round(v*1000) / 1000 }

func fail(err error) {
	fmt.Fprintln(os.Stderr, "trafficshape:", err)
	os.Exit(1)
}
