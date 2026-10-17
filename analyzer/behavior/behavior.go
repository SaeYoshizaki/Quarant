// Package behavior detects behavioural patterns that only appear across many
// connections: scanning and periodic (beacon-like) communication.
//
// The detectors are deliberately simple, explainable statistics with explicit
// thresholds, so every finding can be checked by hand against the evidence it
// carries. They report suspicion, never confirmation: a scan-like pattern can
// be a misbehaving app, and periodic traffic is how most IoT telemetry looks.
package behavior

import (
	"fmt"
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

// Conn is one connection attempt as seen from the monitored device.
type Conn struct {
	Start    time.Time
	DeviceIP string // local device that initiated the connection
	DstIP    string
	DstPort  uint16
	Proto    string // tcp | udp
	// Answered is true when the responder sent SYN/ACK or payload. Unanswered
	// attempts (no reply, or only RST) are the signature of scanning.
	Answered bool
	// DstName is the DNS name the device resolved to DstIP, if observed.
	DstName   string
	BytesOut  int64
	BytesIn   int64
	Plaintext bool // an unencrypted application protocol was identified
	DstLocal  bool
}

// Config holds the detector thresholds. Defaults are documented in
// docs/DETECTION.md together with their rationale.
type Config struct {
	// Horizontal scan: many distinct destination hosts on one port.
	ScanWindow           time.Duration
	HorizontalMinTargets int
	VerticalMinPorts     int
	MinUnansweredRatio   float64

	// Periodic communication.
	PeriodicMinConns    int
	PeriodicMinInterval time.Duration
	// PeriodicMaxJitter is the maximum ratio MAD(interval)/median(interval).
	PeriodicMaxJitter float64

	// Persistent attempts: many connections to one destination endpoint.
	PersistentWindow      time.Duration
	PersistentMinAttempts int
}

func DefaultConfig() Config {
	return Config{
		ScanWindow:            60 * time.Second,
		HorizontalMinTargets:  20,
		VerticalMinPorts:      20,
		MinUnansweredRatio:    0.7,
		PeriodicMinConns:      8,
		PeriodicMinInterval:   10 * time.Second,
		PeriodicMaxJitter:     0.1,
		PersistentWindow:      time.Hour,
		PersistentMinAttempts: 30,
	}
}

// Finding is a detector result. Fields map directly onto analyzer.Event.
type Finding struct {
	Type         string
	Severity     string
	Confidence   string
	DeviceIP     string
	DstIP        string
	DstPort      uint16
	First, Last  time.Time
	Evidence     string
	ObservedFact string
	Inference    string
	Limitation   string
	Recommend    string
	// Key identifies the finding for de-duplication across repeated
	// evaluations (live mode).
	Key string
}

// Analyzer accumulates connection attempts per device.
type Analyzer struct {
	cfg      Config
	conns    map[string][]Conn
	reported map[string]bool
	// maxPerDevice bounds memory; the oldest attempts are dropped first.
	maxPerDevice int
}

func New(cfg Config) *Analyzer {
	return &Analyzer{cfg: cfg, conns: map[string][]Conn{}, reported: map[string]bool{}, maxPerDevice: 50000}
}

// Add records a connection attempt.
func (a *Analyzer) Add(c Conn) {
	if a == nil || c.DeviceIP == "" || c.Start.IsZero() {
		return
	}
	list := append(a.conns[c.DeviceIP], c)
	if len(list) > a.maxPerDevice {
		list = list[len(list)-a.maxPerDevice:]
	}
	a.conns[c.DeviceIP] = list
}

// Evaluate runs all detectors and returns findings not reported before.
func (a *Analyzer) Evaluate() []Finding {
	if a == nil {
		return nil
	}
	devices := make([]string, 0, len(a.conns))
	for ip := range a.conns {
		devices = append(devices, ip)
	}
	sort.Strings(devices)

	var out []Finding
	for _, ip := range devices {
		conns := append([]Conn(nil), a.conns[ip]...)
		sort.SliceStable(conns, func(i, j int) bool { return conns[i].Start.Before(conns[j].Start) })
		var found []Finding
		found = append(found, a.horizontalScans(ip, conns)...)
		found = append(found, a.verticalScans(ip, conns)...)
		found = append(found, a.periodic(ip, conns)...)
		found = append(found, a.persistent(ip, conns)...)
		for _, f := range found {
			if a.reported[f.Key] {
				continue
			}
			a.reported[f.Key] = true
			out = append(out, f)
		}
	}
	return out
}

// ---- scans -------------------------------------------------------------------

// windowMax slides a window over conns (sorted by time) and returns the
// window with the most distinct values of key, plus its members.
func windowMax(conns []Conn, window time.Duration, key func(Conn) string) []Conn {
	best := []Conn(nil)
	bestDistinct := 0
	counts := map[string]int{}
	lo := 0
	for hi := range conns {
		counts[key(conns[hi])]++
		for conns[hi].Start.Sub(conns[lo].Start) > window {
			k := key(conns[lo])
			counts[k]--
			if counts[k] == 0 {
				delete(counts, k)
			}
			lo++
		}
		if len(counts) > bestDistinct {
			bestDistinct = len(counts)
			best = conns[lo : hi+1]
		}
	}
	return best
}

func unansweredRatio(conns []Conn) float64 {
	if len(conns) == 0 {
		return 0
	}
	n := 0
	for _, c := range conns {
		if !c.Answered {
			n++
		}
	}
	return float64(n) / float64(len(conns))
}

func (a *Analyzer) horizontalScans(ip string, conns []Conn) []Finding {
	byPort := map[string][]Conn{}
	for _, c := range conns {
		k := fmt.Sprintf("%s/%d", c.Proto, c.DstPort)
		byPort[k] = append(byPort[k], c)
	}
	keys := sortedKeys(byPort)
	var out []Finding
	for _, k := range keys {
		w := windowMax(byPort[k], a.cfg.ScanWindow, func(c Conn) string { return c.DstIP })
		targets := distinct(w, func(c Conn) string { return c.DstIP })
		ratio := unansweredRatio(w)
		if len(targets) < a.cfg.HorizontalMinTargets || ratio < a.cfg.MinUnansweredRatio {
			continue
		}
		port := w[0].DstPort
		local := 0
		for _, c := range w {
			if c.DstLocal {
				local++
			}
		}
		scope := "external"
		typ := "OUTBOUND_SCAN_SUSPECTED"
		if local*2 > len(w) {
			scope = "local"
			typ = "LATERAL_SCAN_SUSPECTED"
		}
		confidence := "medium"
		if len(targets) >= 3*a.cfg.HorizontalMinTargets && ratio >= 0.9 {
			confidence = "high"
		}
		inference := "The device is probing many hosts for one service, which is characteristic of worm-style propagation or a compromised device used for scanning."
		if port == 23 || port == 2323 {
			inference += " Telnet (23/2323) scanning is the propagation method of Mirai-family IoT malware; this matches that behaviour but does not identify the malware."
		}
		out = append(out, Finding{
			Type: typ, Severity: "HIGH", Confidence: confidence, DeviceIP: ip, DstPort: port,
			First: w[0].Start, Last: w[len(w)-1].Start,
			Evidence: fmt.Sprintf("pattern=horizontal_scan scope=%s proto=%s dst_port=%d distinct_targets=%d attempts=%d unanswered_ratio=%.2f window=%s sample_targets=%s thresholds=targets>=%d,unanswered>=%.2f",
				scope, w[0].Proto, port, len(targets), len(w), ratio, w[len(w)-1].Start.Sub(w[0].Start).Round(time.Millisecond), sample(targets, 5), a.cfg.HorizontalMinTargets, a.cfg.MinUnansweredRatio),
			ObservedFact: fmt.Sprintf("%s attempted connections to %d different %s hosts on port %d within %s; %.0f%% got no answer.", ip, len(targets), scope, port, a.cfg.ScanWindow, ratio*100),
			Inference:    inference,
			Limitation:   "Scanning is inferred from connection metadata only. A misconfigured application or a legitimate network discovery tool can produce the same pattern; passive monitoring cannot confirm infection.",
			Recommend:    "Isolate the device from the network, check it against vendor advisories, factory-reset and update firmware, and change its passwords.",
			Key:          fmt.Sprintf("%s|%s|%s|%d", typ, ip, w[0].Proto, port),
		})
	}
	return out
}

func (a *Analyzer) verticalScans(ip string, conns []Conn) []Finding {
	byTarget := map[string][]Conn{}
	for _, c := range conns {
		byTarget[c.DstIP] = append(byTarget[c.DstIP], c)
	}
	var out []Finding
	for _, target := range sortedKeys(byTarget) {
		w := windowMax(byTarget[target], a.cfg.ScanWindow, func(c Conn) string { return fmt.Sprintf("%s/%d", c.Proto, c.DstPort) })
		ports := distinct(w, func(c Conn) string { return fmt.Sprintf("%d", c.DstPort) })
		ratio := unansweredRatio(w)
		if len(ports) < a.cfg.VerticalMinPorts || ratio < a.cfg.MinUnansweredRatio {
			continue
		}
		typ := "PORT_SCAN_SUSPECTED"
		if w[0].DstLocal {
			typ = "LATERAL_SCAN_SUSPECTED"
		}
		out = append(out, Finding{
			Type: typ, Severity: "HIGH", Confidence: "medium", DeviceIP: ip, DstIP: target,
			First: w[0].Start, Last: w[len(w)-1].Start,
			Evidence: fmt.Sprintf("pattern=vertical_scan target=%s distinct_ports=%d attempts=%d unanswered_ratio=%.2f window=%s sample_ports=%s thresholds=ports>=%d,unanswered>=%.2f",
				target, len(ports), len(w), ratio, w[len(w)-1].Start.Sub(w[0].Start).Round(time.Millisecond), sample(ports, 8), a.cfg.VerticalMinPorts, a.cfg.MinUnansweredRatio),
			ObservedFact: fmt.Sprintf("%s attempted connections to %d different ports on %s within %s; %.0f%% got no answer.", ip, len(ports), target, a.cfg.ScanWindow, ratio*100),
			Inference:    "The device appears to be enumerating services on another host (reconnaissance).",
			Limitation:   "Inferred from connection metadata only. Network management or inventory tools can produce the same pattern.",
			Recommend:    "Confirm whether the device or a user on it runs a scanner; if not, isolate and investigate the device.",
			Key:          fmt.Sprintf("%s|%s|%s", typ, ip, target),
		})
	}
	return out
}

// ---- periodicity -------------------------------------------------------------

func (a *Analyzer) periodic(ip string, conns []Conn) []Finding {
	byDest := map[string][]Conn{}
	for _, c := range conns {
		if !c.Answered {
			continue
		}
		dest := c.DstIP
		if c.DstName != "" {
			dest = c.DstName
		}
		k := fmt.Sprintf("%s|%s|%d", dest, c.Proto, c.DstPort)
		byDest[k] = append(byDest[k], c)
	}
	var out []Finding
	for _, k := range sortedKeys(byDest) {
		list := byDest[k]
		if len(list) < a.cfg.PeriodicMinConns {
			continue
		}
		intervals := make([]float64, 0, len(list)-1)
		for i := 1; i < len(list); i++ {
			intervals = append(intervals, list[i].Start.Sub(list[i-1].Start).Seconds())
		}
		med := median(intervals)
		if med < a.cfg.PeriodicMinInterval.Seconds() {
			continue
		}
		dev := make([]float64, len(intervals))
		for i, v := range intervals {
			dev[i] = math.Abs(v - med)
		}
		jitter := median(dev) / med
		if jitter > a.cfg.PeriodicMaxJitter {
			continue
		}
		c0 := list[0]
		dest := c0.DstIP
		if c0.DstName != "" {
			dest = c0.DstName + " (" + c0.DstIP + ")"
		}
		var flags []string
		if c0.DstName == "" && !c0.DstLocal {
			flags = append(flags, "direct_ip_no_dns_observed")
		}
		if c0.Plaintext {
			flags = append(flags, "plaintext_protocol")
		}
		if !c0.DstLocal && net.ParseIP(c0.DstIP) != nil && !standardServicePorts[c0.DstPort] {
			flags = append(flags, "non_standard_port")
		}
		severity, confidence := "INFO", "high"
		inference := "Regular, timer-driven communication. Most IoT devices send heartbeats or telemetry like this; command-and-control beacons look the same."
		if len(flags) >= 2 {
			severity = "WARNING"
			inference += " Several context flags that are uncommon for vendor telemetry are present, so this destination deserves review."
		}
		out = append(out, Finding{
			Type: "PERIODIC_COMMUNICATION_OBSERVED", Severity: severity, Confidence: confidence, DeviceIP: ip, DstIP: c0.DstIP, DstPort: c0.DstPort,
			First: list[0].Start, Last: list[len(list)-1].Start,
			Evidence: fmt.Sprintf("pattern=periodic destination=%s proto=%s dst_port=%d connections=%d median_interval_s=%.1f jitter_mad_ratio=%.3f context_flags=%s thresholds=conns>=%d,jitter<=%.2f",
				dest, c0.Proto, c0.DstPort, len(list), med, jitter, strings.Join(flags, ","), a.cfg.PeriodicMinConns, a.cfg.PeriodicMaxJitter),
			ObservedFact: fmt.Sprintf("%s connected to %s port %d %d times at a regular interval of about %.0f s.", ip, dest, c0.DstPort, len(list), med),
			Inference:    inference,
			Limitation:   "Periodicity alone does not distinguish benign telemetry from malware beacons. Compare the destination with the vendor's documented services and threat intelligence before drawing conclusions.",
			Recommend:    "Check whether the destination belongs to the device vendor; if it does not, block it and investigate the device.",
			Key:          "PERIODIC|" + ip + "|" + k,
		})
	}
	return out
}

// standardServicePorts are well-known ports for ordinary device-to-cloud
// traffic; plaintext on 80 is flagged separately as plaintext_protocol.
var standardServicePorts = map[uint16]bool{53: true, 80: true, 123: true, 443: true, 8883: true}

// ---- persistent connection attempts ----------------------------------------

// persistent reports devices that keep (re)connecting to one remote endpoint
// at a high rate. Malware reconnect loops to command-and-control servers
// (often dead or sinkholed, so most attempts go unanswered) look like this
// without being periodic; a device whose cloud is down can too, which is why
// the severity depends on context flags.
func (a *Analyzer) persistent(ip string, conns []Conn) []Finding {
	byEndpoint := map[string][]Conn{}
	for _, c := range conns {
		if c.DstLocal {
			continue
		}
		k := fmt.Sprintf("%s|%s|%d", c.DstIP, c.Proto, c.DstPort)
		byEndpoint[k] = append(byEndpoint[k], c)
	}
	var out []Finding
	for _, k := range sortedKeys(byEndpoint) {
		list := byEndpoint[k]
		if len(list) < a.cfg.PersistentMinAttempts {
			continue
		}
		// Densest window of attempts.
		best, lo := 0, 0
		var w []Conn
		for hi := range list {
			for list[hi].Start.Sub(list[lo].Start) > a.cfg.PersistentWindow {
				lo++
			}
			if hi-lo+1 > best {
				best = hi - lo + 1
				w = list[lo : hi+1]
			}
		}
		if best < a.cfg.PersistentMinAttempts {
			continue
		}
		c0 := w[0]
		ratio := unansweredRatio(w)
		var flags []string
		if c0.DstName == "" {
			flags = append(flags, "direct_ip_no_dns_observed")
		}
		if !standardServicePorts[c0.DstPort] {
			flags = append(flags, "non_standard_port")
		}
		if ratio >= 0.5 {
			flags = append(flags, "mostly_unanswered")
		}
		severity := "INFO"
		inference := "The device repeatedly connects to the same remote endpoint at a high rate. Persistent reconnect loops are typical of malware trying to reach a command-and-control server, but also of a device whose cloud service is unreachable."
		if len(flags) >= 2 {
			severity = "WARNING"
			inference += " The endpoint is contacted without observed DNS and/or on an unusual port, which is uncommon for vendor services."
		}
		dest := c0.DstIP
		if c0.DstName != "" {
			dest = c0.DstName + " (" + c0.DstIP + ")"
		}
		out = append(out, Finding{
			Type: "PERSISTENT_CONNECTION_ATTEMPTS", Severity: severity, Confidence: "high", DeviceIP: ip, DstIP: c0.DstIP, DstPort: c0.DstPort,
			First: w[0].Start, Last: w[len(w)-1].Start,
			Evidence: fmt.Sprintf("pattern=persistent_attempts destination=%s proto=%s dst_port=%d attempts_in_window=%d total_attempts=%d window=%s unanswered_ratio=%.2f context_flags=%s thresholds=attempts>=%d/%s",
				dest, c0.Proto, c0.DstPort, len(w), len(list), w[len(w)-1].Start.Sub(w[0].Start).Round(time.Second), ratio, strings.Join(flags, ","), a.cfg.PersistentMinAttempts, a.cfg.PersistentWindow),
			ObservedFact: fmt.Sprintf("%s made %d connection attempts to %s port %d within %s (%.0f%% unanswered).", ip, len(w), dest, c0.DstPort, w[len(w)-1].Start.Sub(w[0].Start).Round(time.Second), ratio*100),
			Inference:    inference,
			Limitation:   "Connection metadata alone cannot show what was exchanged or whether the endpoint is malicious; check the destination against vendor documentation and threat intelligence.",
			Recommend:    "Identify the destination. If it is not a documented vendor service, block it and investigate the device.",
			Key:          "PERSISTENT|" + ip + "|" + k,
		})
	}
	return out
}

// ---- helpers -------------------------------------------------------------------

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	m := len(s) / 2
	if len(s)%2 == 1 {
		return s[m]
	}
	return (s[m-1] + s[m]) / 2
}

func distinct(conns []Conn, key func(Conn) string) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range conns {
		k := key(c)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func sample(values []string, n int) string {
	if len(values) <= n {
		return strings.Join(values, ",")
	}
	return strings.Join(values[:n], ",") + fmt.Sprintf(",...(+%d)", len(values)-n)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
