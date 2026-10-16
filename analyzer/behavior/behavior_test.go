package behavior

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

func TestHorizontalScanDetected(t *testing.T) {
	a := New(DefaultConfig())
	for i := 0; i < 40; i++ {
		a.Add(Conn{Start: t0.Add(time.Duration(i) * 500 * time.Millisecond), DeviceIP: "192.168.1.5", DstIP: fmt.Sprintf("203.0.113.%d", i+1), DstPort: 23, Proto: "tcp", Answered: i%10 == 0})
	}
	f := a.Evaluate()
	if len(f) != 1 || f[0].Type != "OUTBOUND_SCAN_SUSPECTED" || f[0].DstPort != 23 {
		t.Fatalf("unexpected findings: %+v", f)
	}
	if !strings.Contains(f[0].Inference, "Mirai") || !strings.Contains(f[0].Evidence, "distinct_targets=40") {
		t.Fatalf("missing explanation: %+v", f[0])
	}
	if again := a.Evaluate(); len(again) != 0 {
		t.Fatalf("findings must not repeat across evaluations: %+v", again)
	}
}

func TestScanBelowThresholdOrAnsweredIsIgnored(t *testing.T) {
	a := New(DefaultConfig())
	// Many answered connections (e.g. a phone browsing a CDN) are not a scan.
	for i := 0; i < 40; i++ {
		a.Add(Conn{Start: t0.Add(time.Duration(i) * time.Second / 2), DeviceIP: "192.168.1.6", DstIP: fmt.Sprintf("198.51.100.%d", i+1), DstPort: 443, Proto: "tcp", Answered: true})
	}
	// Few unanswered attempts are not a scan either.
	for i := 0; i < 5; i++ {
		a.Add(Conn{Start: t0.Add(time.Duration(i) * time.Second), DeviceIP: "192.168.1.7", DstIP: fmt.Sprintf("203.0.113.%d", i+1), DstPort: 23, Proto: "tcp"})
	}
	if f := a.Evaluate(); len(f) != 0 {
		t.Fatalf("expected no findings, got %+v", f)
	}
}

func TestVerticalLateralScan(t *testing.T) {
	a := New(DefaultConfig())
	for p := 1; p <= 30; p++ {
		a.Add(Conn{Start: t0.Add(time.Duration(p) * 100 * time.Millisecond), DeviceIP: "192.168.1.5", DstIP: "192.168.1.20", DstPort: uint16(p), Proto: "tcp", DstLocal: true})
	}
	f := a.Evaluate()
	if len(f) != 1 || f[0].Type != "LATERAL_SCAN_SUSPECTED" || f[0].DstIP != "192.168.1.20" {
		t.Fatalf("unexpected findings: %+v", f)
	}
}

func TestPeriodicCommunication(t *testing.T) {
	a := New(DefaultConfig())
	for i := 0; i < 12; i++ {
		jitter := time.Duration(i%3) * 200 * time.Millisecond
		a.Add(Conn{Start: t0.Add(time.Duration(i)*time.Minute + jitter), DeviceIP: "192.168.1.5", DstIP: "203.0.113.66", DstPort: 8080, Proto: "tcp", Answered: true, Plaintext: true})
	}
	// Irregular traffic to another destination must not be reported.
	for _, s := range []int{0, 7, 100, 130, 400, 410, 900, 2000, 2100} {
		a.Add(Conn{Start: t0.Add(time.Duration(s) * time.Second), DeviceIP: "192.168.1.5", DstIP: "198.51.100.9", DstName: "api.vendor.test", DstPort: 443, Proto: "tcp", Answered: true})
	}
	f := a.Evaluate()
	if len(f) != 1 || f[0].Type != "PERIODIC_COMMUNICATION_OBSERVED" {
		t.Fatalf("unexpected findings: %+v", f)
	}
	if f[0].Severity != "WARNING" || !strings.Contains(f[0].Evidence, "direct_ip_no_dns_observed") || !strings.Contains(f[0].Evidence, "plaintext_protocol") {
		t.Fatalf("expected escalated periodic finding with context flags: %+v", f[0])
	}
}

func TestPeriodicTelemetryToNamedHTTPSIsInfo(t *testing.T) {
	a := New(DefaultConfig())
	for i := 0; i < 10; i++ {
		a.Add(Conn{Start: t0.Add(time.Duration(i) * 5 * time.Minute), DeviceIP: "192.168.1.5", DstIP: "198.51.100.9", DstName: "telemetry.vendor.test", DstPort: 443, Proto: "tcp", Answered: true})
	}
	f := a.Evaluate()
	if len(f) != 1 || f[0].Severity != "INFO" {
		t.Fatalf("benign-looking telemetry must stay INFO: %+v", f)
	}
}

func TestMedian(t *testing.T) {
	if median([]float64{3, 1, 2}) != 2 || median([]float64{4, 1, 3, 2}) != 2.5 || median(nil) != 0 {
		t.Fatal("median")
	}
}
