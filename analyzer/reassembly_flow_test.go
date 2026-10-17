package analyzer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
	"quarant/internal/synth"
)

// runConn analyses one synthetic connection and returns the sorted event
// types and the flow records.
func runConn(t *testing.T, build func(b *synth.Builder)) ([]string, []FlowRecord) {
	t.Helper()
	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	events, _ := NewJSONSink(filepath.Join(dir, "events.jsonl"))
	flows, _ := NewJSONSink(filepath.Join(dir, "flows.jsonl"))
	h := NewFlowHandlerWithObservations(events, flows, nil, false, db)
	b := &synth.Builder{}
	build(b)
	var pcap bytes.Buffer
	if err := b.WritePCAP(&pcap); err != nil {
		t.Fatal(err)
	}
	if err := NewEngine(h).RunPCAPStream(&pcap); err != nil {
		t.Fatal(err)
	}
	_ = events.Close()
	_ = flows.Close()
	seen := map[string]bool{}
	readJSONL(t, filepath.Join(dir, "events.jsonl"), func(line []byte) {
		var e Event
		_ = json.Unmarshal(line, &e)
		if !e.Debug {
			seen[e.Type] = true
		}
	})
	var types []string
	for k := range seen {
		types = append(types, k)
	}
	sort.Strings(types)
	var recs []FlowRecord
	readJSONL(t, filepath.Join(dir, "flows.jsonl"), func(line []byte) {
		var f FlowRecord
		_ = json.Unmarshal(line, &f)
		recs = append(recs, f)
	})
	return types, recs
}

var (
	reasmStart = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	reasmPhone = synth.NewHost("02:11:22:33:44:55", "192.168.50.31")
	reasmPlug  = synth.NewHost("94:10:3e:00:00:01", "192.168.50.40")
	loginParts = [][]byte{
		[]byte("POST /upnp/control/basicevent1 HTTP/1.1\r\nHost: 192.168.50.40:49153\r\n"),
		[]byte("Authorization: Basic YWRtaW46YWRtaW4=\r\nContent-Type: text/xml\r\n"),
		[]byte("Content-Length: 2\r\n\r\nok"),
	}
	hasAuthEvent = func(types []string) bool {
		for _, ty := range types {
			if ty == "INSECURE_HTTP_AUTH" {
				return true
			}
		}
		return false
	}
)

// TLS recognised by content must survive a reordered start: the first data
// segment captured is not the first in sequence (the first server segment of
// a TLS-by-content flow on UNSW 18-10-22 was lost this way).
func TestTLSByContentWithReorderedFirstSegment(t *testing.T) {
	hello := synth.TLSClientHello("push.example.test", tls.VersionTLS10, tls.VersionTLS10)
	parts := [][]byte{hello[:40], hello[40:]}
	push := synth.Host{MAC: reasmPhone.MAC, IP: net.ParseIP("198.51.100.90").To4()}
	types, _ := runConn(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, push, 50004, 5228).Handshake(reasmStart).
			ClientSegments(parts, []int{1, 0}).Close()
	})
	found := false
	for _, ty := range types {
		found = found || ty == "TLS_CLIENT_HELLO"
	}
	if !found {
		t.Fatalf("reordered ClientHello on port 5228 not parsed, got %v", types)
	}
}

func TestReorderedAndRetransmittedSegmentsGiveSameFindings(t *testing.T) {
	run := func(order []int) []string {
		types, _ := runConn(t, func(b *synth.Builder) {
			b.TCP(reasmPhone, reasmPlug, 50001, 80).Handshake(reasmStart).
				ClientSegments(loginParts, order).Close()
		})
		return types
	}
	want := run([]int{0, 1, 2})
	if !hasAuthEvent(want) {
		t.Fatalf("baseline must report the login, got %v", want)
	}
	for _, order := range [][]int{{0, 2, 1}, {1, 0, 2}, {0, 0, 1, 1, 2}, {0, 2, 1, 2}} {
		if got := run(order); !reflect.DeepEqual(got, want) {
			t.Errorf("order %v: got %v, want %v", order, got, want)
		}
	}
}

// A capture that starts at the server's SYN/ACK makes the server the flow's
// first sender; client data must still reach the client buffer (a ClientHello
// was lost this way on UNSW 18-10-22 while routing by first sender).
func TestCaptureStartingAtSynAckStillParsesClient(t *testing.T) {
	types, _ := runConn(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, reasmPlug, 50003, 80).HandshakeMissedSyn(reasmStart).
			ClientSegments(loginParts, []int{0, 1, 2}).Close()
	})
	if !hasAuthEvent(types) {
		t.Fatalf("client request after a missed SYN must be parsed, got %v", types)
	}
}

func TestCaptureGapIsCountedInFlowRecord(t *testing.T) {
	_, recs := runConn(t, func(b *synth.Builder) {
		// Segment 1 reached the device (the ACK covers it) but not the capture.
		b.TCP(reasmPhone, reasmPlug, 50002, 80).Handshake(reasmStart).
			ClientSegments(loginParts, []int{0, 2}).Close()
	})
	gaps, gapBytes := 0, 0
	for _, r := range recs {
		gaps, gapBytes = max(gaps, r.CaptureGaps), max(gapBytes, r.CaptureGapBytes)
	}
	if gaps != 1 || gapBytes != len(loginParts[1]) {
		t.Fatalf("capture gap not recorded: gaps=%d bytes=%d", gaps, gapBytes)
	}
}
