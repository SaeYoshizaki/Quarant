package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
	"quarant/internal/synth"
)

func TestRTSPPathMasksCredentials(t *testing.T) {
	got := rtspPath("rtsp://admin:secret@192.168.1.5:554/user=admin_password=tlJw9_channel=1_stream=0.sdp?token=abc")
	if strings.Contains(got, "secret") || strings.Contains(got, "tlJw9") || strings.Contains(got, "192.168") {
		t.Fatalf("credentials or host leaked: %q", got)
	}
	if got != "/user=***_password=***_channel=1_stream=0.sdp" {
		t.Fatalf("got %q", got)
	}
}

func rtspRun(t *testing.T, build func(b *synth.Builder, start time.Time)) []Event {
	t.Helper()
	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sink, _ := NewJSONSink(filepath.Join(dir, "events.jsonl"))
	h := NewFlowHandlerWithObservations(sink, nil, nil, false, db)
	b := &synth.Builder{}
	build(b, time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC))
	var pcap bytes.Buffer
	_ = b.WritePCAP(&pcap)
	if err := NewEngine(h).RunPCAPStream(&pcap); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()
	var out []Event
	readJSONL(t, filepath.Join(dir, "events.jsonl"), func(line []byte) {
		var e Event
		_ = json.Unmarshal(line, &e)
		out = append(out, e)
	})
	return out
}

func describe(seq int, auth bool) []byte {
	a := ""
	if auth {
		a = "Authorization: Digest username=\"admin\", response=\"00\"\r\n"
	}
	return []byte(fmt.Sprintf("DESCRIBE rtsp://192.168.50.9:554/live RTSP/1.0\r\nCSeq: %d\r\n%s\r\n", seq, a))
}

func TestRTSPGuessingThenSuccessIsReported(t *testing.T) {
	attacker := synth.NewHost("02:00:00:00:00:05", "192.168.50.5")
	cam := synth.NewHost("02:00:00:00:00:09", "192.168.50.9")
	events := rtspRun(t, func(b *synth.Builder, start time.Time) {
		c := b.TCP(attacker, cam, 41000, 554).Handshake(start)
		for i := 0; i < 120; i++ {
			c = c.Client(describe(i, true)).Server([]byte(fmt.Sprintf("RTSP/1.0 401 Unauthorized\r\nCSeq: %d\r\n\r\n", i)))
		}
		c.Client(describe(999, true)).Server([]byte("RTSP/1.0 200 OK\r\nCSeq: 999\r\n\r\n")).Close()
	})
	var guess []Event
	for _, e := range events {
		if e.Type == "I1_CREDENTIAL_GUESSING_OBSERVED" {
			guess = append(guess, e)
		}
	}
	if len(guess) != 3 {
		t.Fatalf("want reports at 10 failures, past the NIST limit and on success, got %d: %+v", len(guess), guess)
	}
	last := guess[2]
	if last.DeviceKey != "192.168.50.9" || last.Basis != BasisObserved ||
		!strings.Contains(last.Evidence, "failed_attempts=120") || !strings.Contains(last.Evidence, "success_after_failures=true") {
		t.Fatalf("unexpected final report: %+v", last)
	}
	if !strings.Contains(guess[1].Evidence, "exceeds_nist_800_63b_limit=true") {
		t.Fatalf("second report should mark the NIST limit: %s", guess[1].Evidence)
	}
}

func TestRTSPUnauthenticatedDescribeIsReported(t *testing.T) {
	viewer := synth.NewHost("02:00:00:00:00:05", "192.168.50.5")
	cam := synth.NewHost("02:00:00:00:00:09", "192.168.50.9")
	events := rtspRun(t, func(b *synth.Builder, start time.Time) {
		b.TCP(viewer, cam, 41001, 554).Handshake(start).
			Client([]byte("OPTIONS rtsp://192.168.50.9:554/live RTSP/1.0\r\nCSeq: 1\r\n\r\n")).
			Server([]byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")).
			Client(describe(2, false)).
			Server([]byte("RTSP/1.0 200 OK\r\nCSeq: 2\r\nContent-Type: application/sdp\r\n\r\n")).Close()
		// A camera that asks for credentials is not reported.
		other := synth.NewHost("02:00:00:00:00:0a", "192.168.50.10")
		b.TCP(viewer, other, 41002, 554).Handshake(start.Add(time.Second)).
			Client(describe(1, false)).Server([]byte("RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n\r\n")).Close()
	})
	var found []Event
	for _, e := range events {
		if e.Type == "I3_UNAUTHENTICATED_STREAM_ACCESS" {
			found = append(found, e)
		}
	}
	if len(found) != 1 || found[0].DeviceKey != "192.168.50.9" || !strings.Contains(found[0].Evidence, "method=DESCRIBE path=/live status=200") {
		t.Fatalf("unexpected findings: %+v", found)
	}
}
