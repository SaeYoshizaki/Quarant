package reportapi

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadObservationSOCSummarizesPassiveLogs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "observations.jsonl")
	data := "" +
		`{"ts":"2026-09-23T00:00:00Z","kind":"dns_query","src_ip":"192.168.1.10","dst_ip":"8.8.8.8","dst_port":53,"protocol":"udp","app_protocol":"dns","direction":"external","dns_query":"camera-cloud.example","observed_destination":"camera-cloud.example"}` + "\n" +
		`{"ts":"2026-09-23T00:10:00Z","kind":"tls_sni","src_ip":"192.168.1.10","dst_ip":"93.184.216.34","dst_port":443,"protocol":"tcp","app_protocol":"tls","direction":"external","sni":"camera-cloud.example","observed_destination":"camera-cloud.example"}` + "\n" +
		`{"ts":"2026-09-23T00:20:00Z","kind":"http_request","src_ip":"192.168.1.20","dst_ip":"203.0.113.10","dst_port":80,"protocol":"tcp","app_protocol":"http","direction":"external","host":"api.example","observed_destination":"api.example"}` + "\n" +
		`{"ts":"2026-09-23T00:30:00Z","kind":"mdns_query","src_ip":"192.168.1.30","dst_ip":"224.0.0.251","dst_port":5353,"protocol":"udp","app_protocol":"mdns","direction":"local","dns_query":"printer.local","noise":true}` + "\n"
	if err := os.WriteFile(path, []byte(data), 0644); err != nil {
		t.Fatalf("write observations: %v", err)
	}

	got, err := LoadObservationSOC(path)
	if err != nil {
		t.Fatalf("LoadObservationSOC: %v", err)
	}
	if got.Metrics.TotalObservations != 4 {
		t.Fatalf("TotalObservations=%d, want 4", got.Metrics.TotalObservations)
	}
	if got.Metrics.ExternalCount != 3 {
		t.Fatalf("ExternalCount=%d, want 3", got.Metrics.ExternalCount)
	}
	if got.Metrics.DNSCount != 2 {
		t.Fatalf("DNSCount=%d, want 2", got.Metrics.DNSCount)
	}
	if got.Metrics.HTTPCount != 1 {
		t.Fatalf("HTTPCount=%d, want 1", got.Metrics.HTTPCount)
	}
	if got.Metrics.TLSCount != 1 {
		t.Fatalf("TLSCount=%d, want 1", got.Metrics.TLSCount)
	}
	if got.Metrics.NoiseCount != 1 {
		t.Fatalf("NoiseCount=%d, want 1", got.Metrics.NoiseCount)
	}
	if got.Metrics.AttackLikeCount != 3 {
		t.Fatalf("AttackLikeCount=%d, want 3", got.Metrics.AttackLikeCount)
	}
	if len(got.Timeline) != 1 || got.Timeline[0].AttackLikeCount != 3 {
		t.Fatalf("unexpected timeline: %+v", got.Timeline)
	}
	if len(got.TopLists.DNSQueries) == 0 || got.TopLists.DNSQueries[0].Key != "camera-cloud.example" {
		t.Fatalf("unexpected DNS top list: %+v", got.TopLists.DNSQueries)
	}
	if len(got.AttackLike.ByReason) == 0 {
		t.Fatalf("expected attack-like reasons")
	}
}

func TestBuildObservationSOCDetectsScanLikeBurst(t *testing.T) {
	var observations []ObservationRecord
	for i := uint16(0); i < 8; i++ {
		observations = append(observations, ObservationRecord{
			Timestamp:           mustParseTime(t, "2026-09-23T01:00:00Z"),
			Kind:                "external_connection",
			SrcIP:               "192.168.1.10",
			DstIP:               "198.51.100.20",
			DstPort:             8000 + i,
			Protocol:            "tcp",
			Direction:           "external",
			ObservedDestination: "198.51.100.20",
		})
	}

	got := BuildObservationSOC("test", observations)
	found := false
	for _, reason := range got.AttackLike.ByReason {
		if reason.Key == "scan_like_burst" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("scan_like_burst not found in reasons: %+v", got.AttackLike.ByReason)
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, ok := parseRFC3339(value)
	if !ok {
		t.Fatalf("parse time %q", value)
	}
	return parsed
}
