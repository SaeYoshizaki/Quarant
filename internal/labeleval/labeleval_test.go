package labeleval

import (
	"bytes"
	"strings"
	"testing"

	"quarant/internal/synth"
)

func TestEvaluate(t *testing.T) {
	scenario := synth.Scenario{Name: "t", Labels: []synth.Label{
		{ID: "A", DeviceIP: "10.0.0.2", Kind: "weak_tls_version", Visibility: "observable"},
		{ID: "B", DeviceIP: "10.0.0.2", Kind: "outbound_telnet_scan", Visibility: "observable"},
		{ID: "C", DeviceIP: "10.0.0.2", Kind: "known_vulnerable_firmware", Visibility: "hidden"},
		{ID: "N", DeviceIP: "10.0.0.3", Kind: "benign_modern_tls", Visibility: "observable"},
	}}
	events, bad, err := LoadEvents(strings.NewReader(`{"type":"I7_TLS_WEAK_VERSION_OBSERVED","severity":"WARNING","device_key":"10.0.0.2","basis":"observed"}
not json
{"type":"INSECURE_HTTP","severity":"WARNING","src_ip":"10.0.0.2","basis":"observed"}
{"type":"TLS_CLIENT_HELLO","severity":"INFO","device_key":"10.0.0.3"}
{"type":"I6_DEBUG","severity":"INFO","device_key":"10.0.0.3","debug":true}
`))
	if err != nil || bad != 1 || len(events) != 3 {
		t.Fatalf("load: events=%d bad=%d err=%v", len(events), bad, err)
	}
	rep := Evaluate(scenario, events)
	want := map[string]string{"A": "detected", "B": "missed", "C": "not_observable_as_expected", "N": "negative_ok"}
	for _, l := range rep.Labels {
		if l.Outcome != want[l.ID] {
			t.Errorf("label %s: outcome %s want %s", l.ID, l.Outcome, want[l.ID])
		}
	}
	if rep.Metrics.Recall != 0.5 || rep.Metrics.UnlabelledTypes != 1 || rep.Unlabelled[0].Type != "INSECURE_HTTP" {
		t.Fatalf("unexpected metrics: %+v unlabelled=%+v", rep.Metrics, rep.Unlabelled)
	}

	events = append(events, Event{Type: "I7_TLS_WEAK_CIPHER_OFFERED", Severity: "WARNING", DeviceKey: "10.0.0.3"})
	rep = Evaluate(scenario, events)
	if rep.Metrics.NegativeViolations != 1 {
		t.Fatalf("expected negative control violation: %+v", rep.Metrics)
	}
	var buf bytes.Buffer
	WriteMarkdown(&buf, rep)
	if !strings.Contains(buf.String(), "negative_violated") {
		t.Fatal("markdown missing outcome")
	}
}
