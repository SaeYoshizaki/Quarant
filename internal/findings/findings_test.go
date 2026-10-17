package findings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)

func ev(min int, dev, typ, sev, basis, flow, dst string) Event {
	return Event{TS: t0.Add(time.Duration(min) * time.Minute), DeviceKey: dev, SrcIP: dev, Type: typ, Severity: sev, Basis: basis,
		FlowKey: flow, DstIP: dst, DstPort: 80, Evidence: "host=" + dst}
}

func TestBuildCondensesPerDeviceAndCondition(t *testing.T) {
	events := []Event{
		ev(0, "192.168.1.10", "INSECURE_HTTP", "WARNING", "observed", "f1", "203.0.113.1"),
		ev(5, "192.168.1.10", "INSECURE_HTTP", "WARNING", "observed", "f2", "203.0.113.2"),
		ev(9, "192.168.1.10", "INSECURE_HTTP", "WARNING", "observed", "f2", "203.0.113.2"),
		// Same device under a second IP (same MAC).
		ev(20, "192.168.1.11", "INSECURE_HTTP", "WARNING", "observed", "f3", "203.0.113.3"),
		// Another rule restating cleartext HTTP, with a stronger severity.
		ev(7, "192.168.1.10", "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL", "HIGH", "inferred", "f2", "203.0.113.2"),
		// A distinct observation stays its own condition.
		ev(8, "192.168.1.10", "INSECURE_HTTP_AUTH", "HIGH", "observed", "f2", "203.0.113.2"),
		// Filtered: INFO and debug.
		ev(1, "192.168.1.10", "TLS_CLIENT_HELLO", "INFO", "observed", "f4", "203.0.113.9"),
		{TS: t0, DeviceKey: "192.168.1.10", Type: "INSECURE_HTTP", Severity: "WARNING", Debug: true},
		ev(3, "192.168.1.20", "INSECURE_HTTP", "WARNING", "observed", "f9", "203.0.113.1"),
	}
	macs := map[string]string{"192.168.1.10": "aa:bb:cc:00:00:01", "192.168.1.11": "aa:bb:cc:00:00:01"}
	rep := Build(events, macs, "WARNING")

	if rep.Counts.Events != 7 {
		t.Fatalf("events counted %d, want 7 (INFO and debug excluded)", rep.Counts.Events)
	}
	if rep.Counts.Devices != 2 {
		t.Fatalf("devices %d, want 2 (two IPs of one MAC are one device)", rep.Counts.Devices)
	}
	var http *Finding
	for i := range rep.Findings {
		if rep.Findings[i].MAC == "aa:bb:cc:00:00:01" && rep.Findings[i].Type == "INSECURE_HTTP" {
			http = &rep.Findings[i]
		}
	}
	if http == nil || http.Events != 4 || http.Flows != 3 || http.Destinations != 3 {
		t.Fatalf("INSECURE_HTTP finding = %+v, want 4 events, 3 flows, 3 destinations", http)
	}
	if !http.FirstSeen.Equal(t0) || !http.LastSeen.Equal(t0.Add(20*time.Minute)) {
		t.Fatalf("time span %v-%v", http.FirstSeen, http.LastSeen)
	}

	var cleartext, auth *Condition
	for i := range rep.Conditions {
		c := &rep.Conditions[i]
		if c.MAC != "aa:bb:cc:00:00:01" {
			continue
		}
		switch c.Condition {
		case "cleartext_http":
			cleartext = c
		case "insecure_http_auth":
			auth = c
		}
	}
	if cleartext == nil || cleartext.Events != 5 || cleartext.Severity != "HIGH" || strings.Join(cleartext.Types, ",") != "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL,INSECURE_HTTP" {
		t.Fatalf("cleartext condition = %+v", cleartext)
	}
	if strings.Join(cleartext.Basis, ",") != "observed,inferred" {
		t.Fatalf("basis order %v, want observed before inferred", cleartext.Basis)
	}
	if auth == nil || auth.Events != 1 {
		t.Fatalf("credential exposure must stay a separate condition, got %+v", auth)
	}
	if rep.Counts.Conditions != 3 {
		t.Fatalf("conditions %d, want 3", rep.Counts.Conditions)
	}
}

func TestDerivedConditionIsMarked(t *testing.T) {
	rep := Build([]Event{
		ev(0, "192.168.1.10", "R1_COMPOSITE_RISK", "HIGH", "inferred", "", ""),
		ev(0, "192.168.1.10", "I4_I5_COMBINED_RISK", "WARNING", "reference_match", "", ""),
	}, nil, "WARNING")
	if len(rep.Conditions) != 1 || !rep.Conditions[0].Derived || rep.Conditions[0].Condition != "composite_risks" {
		t.Fatalf("conditions %+v", rep.Conditions)
	}
}

func TestEvidenceExamplesAreBoundedAndTruncated(t *testing.T) {
	var events []Event
	for i := 0; i < 10; i++ {
		e := ev(i, "192.168.1.10", "INSECURE_HTTP", "WARNING", "observed", "f", "203.0.113.1")
		e.Evidence = string(rune('a'+i)) + strings.Repeat("x", 400)
		events = append(events, e)
	}
	f := Build(events, nil, "WARNING").Findings[0]
	if len(f.ExampleEvidence) != maxExamples {
		t.Fatalf("examples %d, want %d", len(f.ExampleEvidence), maxExamples)
	}
	if len(f.ExampleEvidence[0]) > maxEvidence+len("…") {
		t.Fatalf("evidence not truncated: %d bytes", len(f.ExampleEvidence[0]))
	}
}

// Every type named in conditionGroups must be emitted by some rule, so a
// typo cannot silently leave a rule outside its group.
func TestConditionGroupsNameRealEventTypes(t *testing.T) {
	var src strings.Builder
	for _, pattern := range []string{"../../analyzer/rules/*.go", "../../analyzer/*.go"} {
		files, _ := filepath.Glob(pattern)
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			src.Write(b)
		}
	}
	for cond, types := range conditionGroups {
		for _, ty := range types {
			if !strings.Contains(src.String(), `"`+ty+`"`) {
				t.Errorf("condition %s lists %s, which no rule emits", cond, ty)
			}
		}
	}
}
