package parserdiff

import "testing"

func mqttStr(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s))}, s...) }

// mqttPacket frames body with a fixed header (remaining length < 128 or
// two-byte encoded).
func mqttPacket(hdr byte, body []byte) []byte {
	n := len(body)
	out := []byte{hdr}
	if n < 128 {
		out = append(out, byte(n))
	} else {
		out = append(out, byte(n%128)|0x80, byte(n/128))
	}
	return append(out, body...)
}

// mqttConnect builds a CONNECT. level 5 adds an empty property block (and an
// empty will-property block when will is set).
func mqttConnect(level byte, clientID, user, pass string, will bool) []byte {
	flags := byte(0x02)
	if user != "" {
		flags |= 0x80
	}
	if pass != "" {
		flags |= 0x40
	}
	if will {
		flags |= 0x04
	}
	body := append(mqttStr("MQTT"), level, flags, 0, 60)
	if level == 5 {
		body = append(body, 0)
	}
	body = append(body, mqttStr(clientID)...)
	if will {
		if level == 5 {
			body = append(body, 0)
		}
		body = append(body, mqttStr("dev/status")...)
		body = append(body, mqttStr("offline")...)
	}
	if user != "" {
		body = append(body, mqttStr(user)...)
	}
	if pass != "" {
		body = append(body, mqttStr(pass)...)
	}
	return mqttPacket(0x10, body)
}

func mqttPublish(topic, payload string) []byte {
	return mqttPacket(0x30, append(mqttStr(topic), payload...))
}

func seedMQTT() [][]byte {
	return [][]byte{
		mqttConnect(4, "plug-01", "user", "secret", false),
		append(mqttConnect(4, "sensor", "", "", false), mqttPublish("home/temp", "21.5")...),
		mqttConnect(5, "cam-02", "u", "p", false),
		mqttConnect(4, "bulb", "u", "p", true),
	}
}

func TestMQTTParsersAgreeOnWellFormedStreams(t *testing.T) {
	for i, s := range seedMQTT() {
		res := CompareMQTT(s)
		if res.Class() != "agree" {
			t.Errorf("seed %d: %s %s %+v", i, res.Class(), res.RefReason, res.Mismatches)
		}
	}
}

// Misreads found by FuzzMQTTDifferential (or by reading the code against
// the differential) and fixed in rules.ParseMQTT.
func TestMQTTDifferentialRegressions(t *testing.T) {
	cases := map[string][]byte{
		// MQTT 5 puts will properties before the will topic; skipping them
		// is needed to reach the username and password.
		"v5_will_properties": mqttConnect(5, "cam", "admin", "pw", true),
	}
	for name, raw := range cases {
		res := CompareMQTT(raw)
		if res.Class() != "agree" {
			t.Errorf("%s: %s %s %+v", name, res.Class(), res.RefReason, res.Mismatches)
		}
	}
}

// FuzzMQTTDifferential looks for client streams that Quarant and the
// mochi-mqtt decoder read differently.
//
//	go test ./internal/parserdiff -run '^$' -fuzz FuzzMQTTDifferential -fuzztime 60s
func FuzzMQTTDifferential(f *testing.F) {
	for _, s := range seedMQTT() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := CompareMQTT(data)
		switch res.Class() {
		case "agree", "both_reject", "quarant_lenient":
		default:
			t.Errorf("%s: ref=%q %+v", res.Class(), res.RefReason, res.Mismatches)
		}
	})
}
