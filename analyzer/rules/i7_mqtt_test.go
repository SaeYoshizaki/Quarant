package rules

import "testing"

func TestParseMQTTConnectWithCredentials(t *testing.T) {
	payload := mqttConnectPacket("device-12345678", "sensor-user", "hunter2")

	info, ok := ParseMQTT(payload)
	if !ok {
		t.Fatal("expected MQTT CONNECT to parse")
	}
	if info.PacketName != "CONNECT" {
		t.Fatalf("unexpected packet name: %s", info.PacketName)
	}
	if info.ClientID != "device-12345678" {
		t.Fatalf("unexpected client id: %s", info.ClientID)
	}
	if !info.HasUsername || !info.HasPassword {
		t.Fatalf("expected username and password flags: %+v", info)
	}
}

func TestI7MQTTCredentialsDetectsPassword(t *testing.T) {
	info, ok := ParseMQTT(mqttConnectPacket("device-12345678", "sensor-user", "hunter2"))
	if !ok {
		t.Fatal("expected MQTT CONNECT to parse")
	}

	match, ok := (&I7MQTTCredentialsRule{}).Apply(&Context{MQTT: info})
	if !ok {
		t.Fatal("expected MQTT credentials to be detected")
	}
	if match.Evidence != "mqtt_password=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7MQTTCredentialsDoesNotDetectAnonymousConnect(t *testing.T) {
	info, ok := ParseMQTT(mqttConnectPacket("device-12345678", "", ""))
	if !ok {
		t.Fatal("expected MQTT CONNECT to parse")
	}

	if _, ok := (&I7MQTTCredentialsRule{}).Apply(&Context{MQTT: info}); ok {
		t.Fatal("did not expect anonymous MQTT CONNECT to trigger credential alert")
	}
}

func TestI7MQTTSensitivePayloadDetectsJSONToken(t *testing.T) {
	info, ok := ParseMQTT(mqttPublishPacket("device/status", []byte(`{"token":"AbCdEf1234567890ZYXWVutsrq"}`)))
	if !ok {
		t.Fatal("expected MQTT PUBLISH to parse")
	}

	match, ok := (&I7MQTTSensitivePayloadRule{}).Apply(&Context{MQTT: info})
	if !ok {
		t.Fatal("expected sensitive MQTT payload to be detected")
	}
	if match.Evidence != "token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7MQTTSensitivePayloadDetectsPublishAfterConnect(t *testing.T) {
	var flow []byte
	flow = append(flow, mqttConnectPacket("device-12345678", "", "")...)
	flow = append(flow, mqttPublishPacket("device/status", []byte(`{"token":"AbCdEf1234567890ZYXWVutsrq"}`))...)

	info, ok := ParseMQTT(flow)
	if !ok {
		t.Fatal("expected MQTT flow to parse")
	}

	match, ok := (&I7MQTTSensitivePayloadRule{}).Apply(&Context{MQTT: info})
	if !ok {
		t.Fatal("expected sensitive MQTT payload after CONNECT to be detected")
	}
	if match.Evidence != "token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7MQTTSensitivePayloadDetectsSensitiveTopic(t *testing.T) {
	info, ok := ParseMQTT(mqttPublishPacket("devices/token/report", []byte(`{"temperature":21}`)))
	if !ok {
		t.Fatal("expected MQTT PUBLISH to parse")
	}

	match, ok := (&I7MQTTSensitivePayloadRule{}).Apply(&Context{MQTT: info})
	if !ok {
		t.Fatal("expected sensitive MQTT topic to be detected")
	}
	if match.Evidence != "topic/token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func mqttConnectPacket(clientID, username, password string) []byte {
	var body []byte
	body = appendMQTTString(body, "MQTT")
	body = append(body, 0x04)
	flags := byte(0x02)
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	body = append(body, flags, 0x00, 0x3c)
	body = appendMQTTString(body, clientID)
	if username != "" {
		body = appendMQTTString(body, username)
	}
	if password != "" {
		body = appendMQTTString(body, password)
	}

	return appendMQTTFixedHeader(0x10, body)
}

func mqttPublishPacket(topic string, body []byte) []byte {
	var packet []byte
	packet = appendMQTTString(packet, topic)
	packet = append(packet, body...)
	return appendMQTTFixedHeader(0x30, packet)
}

func appendMQTTString(dst []byte, value string) []byte {
	dst = append(dst, byte(len(value)>>8), byte(len(value)))
	dst = append(dst, []byte(value)...)
	return dst
}

func appendMQTTFixedHeader(first byte, body []byte) []byte {
	out := []byte{first}
	n := len(body)
	for {
		encoded := byte(n % 128)
		n /= 128
		if n > 0 {
			encoded |= 128
		}
		out = append(out, encoded)
		if n == 0 {
			break
		}
	}
	out = append(out, body...)
	return out
}
