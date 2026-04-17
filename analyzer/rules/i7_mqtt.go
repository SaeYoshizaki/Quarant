package rules

type I7MQTTPlaintextRule struct{}

func (r *I7MQTTPlaintextRule) ID() string         { return "I7_MQTT_PLAINTEXT" }
func (r *I7MQTTPlaintextRule) Category() string   { return "I7" }
func (r *I7MQTTPlaintextRule) Severity() Severity { return SeverityWarning }
func (r *I7MQTTPlaintextRule) Type() string       { return "INSECURE_MQTT" }

func (r *I7MQTTPlaintextRule) Apply(ctx *Context) (Match, bool) {
	if ctx.MQTT == nil || !ctx.MQTT.Plaintext {
		return Match{}, false
	}

	ev := Match{
		Message: "Plaintext MQTT detected",
	}
	if ctx.Debug {
		ev.Evidence = "packet=" + ctx.MQTT.PacketName
		if ctx.MQTT.ClientID != "" {
			ev.Evidence += " client_id=***"
		}
		if ctx.MQTT.Topic != "" {
			ev.Evidence += " topic=" + ctx.MQTT.Topic
		}
	}
	return ev, true
}

type I7MQTTCredentialsRule struct{}

func (r *I7MQTTCredentialsRule) ID() string         { return "I7_MQTT_CREDENTIALS" }
func (r *I7MQTTCredentialsRule) Category() string   { return "I7" }
func (r *I7MQTTCredentialsRule) Severity() Severity { return SeverityCritical }
func (r *I7MQTTCredentialsRule) Type() string       { return "INSECURE_MQTT_CREDENTIALS" }

func (r *I7MQTTCredentialsRule) Apply(ctx *Context) (Match, bool) {
	if ctx.MQTT == nil {
		return Match{}, false
	}

	if ctx.MQTT.HasPassword {
		return Match{
			Message:  "MQTT password sent over plaintext",
			Evidence: "mqtt_password=***",
		}, true
	}

	if ctx.MQTT.HasUsername && looksSensitiveIdentifier(ctx.MQTT.Username) {
		return Match{
			Message:  "MQTT username-like identifier sent over plaintext",
			Evidence: "mqtt_username=***",
		}, true
	}

	return Match{}, false
}

type I7MQTTSensitivePayloadRule struct{}

func (r *I7MQTTSensitivePayloadRule) ID() string         { return "I7_MQTT_PAYLOAD_SECRET" }
func (r *I7MQTTSensitivePayloadRule) Category() string   { return "I7" }
func (r *I7MQTTSensitivePayloadRule) Severity() Severity { return SeverityCritical }
func (r *I7MQTTSensitivePayloadRule) Type() string {
	return "INSECURE_MQTT_PAYLOAD_SECRET"
}

func (r *I7MQTTSensitivePayloadRule) Apply(ctx *Context) (Match, bool) {
	if ctx.MQTT == nil {
		return Match{}, false
	}

	if ev, ok := detectSensitiveMQTTTopic(ctx.MQTT.Topic); ok {
		return Match{
			Message:  "Sensitive MQTT topic observed over plaintext",
			Evidence: ev,
		}, true
	}

	if len(ctx.MQTT.Payload) == 0 {
		return Match{}, false
	}

	if msg, ev, ok := DetectSensitiveHTTPBody("", ctx.MQTT.Payload); ok {
		return Match{
			Message:  "Sensitive data appears in plaintext MQTT payload: " + msg,
			Evidence: ev,
		}, true
	}

	return Match{}, false
}

func detectSensitiveMQTTTopic(topic string) (string, bool) {
	if topic == "" {
		return "", false
	}
	for _, part := range splitMQTTTopic(topic) {
		if HasSensitiveKey(part) || looksSuspiciousKeyName(part) {
			if ev, ok := detectSensitiveField(part, "AbCdEf1234567890ZYXWVutsrq", nil); ok {
				return "topic/" + ev, true
			}
		}
	}
	return "", false
}

func splitMQTTTopic(topic string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(topic); i++ {
		if i == len(topic) || topic[i] == '/' {
			if start < i {
				out = append(out, topic[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func init() {
	Register(&I7MQTTPlaintextRule{})
	Register(&I7MQTTCredentialsRule{})
	Register(&I7MQTTSensitivePayloadRule{})
}
