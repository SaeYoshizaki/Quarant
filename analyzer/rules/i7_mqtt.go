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
		Message:        "Plain MQTT traffic was observed.",
		OWASPTags:      uniqueTags("I2", "I7"),
		Confidence:     "high",
		ObservedFact:   "Plain MQTT traffic was observed.",
		Inference:      "MQTT metadata and payloads may be exposed in transit when transport encryption is absent.",
		Limitation:     "Passive monitoring does not confirm whether TLS is available on another port or whether this topic carries sensitive data.",
		Recommendation: "Use MQTT over TLS, usually port 8883, if supported.",
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
			Message:        "MQTT password was observed over plaintext transport.",
			Evidence:       "mqtt_password=***",
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "MQTT password field was observed in plaintext traffic.",
			Inference:      "Credentials may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine password strength or whether the credential is shared, default, or hardcoded.",
			Recommendation: "Use MQTT over TLS, rotate exposed credentials if needed, and review broker authentication settings.",
		}, true
	}

	if ctx.MQTT.HasUsername && looksSensitiveIdentifier(ctx.MQTT.Username) {
		return Match{
			Message:        "MQTT username-like identifier was observed over plaintext transport.",
			Evidence:       "mqtt_username=***",
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "MQTT username-like identifier was observed in plaintext traffic.",
			Inference:      "An authentication identifier may be exposed in transit.",
			Limitation:     "Passive monitoring cannot confirm whether the value is sensitive on its own or whether stronger credentials are used elsewhere.",
			Recommendation: "Use MQTT over TLS and review broker authentication settings.",
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
			Message:        "Sensitive MQTT topic component was observed over plaintext transport.",
			Evidence:       ev,
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "Sensitive MQTT topic component was observed in plaintext traffic.",
			Inference:      "Topic names may reveal tokens or identifiers in transit.",
			Limitation:     "Passive monitoring cannot determine whether the value remains valid or how it is used by the broker.",
			Recommendation: "Avoid embedding sensitive values in topics and prefer MQTT over TLS.",
		}, true
	}

	if len(ctx.MQTT.Payload) == 0 {
		return Match{}, false
	}

	if msg, ev, ok := DetectSensitiveHTTPBody("", ctx.MQTT.Payload); ok {
		return Match{
			Message:        "Sensitive data appears in plaintext MQTT payload: " + msg,
			Evidence:       ev,
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "Sensitive data patterns were observed in a plaintext MQTT payload.",
			Inference:      "Credentials, tokens, or identifiers may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine whether the value is active or whether the device supports an encrypted transport alternative.",
			Recommendation: "Use MQTT over TLS and review which fields are published in plaintext payloads.",
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
