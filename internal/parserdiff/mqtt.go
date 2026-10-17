package parserdiff

import (
	"bytes"
	"strings"

	mqttpk "github.com/mochi-mqtt/server/v2/packets"

	"quarant/analyzer/rules"
)

// MQTTView is the normalised view of a client MQTT stream: the first
// non-empty value of each field over the packets that parse, which is how
// rules.ParseMQTT merges a stream. Credentials are compared but never
// reported (see Mismatches in CompareMQTT).
type MQTTView struct {
	Protocol    string
	Level       byte
	ClientID    string
	Username    string
	Password    string
	HasUsername bool
	HasPassword bool
	Topic       string
	Packets     int
}

// ReferenceMQTT decodes the stream with the packet decoder of the mochi-mqtt
// broker (MQTT 3.1, 3.1.1 and 5). Decoding stops at the first packet the
// broker would reject, as rules.ParseMQTT stops at the first it cannot
// parse. ok is false when no packet decodes.
func ReferenceMQTT(data []byte) (MQTTView, string, bool) {
	var v MQTTView
	var version byte
	reason := ""
	for off := 0; off < len(data); {
		var fh mqttpk.FixedHeader
		if err := fh.Decode(data[off]); err != nil {
			reason = "fixed_header: " + err.Error()
			break
		}
		if fh.Type == 0 || fh.Type > mqttpk.Auth {
			reason = "reserved_packet_type"
			break
		}
		rem, used, err := mqttpk.DecodeLength(bytes.NewReader(data[off+1:]))
		// The spec caps the Remaining Length at four bytes (MQTT 3.1.1
		// 2.2.3, 5 1.5.5); mochi-mqtt accepts a fifth whose value overflows
		// to a small length, so the cap is applied here.
		if err != nil || used > 4 || off+1+used+rem > len(data) {
			reason = "remaining_length"
			break
		}
		fh.Remaining = rem
		body := data[off+1+used : off+1+used+rem]
		pk := mqttpk.Packet{FixedHeader: fh, ProtocolVersion: version}
		switch fh.Type {
		case mqttpk.Connect:
			if v.Packets > 0 {
				reason = "second_connect"
				break
			}
			if err := pk.ConnectDecode(body); err != nil {
				reason = "connect: " + err.Error()
				break
			}
			if code := pk.ConnectValidate(); code != mqttpk.CodeSuccess {
				reason = "connect_validate: " + code.Reason
				break
			}
			version = pk.ProtocolVersion
			setStr(&v.Protocol, string(pk.Connect.ProtocolName))
			if v.Level == 0 {
				v.Level = version
			}
			setStr(&v.ClientID, pk.Connect.ClientIdentifier)
			if pk.Connect.UsernameFlag {
				setStr(&v.Username, string(pk.Connect.Username))
				v.HasUsername = v.HasUsername || strings.TrimSpace(string(pk.Connect.Username)) != ""
			}
			if pk.Connect.PasswordFlag {
				setStr(&v.Password, string(pk.Connect.Password))
				v.HasPassword = v.HasPassword || len(pk.Connect.Password) > 0
			}
		case mqttpk.Publish:
			if version == 0 {
				// Without a CONNECT the protocol level (and so whether
				// properties follow the topic) is unknown; 3.1.1 is the
				// common case and only the topic is compared.
				pk.ProtocolVersion = 4
			}
			if err := pk.PublishDecode(body); err != nil {
				reason = "publish: " + err.Error()
				break
			}
			setStr(&v.Topic, pk.TopicName)
		}
		if reason != "" {
			break
		}
		v.Packets++
		off += 1 + used + rem
	}
	return v, reason, v.Packets > 0
}

// mqttSemanticReject reports whether the broker rejected the stream for a
// rule above framing (see MQTTResult.Class).
func mqttSemanticReject(reason string) bool {
	return strings.Contains(reason, "utf-8") || strings.Contains(reason, "dup true with no qos") || strings.Contains(reason, "client identifier not valid") || strings.Contains(reason, "will topic") || strings.Contains(reason, "properties") || strings.HasPrefix(reason, "connect_validate:") || reason == "second_connect"
}

func setStr(dst *string, s string) {
	if *dst == "" {
		*dst = s
	}
}

// QuarantMQTT is the production parser.
func QuarantMQTT(data []byte) (MQTTView, bool) {
	info, ok := rules.ParseMQTT(data)
	if !ok {
		return MQTTView{}, false
	}
	return MQTTView{Protocol: info.Protocol, Level: info.Level, ClientID: info.ClientID, Username: info.Username,
		Password: info.Password, HasUsername: info.HasUsername, HasPassword: info.HasPassword, Topic: info.Topic}, true
}

// MQTTResult is one differential comparison of an MQTT client stream.
type MQTTResult struct {
	QuarantOK   bool
	ReferenceOK bool
	RefReason   string
	// Mismatches name the differing fields. Values are included only for
	// non-secret fields; username and password show as "<differs>".
	Mismatches []Mismatch
}

// Class buckets the comparison: agree, both_reject, quarant_only,
// reference_only, field_mismatch, credential_mismatch (the fields the
// credential rules read differ: a missed or invented cleartext login), and
// quarant_lenient: only Quarant accepts, because the broker enforces a
// semantic rule (UTF-8 strings, flag consistency in CONNECT) on a packet
// whose framing is valid. The bytes still crossed the network, so reading
// them is what a passive observer should do.
func (r MQTTResult) Class() string {
	switch {
	case r.QuarantOK && r.ReferenceOK && len(r.Mismatches) == 0:
		return "agree"
	case !r.QuarantOK && !r.ReferenceOK:
		return "both_reject"
	case !r.QuarantOK:
		return "reference_only"
	case !r.ReferenceOK && mqttSemanticReject(r.RefReason):
		return "quarant_lenient"
	case !r.ReferenceOK:
		return "quarant_only"
	case mqttSemanticReject(r.RefReason):
		// The broker stopped at a later packet that Quarant still read.
		return "quarant_lenient"
	}
	for _, m := range r.Mismatches {
		switch m.Field {
		case "username", "password", "has_username", "has_password":
			return "credential_mismatch"
		}
	}
	return "field_mismatch"
}

// CompareMQTT runs both parsers on a client stream.
func CompareMQTT(data []byte) MQTTResult {
	q, qok := QuarantMQTT(data)
	ref, reason, rok := ReferenceMQTT(data)
	res := MQTTResult{QuarantOK: qok, ReferenceOK: rok, RefReason: reason}
	if !qok || !rok {
		return res
	}
	add := func(field, a, b string, secret bool) {
		if a == b {
			return
		}
		if secret {
			a, b = "<differs>", "<differs>"
		}
		res.Mismatches = append(res.Mismatches, Mismatch{Field: field, Quarant: a, Reference: b})
	}
	b := func(x bool) string {
		if x {
			return "true"
		}
		return "false"
	}
	add("protocol", q.Protocol, ref.Protocol, false)
	add("level", string('0'+q.Level), string('0'+ref.Level), false)
	add("client_id", q.ClientID, ref.ClientID, true)
	add("username", q.Username, ref.Username, true)
	add("password", q.Password, ref.Password, true)
	add("has_username", b(q.HasUsername), b(ref.HasUsername), false)
	add("has_password", b(q.HasPassword), b(ref.HasPassword), false)
	add("topic", q.Topic, ref.Topic, false)
	return res
}
