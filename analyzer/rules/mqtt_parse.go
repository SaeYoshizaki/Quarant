package rules

import "strings"

type MQTTInfo struct {
	PacketType  byte
	PacketName  string
	Protocol    string
	Level       byte
	ClientID    string
	Username    string
	Password    string
	Topic       string
	Payload     []byte
	Plaintext   bool
	HasUsername bool
	HasPassword bool
}

func IsMQTTPort(p uint16) bool {
	return p == 1883
}

func ParseMQTT(payload []byte) (*MQTTInfo, bool) {
	var merged *MQTTInfo
	offset := 0
	for offset < len(payload) {
		info, consumed, ok := parseMQTTPacket(payload[offset:])
		if !ok {
			break
		}
		if merged == nil {
			merged = info
		} else {
			mergeMQTTInfo(merged, info)
		}
		offset += consumed
	}

	if merged == nil {
		return nil, false
	}
	return merged, true
}

func parseMQTTPacket(payload []byte) (*MQTTInfo, int, bool) {
	if len(payload) < 2 {
		return nil, 0, false
	}

	packetType := payload[0] >> 4
	flags := payload[0] & 0x0f
	remainingLength, used, ok := parseMQTTRemainingLength(payload[1:])
	if !ok {
		return nil, 0, false
	}

	packetStart := 1 + used
	packetEnd := packetStart + remainingLength
	if remainingLength < 0 || packetEnd > len(payload) {
		return nil, 0, false
	}

	packet := payload[packetStart:packetEnd]
	switch packetType {
	case 1:
		info, ok := parseMQTTConnect(packet)
		if !ok {
			return nil, 0, false
		}
		return info, packetEnd, true
	case 3:
		info, ok := parseMQTTPublish(flags, packet)
		if !ok {
			return nil, 0, false
		}
		return info, packetEnd, true
	default:
		return &MQTTInfo{
			PacketType: packetType,
			PacketName: mqttPacketName(packetType),
			Plaintext:  true,
		}, packetEnd, true
	}
}

func mergeMQTTInfo(dst, src *MQTTInfo) {
	if dst.PacketName == "" || dst.PacketName == "MQTT" {
		dst.PacketName = src.PacketName
		dst.PacketType = src.PacketType
	}
	if dst.Protocol == "" {
		dst.Protocol = src.Protocol
	}
	if dst.Level == 0 {
		dst.Level = src.Level
	}
	if dst.ClientID == "" {
		dst.ClientID = src.ClientID
	}
	if dst.Username == "" {
		dst.Username = src.Username
	}
	if dst.Password == "" {
		dst.Password = src.Password
	}
	if dst.Topic == "" {
		dst.Topic = src.Topic
	}
	if len(dst.Payload) == 0 {
		dst.Payload = src.Payload
	}
	dst.Plaintext = dst.Plaintext || src.Plaintext
	dst.HasUsername = dst.HasUsername || src.HasUsername
	dst.HasPassword = dst.HasPassword || src.HasPassword
}

func LooksLikeMQTT(payload []byte) bool {
	info, ok := ParseMQTT(payload)
	return ok && info != nil
}

func parseMQTTConnect(packet []byte) (*MQTTInfo, bool) {
	offset := 0
	protocol, ok := readMQTTString(packet, &offset)
	if !ok {
		return nil, false
	}
	if protocol != "MQTT" && protocol != "MQIsdp" {
		return nil, false
	}
	if offset+4 > len(packet) {
		return nil, false
	}

	level := packet[offset]
	connectFlags := packet[offset+1]
	offset += 4 // level, flags, keepalive

	if level == 5 {
		propsLen, used, ok := parseMQTTRemainingLength(packet[offset:])
		if !ok || offset+used+propsLen > len(packet) {
			return nil, false
		}
		offset += used + propsLen
	}

	clientID, ok := readMQTTString(packet, &offset)
	if !ok {
		return nil, false
	}

	if connectFlags&0x04 != 0 {
		if _, ok := readMQTTString(packet, &offset); !ok {
			return nil, false
		}
		if _, ok := readMQTTBinary(packet, &offset); !ok {
			return nil, false
		}
	}

	info := &MQTTInfo{
		PacketType: 1,
		PacketName: "CONNECT",
		Protocol:   protocol,
		Level:      level,
		ClientID:   clientID,
		Plaintext:  true,
	}

	if connectFlags&0x80 != 0 {
		username, ok := readMQTTString(packet, &offset)
		if !ok {
			return nil, false
		}
		info.Username = username
		info.HasUsername = strings.TrimSpace(username) != ""
	}

	if connectFlags&0x40 != 0 {
		password, ok := readMQTTBinary(packet, &offset)
		if !ok {
			return nil, false
		}
		info.Password = string(password)
		info.HasPassword = len(password) > 0
	}

	return info, true
}

func parseMQTTPublish(flags byte, packet []byte) (*MQTTInfo, bool) {
	offset := 0
	topic, ok := readMQTTString(packet, &offset)
	if !ok {
		return nil, false
	}

	qos := (flags & 0x06) >> 1
	if qos > 0 {
		if offset+2 > len(packet) {
			return nil, false
		}
		offset += 2
	}

	payload := packet[offset:]
	return &MQTTInfo{
		PacketType: 3,
		PacketName: "PUBLISH",
		Topic:      topic,
		Payload:    payload,
		Plaintext:  true,
	}, true
}

func parseMQTTRemainingLength(data []byte) (int, int, bool) {
	multiplier := 1
	value := 0
	for i := 0; i < len(data) && i < 4; i++ {
		encoded := data[i]
		value += int(encoded&127) * multiplier
		if encoded&128 == 0 {
			return value, i + 1, true
		}
		multiplier *= 128
	}
	return 0, 0, false
}

func readMQTTString(data []byte, offset *int) (string, bool) {
	raw, ok := readMQTTBinary(data, offset)
	if !ok {
		return "", false
	}
	return string(raw), true
}

func readMQTTBinary(data []byte, offset *int) ([]byte, bool) {
	if *offset+2 > len(data) {
		return nil, false
	}
	size := int(data[*offset])<<8 | int(data[*offset+1])
	*offset += 2
	if size < 0 || *offset+size > len(data) {
		return nil, false
	}
	raw := data[*offset : *offset+size]
	*offset += size
	return raw, true
}

func mqttPacketName(packetType byte) string {
	switch packetType {
	case 1:
		return "CONNECT"
	case 2:
		return "CONNACK"
	case 3:
		return "PUBLISH"
	case 4:
		return "PUBACK"
	case 8:
		return "SUBSCRIBE"
	case 12:
		return "PINGREQ"
	case 14:
		return "DISCONNECT"
	default:
		return "MQTT"
	}
}
