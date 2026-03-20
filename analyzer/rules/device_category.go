package rules

import "strings"

func MapDeviceTypeToCategory(deviceType string) string {
	t := strings.ToLower(deviceType)

	switch {
	case strings.Contains(t, "camera"):
		return "Camera"

	case strings.Contains(t, "plug"),
		strings.Contains(t, "light"):
		return "SmartPlugLight"

	case strings.Contains(t, "sensor"):
		return "Sensor"

	case strings.Contains(t, "speaker"),
		strings.Contains(t, "voice"),
		strings.Contains(t, "assistant"):
		return "VoiceAssistant"

	case strings.Contains(t, "hub"),
		strings.Contains(t, "bridge"),
		strings.Contains(t, "router"):
		return "Hub"
	}

	return "Unknown"
}
