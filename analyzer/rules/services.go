package rules

import (
	"bytes"
	"net"
	"strings"
)

var insecureServicePorts = map[uint16]string{
	21:   "ftp",
	23:   "telnet",
	2323: "telnet",
	554:  "rtsp",
	1883: "mqtt",
	5683: "coap",
}

func IsHTTPPort(p uint16) bool {
	switch p {
	case 80, 8000, 8080, 8888:
		return true
	default:
		return false
	}
}

func IsTLSPort(p uint16) bool {
	switch p {
	case 443, 8443, 9443, 10443, 8883:
		return true
	default:
		return false
	}
}

func IsInsecureServicePort(p uint16) bool {
	_, ok := insecureServicePorts[p]
	return ok
}

func NeedsPayloadCapture(p uint16) bool {
	if IsHTTPPort(p) || IsTLSPort(p) {
		return true
	}

	if _, ok := insecureServicePorts[p]; ok {
		return true
	}

	return false
}

func InsecureServiceNameByPort(p uint16) (string, bool) {
	name, ok := insecureServicePorts[p]
	return name, ok
}

func IsPublicIPv4(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	ip = ip.To4()
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}

	if ip[0] == 10 {
		return false
	}
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return false
	}
	if ip[0] == 192 && ip[1] == 168 {
		return false
	}
	if ip[0] == 169 && ip[1] == 254 {
		return false
	}
	return true
}

func DetectHTTPAdminIndicators(http *HTTPInfo) ([]string, bool) {
	if http == nil {
		return nil, false
	}

	indicators := make([]string, 0, 6)

	pathLower := strings.ToLower(http.Path)
	for _, needle := range []string{
		"/admin",
		"/login",
		"/setup",
		"/config",
		"/manage",
		"/management",
		"/system",
		"/webui",
		"/cgi-bin",
		"/manager",
		"/control",
		"/dashboard",
	} {
		if strings.Contains(pathLower, needle) {
			indicators = append(indicators, "path="+needle)
		}
	}

	if host := strings.ToLower(http.Headers["host"]); host != "" {
		for _, needle := range []string{"router", "camera", "cam", "nvr", "dvr", "iot", "admin"} {
			if strings.Contains(host, needle) {
				indicators = append(indicators, "host~"+needle)
				break
			}
		}
	}

	if v := strings.ToLower(http.Headers["authorization"]); v != "" {
		if strings.Contains(v, "basic") {
			indicators = append(indicators, "authorization=basic")
		} else {
			indicators = append(indicators, "authorization=present")
		}
	}

	if v := strings.ToLower(http.Headers["www-authenticate"]); v != "" {
		indicators = append(indicators, "www-authenticate")
	}

	return indicators, len(indicators) > 0
}

func DetectTelnetIndicators(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}

	s := strings.ToLower(string(payload))
	indicators := make([]string, 0, 6)

	for _, needle := range []string{
		"login:",
		"password:",
		"username:",
		"last login",
		"busybox",
		"welcome to",
	} {
		if strings.Contains(s, needle) {
			indicators = append(indicators, needle)
		}
	}

	return indicators
}

func DetectFTPIndicators(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}

	s := strings.ToUpper(string(payload))
	indicators := make([]string, 0, 5)

	for _, needle := range []string{
		"220 ",
		"USER ",
		"PASS ",
		"230 ",
		"530 ",
	} {
		if strings.Contains(s, needle) {
			indicators = append(indicators, strings.TrimSpace(needle))
		}
	}

	return indicators
}

func DetectRTSPIndicators(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}

	s := strings.ToUpper(string(payload))
	indicators := make([]string, 0, 5)

	for _, needle := range []string{
		"RTSP/1.0",
		"OPTIONS ",
		"DESCRIBE ",
		"SETUP ",
		"PLAY ",
	} {
		if strings.Contains(s, needle) {
			indicators = append(indicators, strings.TrimSpace(needle))
		}
	}

	return indicators
}

func DetectMQTTIndicators(payload []byte) []string {
	if len(payload) == 0 {
		return nil
	}

	indicators := make([]string, 0, 2)

	if bytes.Contains(payload, []byte("MQTT")) {
		indicators = append(indicators, "MQTT")
	}

	if len(payload) > 0 && payload[0] == 0x10 {
		indicators = append(indicators, "CONNECT")
	}

	return indicators
}

func DetectServiceIndicators(service string, payload []byte) []string {
	switch service {
	case "telnet":
		return DetectTelnetIndicators(payload)
	case "ftp":
		return DetectFTPIndicators(payload)
	case "rtsp":
		return DetectRTSPIndicators(payload)
	case "mqtt":
		return DetectMQTTIndicators(payload)
	default:
		return nil
	}
}