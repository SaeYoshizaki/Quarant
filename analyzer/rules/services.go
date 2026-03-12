package rules

import (
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

func NeedsPayloadCapture(p uint16) bool {
	return IsHTTPPort(p) || IsTLSPort(p)
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

	indicators := make([]string, 0, 4)

	pathLower := strings.ToLower(http.Path)
	for _, needle := range []string{"/admin", "/login", "/setup", "/config", "/manage", "/management", "/system"} {
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
