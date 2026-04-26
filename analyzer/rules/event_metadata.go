package rules

import "strings"

func uniqueTags(values ...string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func joinRecommendations(values ...string) string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return strings.Join(out, " ")
}

func serviceDisplayName(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "telnet":
		return "Telnet"
	case "ftp":
		return "FTP"
	case "mqtt":
		return "MQTT"
	case "rtsp":
		return "RTSP"
	case "coap":
		return "CoAP"
	default:
		return strings.ToUpper(strings.TrimSpace(service))
	}
}

func i2ServiceRecommendation(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "telnet":
		return "Disable Telnet if not required, or replace it with SSH or a vendor-supported secure management method."
	case "ftp":
		return "Disable FTP if not required, or use a secure alternative such as SFTP/FTPS if supported."
	case "mqtt":
		return "Use MQTT over TLS, usually port 8883, if supported."
	case "rtsp":
		return "Confirm whether video streaming is intended and restrict access to trusted local networks."
	case "coap":
		return "Use DTLS-protected CoAP or restrict access where possible."
	default:
		return "Restrict the service to trusted networks and disable it if not required."
	}
}

func i2ServiceRiskText(service string) string {
	switch strings.ToLower(strings.TrimSpace(service)) {
	case "telnet":
		return "Telnet is a plaintext remote login service. Credentials and commands may be exposed if used on an untrusted network."
	case "ftp":
		return "FTP commonly transmits credentials and file contents without encryption."
	case "mqtt":
		return "Plain MQTT on port 1883 is commonly used by IoT devices but does not provide transport encryption by itself."
	case "rtsp":
		return "RTSP is often used for camera or video streaming. If exposed unexpectedly, it may create privacy or surveillance risk."
	case "coap":
		return "Plain CoAP does not provide transport encryption by itself."
	default:
		return serviceDisplayName(service) + " may expose device functionality on an untrusted network."
	}
}
