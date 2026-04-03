package device

import "strings"

func inferDevice(d *DeviceProfile) {
	for s := range d.Servers {
		server := strings.ToLower(s)

		if strings.Contains(server, "goahead") {
			d.DeviceType = "IP Camera"
			d.Confidence += 0.2
		}

		if strings.Contains(server, "boa") {
			d.DeviceType = "IoT Device"
			d.Confidence += 0.1
		}
	}

	for h := range d.Hosts {
		host := strings.ToLower(h)

		if strings.Contains(host, "tplink") || strings.Contains(host, "tapo") {
			d.Vendor = "TP-Link"
			d.Confidence += 0.4
			if d.DeviceType == "" {
				d.DeviceType = "IP Camera"
			}
		}

		if strings.Contains(host, "hikvision") {
			d.Vendor = "Hikvision"
			d.DeviceType = "IP Camera"
			d.Confidence += 0.4
		}

		if strings.Contains(host, "alexa") || strings.Contains(host, "assistant.google") {
			d.DeviceType = "Voice Assistant Speaker"
			d.Confidence += 0.3
		}

		if strings.Contains(host, "aqara") || strings.Contains(host, "sensor") {
			d.DeviceType = "Sensor"
			d.Confidence += 0.2
		}
	}

	for ua := range d.UserAgents {
		agent := strings.ToLower(strings.TrimSpace(ua))

		if strings.Contains(agent, "tapo") ||
		strings.Contains(agent, "camera") ||
		strings.Contains(agent, "ipcam") {

			d.DeviceType = "IP Camera"
			if d.Vendor == "" && strings.Contains(agent, "tapo") {
				d.Vendor = "TP-Link"
			}
			d.Confidence += 0.6
		}

		switch {
		case strings.Contains(agent, "tapo-camera"),
			strings.Contains(agent, "ipcamera"),
			strings.Contains(agent, "camera"):
			d.DeviceType = "IP Camera"
			if d.Vendor == "" && (strings.Contains(agent, "tapo") || strings.Contains(agent, "tplink")) {
				d.Vendor = "TP-Link"
			}
			d.Confidence += 0.6

		case strings.Contains(agent, "alexa"),
			strings.Contains(agent, "echo"),
			strings.Contains(agent, "assistant"),
			strings.Contains(agent, "homepod"):
			d.DeviceType = "Voice Assistant Speaker"
			d.Confidence += 0.4

		case strings.Contains(agent, "sensor"),
			strings.Contains(agent, "aqara"),
			strings.Contains(agent, "switchbot-meter"):
			d.DeviceType = "Sensor"
			d.Confidence += 0.3
		}
	}
}

func EnrichFromHTTP(d *DeviceProfile, headers map[string]string) {
	if host, ok := headers["host"]; ok {
		d.Hosts[host] = true
		d.Evidence = appendUnique(d.Evidence, "Host="+host)
	}

	if ua, ok := headers["user-agent"]; ok {
		d.UserAgents[ua] = true
		d.Evidence = appendUnique(d.Evidence, "UA="+ua)
	}

	if srv, ok := headers["server"]; ok {
		d.Servers[srv] = true
		d.Evidence = appendUnique(d.Evidence, "Server="+srv)
	}

	inferDevice(d)
}
