package device

import "strings"

func inferDevice(d *DeviceProfile) {

	for s := range d.Servers {

		if strings.Contains(strings.ToLower(s), "goahead") {
			d.DeviceType = "IP Camera"
			d.Confidence += 0.2
		}

		if strings.Contains(strings.ToLower(s), "boa") {
			d.DeviceType = "IoT Device"
			d.Confidence += 0.1
		}
	}

	for h := range d.Hosts {

		if strings.Contains(h, "tplink") {
			d.Vendor = "TP-Link"
			d.Confidence += 0.4
		}

		if strings.Contains(h, "hikvision") {
			d.Vendor = "Hikvision"
			d.Confidence += 0.4
		}
	}
}

func EnrichFromHTTP(d *DeviceProfile, headers map[string]string) {

	if host, ok := headers["host"]; ok {
		d.Hosts[host] = true
		d.Evidence = append(d.Evidence, "Host="+host)
	}

	if ua, ok := headers["user-agent"]; ok {
		d.UserAgents[ua] = true
		d.Evidence = append(d.Evidence, "UA="+ua)
	}

	if srv, ok := headers["server"]; ok {
		d.Servers[srv] = true
		d.Evidence = append(d.Evidence, "Server="+srv)
	}

	inferDevice(d)
}
