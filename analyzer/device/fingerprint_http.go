package device

import (
	"sort"
	"strings"
)

func addScore(scores map[string]float64, key string, delta float64) {
	if key == "" || delta <= 0 {
		return
	}
	scores[key] += delta
}

func bestScoredLabel(scores map[string]float64, prefer string) (string, float64) {
	bestLabel := ""
	bestScore := 0.0

	labels := make([]string, 0, len(scores))
	for label := range scores {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		score := scores[label]
		if score > bestScore || (score == bestScore && label == prefer) {
			bestLabel = label
			bestScore = score
		}
	}

	return bestLabel, bestScore
}

func recomputeDeviceIdentity(d *DeviceProfile) {
	typeScores := map[string]float64{}
	vendorScores := map[string]float64{}

	for s := range d.Servers {
		server := strings.ToLower(s)

		if strings.Contains(server, "goahead") {
			addScore(typeScores, "IP Camera", 0.2)
		}
		if strings.Contains(server, "boa") {
			addScore(typeScores, "IoT Device", 0.1)
		}
	}

	for h := range d.Hosts {
		host := strings.ToLower(h)

		switch {
		case strings.Contains(host, "tplinkcloud") || strings.Contains(host, "kasa"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "Smart Home Controller", 0.5)
		case strings.Contains(host, "smartthings") || strings.Contains(host, "meethue"):
			addScore(typeScores, "Smart Home Hub", 0.5)
		case strings.Contains(host, "switch-bot") ||
			strings.Contains(host, "ewelink") ||
			strings.Contains(host, "shelly") ||
			strings.Contains(host, "tuyaus") ||
			strings.Contains(host, "meross"):
			addScore(typeScores, "Smart Home Controller", 0.4)
		case strings.Contains(host, "tapo"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "hikvision"):
			addScore(vendorScores, "Hikvision", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "reolink"):
			addScore(vendorScores, "Reolink", 0.3)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(host, "alexa") || strings.Contains(host, "assistant.google") || strings.Contains(host, "siri.apple"):
			addScore(typeScores, "Voice Assistant Speaker", 0.4)
		case strings.Contains(host, "aqara") || strings.Contains(host, "sensor"):
			addScore(typeScores, "Sensor", 0.3)
		}
	}

	for sni := range d.SNIValues {
		value := strings.ToLower(sni)

		switch {
		case strings.Contains(value, "tplinkcloud") || strings.Contains(value, "kasa"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "Smart Home Controller", 0.5)
		case strings.Contains(value, "smartthings") || strings.Contains(value, "meethue"):
			addScore(typeScores, "Smart Home Hub", 0.5)
		case strings.Contains(value, "hikvision"):
			addScore(vendorScores, "Hikvision", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(value, "tapo"):
			addScore(vendorScores, "TP-Link", 0.4)
			addScore(typeScores, "IP Camera", 0.4)
		case strings.Contains(value, "reolink"):
			addScore(vendorScores, "Reolink", 0.3)
			addScore(typeScores, "IP Camera", 0.4)
		}
	}

	for ua := range d.UserAgents {
		agent := strings.ToLower(strings.TrimSpace(ua))

		switch {
		case strings.Contains(agent, "tapo-camera"),
			strings.Contains(agent, "ipcamera"),
			strings.Contains(agent, "ipcam"),
			strings.Contains(agent, "camera"):
			addScore(typeScores, "IP Camera", 0.6)
			if strings.Contains(agent, "tapo") || strings.Contains(agent, "tplink") {
				addScore(vendorScores, "TP-Link", 0.3)
			}

		case strings.Contains(agent, "kasa"),
			strings.Contains(agent, "tplink-smartplug"),
			strings.Contains(agent, "tplink controller"):
			addScore(typeScores, "Smart Home Controller", 0.6)
			addScore(vendorScores, "TP-Link", 0.3)

		case strings.Contains(agent, "smartthingshub"),
			strings.Contains(agent, "smartthings hub"),
			strings.Contains(agent, "hue-bridge"),
			strings.Contains(agent, "aqara hub"):
			addScore(typeScores, "Smart Home Hub", 0.6)

		case strings.Contains(agent, "alexa"),
			strings.Contains(agent, "echo"),
			strings.Contains(agent, "assistant"),
			strings.Contains(agent, "homepod"):
			addScore(typeScores, "Voice Assistant Speaker", 0.4)

		case strings.Contains(agent, "sensor"),
			strings.Contains(agent, "aqara"),
			strings.Contains(agent, "switchbot-meter"):
			addScore(typeScores, "Sensor", 0.3)
		}
	}

	bestType, bestTypeScore := bestScoredLabel(typeScores, d.DeviceType)
	bestVendor, bestVendorScore := bestScoredLabel(vendorScores, d.Vendor)

	d.TypeScores = typeScores
	d.DeviceType = bestType
	d.Vendor = bestVendor
	d.Confidence = bestTypeScore + bestVendorScore
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

	recomputeDeviceIdentity(d)
}

func InferFlowFromHTTP(headers map[string]string) *DeviceProfile {
	d := NewProfile("")
	EnrichFromHTTP(d, headers)
	return d
}
