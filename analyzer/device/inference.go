package device

import (
	"fmt"
	"strings"

	"quarant/analyzer/rules"
)

type InferenceSource string

const (
	InferenceSourceKnown    InferenceSource = "known"
	InferenceSourceInferred InferenceSource = "inferred"
	InferenceSourceUnknown  InferenceSource = "unknown"
)

type Classification struct {
	Category        string
	DeviceType      string
	InferenceSource InferenceSource
	ConfidenceScore float64
	ConfidenceLabel string
	Reasons         []string
	Scores          map[string]float64
}

func (c Classification) NormalizedCategory() string {
	category := strings.TrimSpace(c.Category)
	if category == "" || category == "Unknown" {
		return "GenericIoT"
	}
	return category
}

func (c Classification) ConfidenceSummary() string {
	label := strings.TrimSpace(c.ConfidenceLabel)
	if label == "" {
		label = "unknown"
	}
	return fmt.Sprintf("%s(%.2f)", label, c.ConfidenceScore)
}

func normalizedKnownConfidence(score float64) float64 {
	if score <= 0 {
		return 0
	}
	if score >= 1.0 {
		return 1.0
	}
	return 0.9
}

func resolveClassification(d *DeviceProfile, knownType string, knownScore float64) Classification {
	if known := resolveKnownClassification(d, knownType, knownScore); known != nil {
		return *known
	}
	if inferred := resolveInferredClassification(d); inferred != nil {
		return *inferred
	}
	return Classification{
		Category:        "GenericIoT",
		DeviceType:      "",
		InferenceSource: InferenceSourceUnknown,
		ConfidenceScore: 0.0,
		ConfidenceLabel: "very_low",
		Reasons:         []string{"insufficient_evidence"},
		Scores:          map[string]float64{},
	}
}

func resolveKnownClassification(d *DeviceProfile, deviceType string, score float64) *Classification {
	if strings.TrimSpace(deviceType) == "" {
		return nil
	}

	category := rules.MapDeviceTypeToCategory(deviceType)
	if category == "Unknown" {
		return nil
	}

	return &Classification{
		Category:        category,
		DeviceType:      deviceType,
		InferenceSource: InferenceSourceKnown,
		ConfidenceScore: normalizedKnownConfidence(score),
		ConfidenceLabel: "strong",
		Reasons:         collectInferenceReasons(d, 4),
		Scores:          map[string]float64{},
	}
}

func resolveInferredClassification(d *DeviceProfile) *Classification {
	scores := scoreInferredCategories(d)
	bestCategory, bestScore := bestInferredCategory(scores)
	if bestCategory == "" {
		return nil
	}

	label := "low"
	if bestScore >= 1.6 {
		label = "medium"
	}

	return &Classification{
		Category:        bestCategory,
		DeviceType:      "Inferred " + bestCategory,
		InferenceSource: InferenceSourceInferred,
		ConfidenceScore: bestScore,
		ConfidenceLabel: label,
		Reasons:         collectTopInferredReasons(d, bestCategory, 5),
		Scores:          scores,
	}
}

func refreshClassification(d *DeviceProfile) {
	if d == nil {
		return
	}
	classification := resolveClassification(d, d.KnownDeviceType, d.KnownConfidence)
	d.Classification = classification
	d.DeviceType = classification.DeviceType
	d.Confidence = classification.ConfidenceScore
}

func scoreInferredCategories(d *DeviceProfile) map[string]float64 {
	scores := map[string]float64{
		"Camera":         0,
		"Sensor":         0,
		"Controller":     0,
		"Hub":            0,
		"VoiceAssistant": 0,
		"Wearable":       0,
		"Appliance":      0,
	}

	if d == nil {
		return scores
	}

	for port := range d.Ports {
		switch port {
		case 554:
			scores["Camera"] += 1.0
		case 1883, 8883:
			scores["Sensor"] += 0.8
		case 5683:
			scores["Sensor"] += 0.8
			scores["Hub"] += 0.3
		}
	}

	for protocol := range d.Protocols {
		switch strings.ToLower(protocol) {
		case "rtsp":
			scores["Camera"] += 1.2
		case "mqtt":
			scores["Sensor"] += 1.0
			scores["Hub"] += 0.3
		case "coap":
			scores["Sensor"] += 1.0
			scores["Hub"] += 0.3
		case "https", "tls":
			scores["Controller"] += 0.2
			scores["VoiceAssistant"] += 0.2
			scores["Wearable"] += 0.2
			scores["Appliance"] += 0.2
		}
	}

	combined := strings.ToLower(strings.Join(append(append(keysString(d.Hosts), keysString(d.Paths)...), keysString(d.UserAgents)...), " "))
	addKeywordScores(scores, combined,
		map[string]float64{
			"camera": 0.5, "stream": 0.5, "live": 0.5, "rtsp": 0.6, "video": 0.4, "cam": 0.3, "reolink": 0.6, "tapo-camera": 0.6,
		},
		"Camera",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"mqtt": 0.5, "coap": 0.5, "telemetry": 0.5, "sensor": 0.5, "miot": 0.5, "aqara": 0.5, "report": 0.2,
		},
		"Sensor",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"switch": 0.4, "plug": 0.4, "relay": 0.4, "control": 0.4, "kasa": 0.6, "meross": 0.6, "switch-bot": 0.5, "ewelink": 0.5, "shelly": 0.5, "tuyaus": 0.5,
		},
		"Controller",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"bridge": 0.5, "hub": 0.5, "gateway": 0.5, "matter": 0.5, "zigbee": 0.5, "smartthings": 0.6, "meethue": 0.6, "aqara hub": 0.6,
		},
		"Hub",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"alexa": 0.6, "assistant": 0.6, "siri": 0.6, "homepod": 0.6, "nest": 0.5, "speaker": 0.5, "echo": 0.5,
		},
		"VoiceAssistant",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"health": 0.5, "sync": 0.4, "fitbit": 0.6, "garmin": 0.6, "wearable": 0.6, "band": 0.4, "watch": 0.4,
		},
		"Wearable",
	)
	addKeywordScores(scores, combined,
		map[string]float64{
			"hvac": 0.6, "washer": 0.6, "fridge": 0.6, "appliance": 0.5, "daikin": 0.6, "thinq": 0.6, "midea": 0.6, "ac": 0.3,
		},
		"Appliance",
	)

	return scores
}

func addKeywordScores(scores map[string]float64, combined string, weights map[string]float64, category string) {
	for keyword, weight := range weights {
		if strings.Contains(combined, keyword) {
			scores[category] += weight
		}
	}
}

func bestInferredCategory(scores map[string]float64) (string, float64) {
	const threshold = 1.0
	const minMargin = 0.2

	bestCategory := ""
	bestScore := 0.0
	secondScore := 0.0

	for category, score := range scores {
		if score > bestScore {
			secondScore = bestScore
			bestScore = score
			bestCategory = category
		} else if score > secondScore {
			secondScore = score
		}
	}

	if bestScore < threshold {
		return "", 0
	}
	if bestScore-secondScore < minMargin {
		return "", 0
	}
	return bestCategory, bestScore
}

func collectTopInferredReasons(d *DeviceProfile, category string, limit int) []string {
	if d == nil || limit <= 0 {
		return nil
	}

	reasons := make([]string, 0, limit)
	addIf := func(reason string, cond bool) {
		if !cond || len(reasons) >= limit {
			return
		}
		reasons = append(reasons, reason)
	}

	hasToken := func(tokens ...string) bool {
		for _, token := range tokens {
			for host := range d.Hosts {
				if strings.Contains(strings.ToLower(host), token) {
					return true
				}
			}
			for path := range d.Paths {
				if strings.Contains(strings.ToLower(path), token) {
					return true
				}
			}
			for ua := range d.UserAgents {
				if strings.Contains(strings.ToLower(ua), token) {
					return true
				}
			}
		}
		return false
	}

	switch category {
	case "Camera":
		_, has554 := d.Ports[554]
		_, hasRTSP := d.Protocols["rtsp"]
		addIf("port=554", has554)
		addIf("protocol=rtsp", hasRTSP)
		addIf("camera-like host/path", hasToken("camera", "stream", "live", "rtsp", "reolink", "cam"))
	case "Sensor":
		_, hasMQTT := d.Protocols["mqtt"]
		_, hasCoAP := d.Protocols["coap"]
		addIf("protocol=mqtt", hasMQTT)
		addIf("protocol=coap", hasCoAP)
		addIf("sensor/telemetry hint", hasToken("sensor", "telemetry", "aqara", "miot", "report"))
	case "Controller":
		addIf("controller/control hint", hasToken("control", "switch", "plug", "relay", "kasa", "meross", "switch-bot", "shelly", "ewelink", "tuyaus"))
		addIf("protocol=https/tls", d.Protocols["https"] || d.Protocols["tls"])
	case "Hub":
		addIf("hub/bridge hint", hasToken("hub", "bridge", "gateway", "matter", "zigbee", "smartthings", "meethue"))
	case "VoiceAssistant":
		addIf("assistant/speaker hint", hasToken("alexa", "assistant", "siri", "homepod", "nest", "speaker", "echo"))
	case "Wearable":
		addIf("wearable/health hint", hasToken("health", "sync", "fitbit", "garmin", "wearable", "band", "watch"))
	case "Appliance":
		addIf("appliance/hvac hint", hasToken("hvac", "washer", "fridge", "appliance", "daikin", "thinq", "midea", "ac"))
	}

	return reasons
}

func keysString[T comparable](m map[T]bool) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, fmt.Sprint(key))
	}
	return out
}

func collectInferenceReasons(d *DeviceProfile, limit int) []string {
	if d == nil || len(d.Evidence) == 0 || limit <= 0 {
		return nil
	}

	if len(d.Evidence) <= limit {
		out := make([]string, len(d.Evidence))
		copy(out, d.Evidence)
		return out
	}

	out := make([]string, limit)
	copy(out, d.Evidence[:limit])
	return out
}
