package rules

import (
	"net/url"
	"regexp"
	"strings"
)

type PIIHit struct {
	Type     string
	Source   string
	Key      string
	Evidence string
}

var (
	emailRegex = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)
	uuidRegex  = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	macRegex   = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(:[0-9a-f]{2}){5}\b`)
)

var piiKeyToType = map[string]string{
	"email":          "email",
	"mail":           "email",
	"phone":          "phone",
	"tel":            "phone",
	"location":       "location",
	"lat":            "location",
	"lon":            "location",
	"latitude":       "location",
	"longitude":      "location",
	"gps":            "location",
	"coords":         "location",
	"address":        "location",
	"account":        "account_info",
	"account_id":     "account_info",
	"profile":        "account_info",
	"profile_id":     "account_info",
	"user_id":        "user_identifier",
	"userid":         "user_identifier",
	"username":       "user_identifier",
	"user":           "user_identifier",
	"user_name":      "user_identifier",
	"device_id":      "device_identifier",
	"uuid":           "device_identifier",
	"serial":         "device_identifier",
	"serial_number":  "device_identifier",
	"mac":            "device_identifier",
	"imei":           "device_identifier",
	"imsi":           "device_identifier",
	"adid":           "device_identifier",
	"advertising_id": "device_identifier",
	"usage":          "usage_data",
	"usage_log":      "usage_data",
	"activity":       "usage_data",
	"history":        "usage_data",
	"media_id":       "media_metadata",
	"image_id":       "media_metadata",
	"video_id":       "media_metadata",
	"audio_id":       "media_metadata",
	"snapshot_id":    "media_metadata",
	"clip_id":        "media_metadata",
}

func DetectPIIHits(http *HTTPInfo, payload []byte) []PIIHit {
	hits := make([]PIIHit, 0, 8)

	if http != nil {
		hits = append(hits, detectQueryPII(http.Path)...)
		hits = append(hits, detectHeaderPII(http.Headers)...)
	}

	body := extractHTTPBody(payload)
	if body != "" {
		hits = append(hits, detectBodyPII(body)...)
	}

	return dedupePIIHits(hits)
}

func detectQueryPII(path string) []PIIHit {
	idx := strings.Index(path, "?")
	if idx < 0 || idx+1 >= len(path) {
		return nil
	}

	rawQuery := path[idx+1:]
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil
	}

	hits := make([]PIIHit, 0, 4)

	for key, vals := range values {
		keyLower := strings.ToLower(strings.TrimSpace(key))
		piiType, ok := piiKeyToType[keyLower]
		if !ok {
			continue
		}

		for _, v := range vals {
			if strings.TrimSpace(v) == "" {
				continue
			}
			hits = append(hits, PIIHit{
				Type:     piiType,
				Source:   "query",
				Key:      keyLower,
				Evidence: "query " + keyLower + "=***",
			})
		}
	}

	return hits
}

func detectHeaderPII(headers map[string]string) []PIIHit {
	hits := make([]PIIHit, 0, 4)

	for key, value := range headers {
		keyLower := strings.ToLower(strings.TrimSpace(key))
		valueLower := strings.ToLower(strings.TrimSpace(value))

		if piiType, ok := piiKeyToType[keyLower]; ok && valueLower != "" {
			hits = append(hits, PIIHit{
				Type:     piiType,
				Source:   "header",
				Key:      keyLower,
				Evidence: "header " + keyLower + "=***",
			})
			continue
		}

		switch {
		case emailRegex.MatchString(value):
			hits = append(hits, PIIHit{
				Type:     "email",
				Source:   "header",
				Key:      keyLower,
				Evidence: "header " + keyLower + "=***",
			})
		case uuidRegex.MatchString(value) || macRegex.MatchString(value):
			hits = append(hits, PIIHit{
				Type:     "device_identifier",
				Source:   "header",
				Key:      keyLower,
				Evidence: "header " + keyLower + "=***",
			})
		}
	}

	return hits
}

func detectBodyPII(body string) []PIIHit {
	hits := make([]PIIHit, 0, 6)
	bodyLower := strings.ToLower(body)

	for key, piiType := range piiKeyToType {
		if strings.Contains(bodyLower, `"`+key+`"`) || strings.Contains(bodyLower, key+"=") {
			hits = append(hits, PIIHit{
				Type:     piiType,
				Source:   "body",
				Key:      key,
				Evidence: "body " + key + "=***",
			})
		}
	}

	if emailRegex.MatchString(body) {
		hits = append(hits, PIIHit{
			Type:     "email",
			Source:   "body",
			Key:      "email",
			Evidence: "body email=***",
		})
	}

	if uuidRegex.MatchString(body) || macRegex.MatchString(body) {
		hits = append(hits, PIIHit{
			Type:     "device_identifier",
			Source:   "body",
			Key:      "device_identifier",
			Evidence: "body device_identifier=***",
		})
	}

	return hits
}

func extractHTTPBody(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}

	s := string(payload)
	sep := "\r\n\r\n"
	idx := strings.Index(s, sep)
	if idx < 0 {
		return ""
	}

	body := s[idx+len(sep):]
	return strings.TrimSpace(body)
}

func dedupePIIHits(in []PIIHit) []PIIHit {
	seen := make(map[string]bool)
	out := make([]PIIHit, 0, len(in))

	for _, h := range in {
		k := h.Type + "|" + h.Source + "|" + h.Key + "|" + h.Evidence
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, h)
	}

	return out
}
