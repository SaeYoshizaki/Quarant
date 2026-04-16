package rules

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var strongSensitiveHTTPKeys = []string{
	"password",
	"passwd",
	"pwd",
	"token",
	"access_token",
	"refresh_token",
	"apikey",
	"api_key",
	"x-api-key",
	"x-auth-token",
	"secret",
	"client_secret",
	"client_key",
	"private_key",
	"wifi_password",
	"psk",
	"mqtt_user",
	"mqtt_pass",
	"rtsp_url",
	"update_token",
}

var heuristicSensitiveHTTPKeys = []string{
	"session",
	"sid",
	"jwt",
	"ssid",
	"device_id",
	"serial",
}

var multipartNameRegex = regexp.MustCompile(`(?i)\bname="([^"]+)"`)
var xmlKeyValueRegex = regexp.MustCompile(`(?is)<([a-z0-9_\-:]+)[^>]*>\s*([^<]+?)\s*</[a-z0-9_\-:]+>`)
var jsonStringKVRegex = regexp.MustCompile(`(?is)"([^"]+)"\s*:\s*"([^"]*)"`)
var textKVRegex = regexp.MustCompile(`(?i)([a-z0-9_\-]+)\s*=\s*([^\s&;]+)`)
var jwtLikeRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$`)
var hexLikeRegex = regexp.MustCompile(`^(?i:[a-f0-9]{16,}|[a-f0-9-]{16,})$`)
var uuidLikeRegex = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var macLikeRegex = regexp.MustCompile(`(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
var longTokenCharsetRegex = regexp.MustCompile(`^[A-Za-z0-9._~+\-=/]+$`)

var sensitiveHTTPHeaders = map[string]string{
	"authorization":        "Authorization: ***",
	"proxy-authorization":  "Proxy-Authorization: ***",
	"x-api-key":            "X-Api-Key: ***",
	"x-auth-token":         "X-Auth-Token: ***",
	"x-access-token":       "X-Access-Token: ***",
	"api-token":            "Api-Token: ***",
	"authentication":       "Authentication: ***",
	"authentication-token": "Authentication-Token: ***",
}

func HasSensitiveKey(name string) bool {
	n := normalizeSensitiveKey(name)
	return isStrongSensitiveHTTPKey(n) || isHeuristicSensitiveHTTPKey(n)
}

func DetectSensitiveHeader(headers map[string]string) (string, bool) {
	for key, evidence := range sensitiveHTTPHeaders {
		if value, ok := headers[key]; ok && strings.TrimSpace(value) != "" {
			return evidence, true
		}
	}

	for key, value := range headers {
		if evidence, ok := detectSensitiveField(key, value, nil); ok {
			return evidence, true
		}
	}

	return "", false
}

func DetectSensitiveFormBody(body []byte) (string, bool) {
	v, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false
	}
	return detectSensitiveValues(v)
}

func DetectSensitiveJSONBody(body []byte) (string, bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", false
	}
	return detectSensitiveJSONMap(m)
}

func DetectSensitiveMultipartBody(body []byte) (string, bool) {
	matches := multipartNameRegex.FindAllStringSubmatch(string(body), -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		if HasSensitiveKey(match[1]) {
			return match[1] + "=***", true
		}
	}
	return "", false
}

func DetectSensitiveTextBody(body []byte) (string, bool) {
	text := string(body)

	for _, match := range jsonStringKVRegex.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		if evidence, ok := detectSensitiveField(match[1], match[2], nil); ok {
			return evidence, true
		}
	}

	for _, match := range xmlKeyValueRegex.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		if evidence, ok := detectSensitiveField(match[1], match[2], nil); ok {
			return evidence, true
		}
	}

	for _, match := range textKVRegex.FindAllStringSubmatch(text, -1) {
		if len(match) < 3 {
			continue
		}
		if evidence, ok := detectSensitiveField(match[1], match[2], nil); ok {
			return evidence, true
		}
	}

	return "", false
}

func InferHTTPBodyFormat(contentType string, body []byte) string {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch ct {
	case "application/x-www-form-urlencoded":
		return "form"
	case "application/json":
		return "json"
	case "multipart/form-data":
		return "multipart"
	case "application/xml", "text/xml":
		return "xml"
	case "text/plain":
		return "text"
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return ""
	}

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}

	if strings.HasPrefix(trimmed, "<") {
		return "xml"
	}

	if strings.Contains(trimmed, "Content-Disposition: form-data") {
		return "multipart"
	}

	if strings.Contains(trimmed, "=") {
		if values, err := url.ParseQuery(trimmed); err == nil && len(values) > 0 {
			return "form"
		}
	}

	return "text"
}

func DetectSensitiveHTTPBody(contentType string, body []byte) (string, string, bool) {
	format := InferHTTPBodyFormat(contentType, body)
	switch format {
	case "form":
		if ev, ok := DetectSensitiveFormBody(body); ok {
			return "Sensitive data appears in plaintext HTTP form body", ev, true
		}
	case "json":
		if ev, ok := DetectSensitiveJSONBody(body); ok {
			return "Sensitive data appears in plaintext HTTP JSON body", ev, true
		}
	case "multipart":
		if ev, ok := DetectSensitiveMultipartBody(body); ok {
			return "Sensitive data appears in plaintext HTTP multipart body", ev, true
		}
	case "xml":
		if ev, ok := DetectSensitiveTextBody(body); ok {
			return "Sensitive data appears in plaintext HTTP XML body", ev, true
		}
	case "text":
		if ev, ok := DetectSensitiveTextBody(body); ok {
			return "Sensitive data appears in plaintext HTTP text body", ev, true
		}
	}

	return "", "", false
}

func DetectSensitiveQuery(values url.Values) (string, bool) {
	return detectSensitiveValues(values)
}

func detectSensitiveValues(values url.Values) (string, bool) {
	siblings := make(map[string]bool, len(values))
	for key := range values {
		siblings[normalizeSensitiveKey(key)] = true
	}

	for key, vals := range values {
		for _, value := range vals {
			if evidence, ok := detectSensitiveField(key, value, siblings); ok {
				return evidence, true
			}
		}
	}
	return "", false
}

func detectSensitiveJSONMap(m map[string]any) (string, bool) {
	siblings := make(map[string]bool, len(m))
	for key := range m {
		siblings[normalizeSensitiveKey(key)] = true
	}

	for key, raw := range m {
		switch v := raw.(type) {
		case string:
			if evidence, ok := detectSensitiveField(key, v, siblings); ok {
				return evidence, true
			}
		case []any:
			for _, item := range v {
				s, ok := item.(string)
				if !ok {
					continue
				}
				if evidence, ok := detectSensitiveField(key, s, siblings); ok {
					return evidence, true
				}
			}
		case map[string]any:
			if evidence, ok := detectSensitiveJSONMap(v); ok {
				return evidence, true
			}
		}
	}
	return "", false
}

func detectSensitiveField(key, value string, siblings map[string]bool) (string, bool) {
	normalizedKey := normalizeSensitiveKey(key)
	trimmedValue := strings.TrimSpace(value)
	if trimmedValue == "" {
		return "", false
	}

	if isStrongSensitiveHTTPKey(normalizedKey) {
		return normalizedKey + "=***", true
	}

	if isHeuristicSensitiveHTTPKey(normalizedKey) && looksSensitiveForKey(normalizedKey, trimmedValue, siblings) {
		return normalizedKey + "=***", true
	}

	if looksSuspiciousKeyName(normalizedKey) && looksSensitiveTokenValue(trimmedValue) {
		return normalizedKey + "=***", true
	}

	return "", false
}

func looksSensitiveForKey(key, value string, siblings map[string]bool) bool {
	switch key {
	case "session", "sid", "jwt":
		return looksSensitiveTokenValue(value)
	case "ssid":
		return hasWiFiSecretSibling(siblings) && len(value) >= 2
	case "device_id", "serial":
		return looksSensitiveIdentifier(value)
	default:
		return false
	}
}

func hasWiFiSecretSibling(siblings map[string]bool) bool {
	if siblings == nil {
		return false
	}
	return siblings["wifi_password"] || siblings["psk"]
}

func looksSensitiveTokenValue(value string) bool {
	return looksLikeJWT(value) || looksLikeBase64Token(value) || looksLikeLongRandomToken(value)
}

func looksLikeJWT(value string) bool {
	return jwtLikeRegex.MatchString(strings.TrimSpace(value))
}

func looksLikeBase64Token(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 24 || len(trimmed)%4 != 0 {
		return false
	}
	if !longTokenCharsetRegex.MatchString(trimmed) || !strings.Contains(trimmed, "=") {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(trimmed)
	return err == nil
}

func looksLikeLongRandomToken(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) < 20 || !longTokenCharsetRegex.MatchString(trimmed) {
		return false
	}

	hasLower := strings.IndexFunc(trimmed, func(r rune) bool { return 'a' <= r && r <= 'z' }) >= 0
	hasUpper := strings.IndexFunc(trimmed, func(r rune) bool { return 'A' <= r && r <= 'Z' }) >= 0
	hasDigit := strings.IndexFunc(trimmed, func(r rune) bool { return '0' <= r && r <= '9' }) >= 0
	return (hasLower && hasUpper && hasDigit) || hexLikeRegex.MatchString(trimmed)
}

func looksSensitiveIdentifier(value string) bool {
	trimmed := strings.TrimSpace(value)
	if uuidLikeRegex.MatchString(trimmed) || macLikeRegex.MatchString(trimmed) {
		return true
	}
	if len(trimmed) < 8 {
		return false
	}

	hasLetter := strings.IndexFunc(trimmed, func(r rune) bool {
		return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
	}) >= 0
	hasDigit := strings.IndexFunc(trimmed, func(r rune) bool { return '0' <= r && r <= '9' }) >= 0
	return hasLetter && hasDigit
}

func looksSuspiciousKeyName(key string) bool {
	for _, needle := range []string{
		"auth",
		"token",
		"secret",
		"key",
		"session",
		"sid",
		"jwt",
		"bearer",
	} {
		if strings.Contains(key, needle) {
			return true
		}
	}
	return false
}

func normalizeSensitiveKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func isStrongSensitiveHTTPKey(key string) bool {
	for _, candidate := range strongSensitiveHTTPKeys {
		if key == candidate {
			return true
		}
	}
	return false
}

func isHeuristicSensitiveHTTPKey(key string) bool {
	for _, candidate := range heuristicSensitiveHTTPKeys {
		if key == candidate {
			return true
		}
	}
	return false
}
