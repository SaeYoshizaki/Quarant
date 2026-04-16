package rules

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

var sensitiveHTTPKeys = []string{
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
	"session",
	"sid",
	"jwt",
	"wifi_password",
	"ssid",
	"psk",
	"device_id",
	"serial",
	"client_key",
	"private_key",
	"mqtt_user",
	"mqtt_pass",
	"rtsp_url",
	"update_token",
}

var multipartNameRegex = regexp.MustCompile(`(?i)\bname="([^"]+)"`)

var sensitiveHTTPHeaders = map[string]string{
	"authorization":       "Authorization: ***",
	"proxy-authorization": "Proxy-Authorization: ***",
	"x-api-key":           "X-Api-Key: ***",
	"x-auth-token":        "X-Auth-Token: ***",
}

func HasSensitiveKey(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range sensitiveHTTPKeys {
		if n == k {
			return true
		}
	}
	return false
}

func DetectSensitiveHeader(headers map[string]string) (string, bool) {
	for key, evidence := range sensitiveHTTPHeaders {
		if value, ok := headers[key]; ok && strings.TrimSpace(value) != "" {
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

	for k := range v {
		if HasSensitiveKey(k) {
			return k + "=***", true
		}
	}
	return "", false
}

func DetectSensitiveJSONBody(body []byte) (string, bool) {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return "", false
	}

	for k := range m {
		if HasSensitiveKey(k) {
			return k + "=***", true
		}
	}
	return "", false
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
	text := strings.ToLower(string(body))
	for _, key := range sensitiveHTTPKeys {
		switch {
		case strings.Contains(text, key+"="),
			strings.Contains(text, `"`+key+`"`),
			strings.Contains(text, `'`+key+`'`),
			strings.Contains(text, "<"+key+">"),
			strings.Contains(text, "<"+key+" "):
			return key + "=***", true
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
