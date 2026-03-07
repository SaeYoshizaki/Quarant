package rules

import (
	"encoding/json"
	"net/url"
	"strings"
)

var sensitiveBodyKeys = []string{
	"password",
	"passwd",
	"pwd",
	"token",
	"access_token",
	"refresh_token",
	"apikey",
	"api_key",
	"secret",
	"client_secret",
	"session",
	"sid",
}

func HasSensitiveKey(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, k := range sensitiveBodyKeys {
		if n == k {
			return true
		}
	}
	return false
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
