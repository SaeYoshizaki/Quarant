package rules

import (
	"net/url"
	"sort"
	"strings"
)

var i3APIPathHints = []string{
	"/api/",
	"/api",
	"/v1/",
	"/v2/",
	"/graphql",
	"/rest/",
	"/oauth/token",
	"/device/register",
	"/cloud/sync",
	"/api/login",
	"/api/config",
	"/api/device",
	"/api/register",
}

var i3SensitiveAPIHints = []string{
	"login",
	"token",
	"config",
	"admin",
	"oauth",
	"register",
}

var i3ManagementHighHints = []string{
	"/admin",
	"/config",
	"/debug",
	"/diag",
	"/diagnostic",
	"/shell",
	"/console",
	"/backup",
	"/restore",
	"/export",
}

var i3ManagementMediumHints = []string{
	"/login",
	"/settings",
	"/setup",
	"/wizard",
	"/status",
	"/users",
	"/account",
}

var i3CloudHostHints = []string{
	"api",
	"cloud",
	"backend",
	"sync",
	"account",
	"auth",
	"login",
	"mobile",
	"app",
}

var i3CloudPathHints = []string{
	"/api/",
	"/cloud/",
	"/sync",
	"/auth",
	"/login",
	"/oauth",
	"/account",
}

var i3MobileHints = []string{
	"/mobile",
	"/app",
	"/account",
	"/user",
	"/users",
	"/profile",
	"/pair",
	"/pairing",
	"/bind",
	"/unbind",
	"/register",
	"/device/register",
	"/sync",
	"/push",
	"/notification",
}

var i3AuthURLKeys = map[string]bool{
	"token":         true,
	"access_token":  true,
	"refresh_token": true,
	"api_key":       true,
	"apikey":        true,
	"session":       true,
	"session_id":    true,
	"sid":           true,
	"auth":          true,
	"jwt":           true,
	"password":      true,
	"passwd":        true,
	"secret":        true,
}

func isI3PlaintextHTTP(ctx *Context) bool {
	return ctx != nil && ctx.HTTP != nil && !ctx.TLS
}

func i3Header(info *HTTPInfo, name string) string {
	if info == nil || info.Headers == nil {
		return ""
	}
	return strings.TrimSpace(info.Headers[strings.ToLower(name)])
}

func isAPIEndpoint(path, host string) bool {
	combinedPath := strings.ToLower(strings.TrimSpace(path))

	for _, hint := range i3APIPathHints {
		if combinedPath == hint || strings.Contains(combinedPath, hint) {
			return true
		}
	}

	return false
}

func isSensitiveAPIEndpoint(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, hint := range i3SensitiveAPIHints {
		if strings.Contains(path, hint) {
			return true
		}
	}
	return false
}

func isManagementEndpoint(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, hint := range append(append([]string{}, i3ManagementHighHints...), i3ManagementMediumHints...) {
		if strings.Contains(path, hint) {
			return true
		}
	}
	return false
}

func i3ManagementSeverity(path string, plaintext bool) Severity {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, hint := range i3ManagementHighHints {
		if strings.Contains(path, hint) {
			if plaintext {
				return SeverityHigh
			}
			return SeverityWarning
		}
	}
	for _, hint := range i3ManagementMediumHints {
		if strings.Contains(path, hint) {
			if plaintext {
				return SeverityWarning
			}
			return SeverityInfo
		}
	}
	if plaintext {
		return SeverityWarning
	}
	return SeverityInfo
}

func isCloudOrBackendHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, hint := range i3CloudHostHints {
		if strings.Contains(host, hint) {
			return true
		}
	}
	return false
}

func isCloudOrBackendPath(path string) bool {
	path = strings.ToLower(strings.TrimSpace(path))
	for _, hint := range i3CloudPathHints {
		if strings.Contains(path, hint) {
			return true
		}
	}
	return false
}

func isMobileBackendPattern(host, path, userAgent string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.ToLower(strings.TrimSpace(path))
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))

	pathOrHostHint := false
	for _, hint := range i3MobileHints {
		if strings.Contains(path, hint) || strings.Contains(host, strings.TrimPrefix(hint, "/")) {
			pathOrHostHint = true
			break
		}
	}

	hostSupportHint := isCloudOrBackendHost(host)
	userAgentHint := strings.Contains(userAgent, "android") || strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ios") || strings.Contains(userAgent, "okhttp") || strings.Contains(userAgent, "cfnetwork")

	if pathOrHostHint {
		return true
	}
	if hostSupportHint && (isCloudOrBackendPath(path) || userAgentHint) {
		return true
	}
	return false
}

func i3SensitiveURLKeys(values url.Values) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for key := range values {
		normalized := normalizeSensitiveKey(key)
		if i3AuthURLKeys[normalized] {
			out = append(out, normalized)
		}
	}
	sort.Strings(out)
	return dedupeOrderedStrings(out)
}

func maskSensitiveQueryKeys(values url.Values, keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	set := map[string]bool{}
	for _, key := range keys {
		set[key] = true
	}
	out := make([]string, 0, len(keys))
	for key := range values {
		normalized := normalizeSensitiveKey(key)
		if set[normalized] {
			out = append(out, normalized+"=***")
		}
	}
	sort.Strings(out)
	return strings.Join(out, "&")
}

func i3AuthTokenSeverity(keys []string) Severity {
	for _, key := range keys {
		switch key {
		case "password", "passwd", "token", "access_token", "refresh_token", "api_key", "apikey", "session_id", "secret", "jwt":
			return SeverityHigh
		}
	}
	return SeverityWarning
}

func i3HasQuerySupportHint(values url.Values) bool {
	for key := range values {
		switch normalizeSensitiveKey(key) {
		case "token", "access_token", "refresh_token", "api_key", "apikey", "session_id", "session", "sid", "auth", "jwt", "password", "passwd", "secret", "user_id", "device_id":
			return true
		}
	}
	return false
}

func i3ContainsSensitiveKey(values url.Values) bool {
	return len(i3SensitiveURLKeys(values)) > 0
}
