package rules

import (
	"fmt"
	"net"
	"strings"
)

type I9SetupEndpointStillActiveRule struct{}

func (r *I9SetupEndpointStillActiveRule) ID() string         { return "I9_SETUP_ENDPOINT_STILL_ACTIVE" }
func (r *I9SetupEndpointStillActiveRule) Category() string   { return "I9" }
func (r *I9SetupEndpointStillActiveRule) Severity() Severity { return SeverityWarning }
func (r *I9SetupEndpointStillActiveRule) Type() string       { return "I9_SETUP_ENDPOINT_STILL_ACTIVE" }

func (r *I9SetupEndpointStillActiveRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.HTTP == nil {
		return Match{}, false
	}

	hit, ok := i9SetupEndpointHint(ctx.HTTP.Path)
	if !ok {
		return Match{}, false
	}

	tags := uniqueTags("I3", "I9")
	if !ctx.TLS {
		tags = uniqueTags("I3", "I7", "I9")
	}

	return Match{
		Severity:       SeverityWarning,
		Message:        "Setup or onboarding-like endpoint observed in HTTP traffic.",
		Evidence:       fmt.Sprintf("method=%s path=%s hint=%s plaintext=%t", ctx.HTTP.Method, ctx.HTTP.Path, hit, !ctx.TLS),
		OWASPTags:      tags,
		Confidence:     "medium",
		ObservedFact:   "Setup or onboarding-like endpoint was observed in HTTP traffic.",
		Inference:      "This may indicate that an initial configuration or provisioning interface is still reachable.",
		Limitation:     "Passive monitoring cannot determine whether the device is still in a factory-default state or whether the endpoint requires authentication.",
		Recommendation: "Confirm that setup or provisioning interfaces are disabled or restricted after initial configuration.",
	}, true
}

type I9DefaultHostnamePatternRule struct{}

func (r *I9DefaultHostnamePatternRule) ID() string         { return "I9_DEFAULT_HOSTNAME_PATTERN" }
func (r *I9DefaultHostnamePatternRule) Category() string   { return "I9" }
func (r *I9DefaultHostnamePatternRule) Severity() Severity { return SeverityInfo }
func (r *I9DefaultHostnamePatternRule) Type() string       { return "I9_DEFAULT_HOSTNAME_PATTERN" }

func (r *I9DefaultHostnamePatternRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil {
		return Match{}, false
	}

	value, source, ok := i9DefaultHostnameCandidate(ctx)
	if !ok {
		return Match{}, false
	}

	severity := SeverityInfo
	confidence := "low"
	if i9ShouldElevateHostnameSeverity(ctx) {
		severity = SeverityWarning
	}
	if ctx.FamilyConfidenceAtLeast("medium") || ctx.VendorConfidenceAtLeast("medium") {
		confidence = "medium"
	}

	return Match{
		Message:        "Default hostname-like pattern observed.",
		Evidence:       fmt.Sprintf("source=%s hostname=%s", source, value),
		OWASPTags:      uniqueTags("I9"),
		Confidence:     confidence,
		Severity:       severity,
		ObservedFact:   "Default hostname-like pattern was observed.",
		Inference:      "This may indicate that the device still uses a factory-like or generic hostname.",
		Limitation:     "Passive monitoring cannot confirm whether other default settings remain unchanged.",
		Recommendation: "Rename the device where possible and review initial setup and security settings.",
	}, true
}

var i9SetupEndpointTokens = map[string]bool{
	"setup":        true,
	"wizard":       true,
	"onboarding":   true,
	"pair":         true,
	"pairing":      true,
	"provision":    true,
	"provisioning": true,
	"initial":      true,
	"init":         true,
	"factory":      true,
	"firstboot":    true,
	"welcome":      true,
	"install":      true,
	"configure":    true,
}

var i9DefaultHostnameHints = []string{
	"device.local",
	"camera.local",
	"ipcamera",
	"webcam",
	"smartplug",
	"smartbulb",
	"iot-device",
	"openwrt",
	"raspberrypi",
	"esp_",
	"esp32",
	"esp8266",
	"tasmota",
	"shelly",
	"sonoff",
}

func i9SetupEndpointHint(path string) (string, bool) {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return "", false
	}
	for _, token := range i9PathTokens(path) {
		if i9SetupEndpointTokens[token] {
			return token, true
		}
	}
	return "", false
}

func i9PathTokens(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool {
		switch r {
		case '/', '-', '_', '.', '?', '&', '=':
			return true
		default:
			return false
		}
	})
}

func i9DefaultHostnameCandidate(ctx *Context) (string, string, bool) {
	if ctx.HTTP != nil {
		if host, ok := i9LooksDefaultHostname(i3Header(ctx.HTTP, "host")); ok {
			return host, "http_host", true
		}
	}
	for _, host := range ctx.ObservedHosts {
		if value, ok := i9LooksDefaultHostname(host); ok {
			return value, "observed_host", true
		}
	}
	if ctx.TLSInfo != nil {
		if host, ok := i9LooksDefaultHostname(ctx.TLSInfo.SNI); ok {
			return host, "tls_sni", true
		}
	}
	for _, host := range ctx.ObservedSNIValues {
		if value, ok := i9LooksDefaultHostname(host); ok {
			return value, "observed_sni", true
		}
	}
	return "", "", false
}

func i9LooksDefaultHostname(value string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(value))
	if host == "" {
		return "", false
	}
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	} else if idx := strings.IndexByte(host, ':'); idx > 0 && !strings.Contains(host, "]") {
		host = host[:idx]
	}
	host = strings.Trim(host, "[]")
	firstLabel := host
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		firstLabel = host[:idx]
	}
	for _, hint := range i9DefaultHostnameHints {
		if host == hint || firstLabel == hint || strings.Contains(firstLabel, hint) {
			return host, true
		}
	}
	return "", false
}

func i9ShouldElevateHostnameSeverity(ctx *Context) bool {
	if ctx == nil {
		return false
	}
	if ctx.HTTP != nil {
		if _, ok := i9SetupEndpointHint(ctx.HTTP.Path); ok {
			return true
		}
		if isManagementEndpoint(ctx.HTTP.Path) {
			return true
		}
	}
	if _, ok := InsecureServiceNameByPort(ctx.DstPort); ok {
		return true
	}
	return false
}

func init() {
	Register(&I9SetupEndpointStillActiveRule{})
	Register(&I9DefaultHostnamePatternRule{})
}
