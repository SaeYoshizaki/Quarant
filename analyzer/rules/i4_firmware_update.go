package rules

import (
	"fmt"
	"strings"
)

var i4FirmwareUpdateStrongKeywords = []string{
	"/firmware",
	"/ota",
	"/upgrade",
	"/firmware.bin",
	"firmware",
	"ota",
}

var i4FirmwareUpdateWeakKeywords = []string{
	"update",
	"download",
	"release",
}

type i4KeywordStrength string

const (
	i4KeywordStrengthStrong i4KeywordStrength = "strong"
	i4KeywordStrengthWeak   i4KeywordStrength = "weak"
)

var i4FirmwareEvidenceFieldOrder = []string{"path", "host", "sni"}

type i4KeywordMatch struct {
	Field    string
	Keyword  string
	Strength i4KeywordStrength
}

var i4FirmwareUpdateStrongOnlyPathKeywords = []string{
	"/firmware.bin",
}

var i4LegacyFirmwareUpdateKeywords = []string{
	"/update",
	"/firmware",
	"/ota",
	"/upgrade",
	"/download",
	"/release",
	"firmware",
	"update",
	"ota",
	"upgrade",
	"release",
}

type i4FirmwareUpdateObservation struct {
	Endpoint    string
	Indicators  []string
	ObservedVia string
	CommType    string
	External    bool
	StrongHit   bool
}

type I4FirmwareUpdateObservedRule struct{}

func (r *I4FirmwareUpdateObservedRule) ID() string         { return "I4_FIRMWARE_UPDATE_OBSERVED" }
func (r *I4FirmwareUpdateObservedRule) Category() string   { return "I4" }
func (r *I4FirmwareUpdateObservedRule) Severity() Severity { return SeverityInfo }
func (r *I4FirmwareUpdateObservedRule) Type() string       { return "I4_FIRMWARE_UPDATE_OBSERVED" }

func (r *I4FirmwareUpdateObservedRule) Apply(ctx *Context) (Match, bool) {
	obs, ok := detectFirmwareUpdateObservation(ctx)
	if !ok || !obs.StrongHit {
		return Match{}, false
	}

	return Match{
		Message:  "Firmware/update-like communication observed",
		Evidence: formatI4FirmwareEvidence(obs),
	}, true
}

type I4InsecureFirmwareUpdateHTTPRule struct{}

func (r *I4InsecureFirmwareUpdateHTTPRule) ID() string         { return "I4_INSECURE_FIRMWARE_UPDATE_HTTP" }
func (r *I4InsecureFirmwareUpdateHTTPRule) Category() string   { return "I4" }
func (r *I4InsecureFirmwareUpdateHTTPRule) Severity() Severity { return SeverityWarning }
func (r *I4InsecureFirmwareUpdateHTTPRule) Type() string {
	return "I4_INSECURE_FIRMWARE_UPDATE_HTTP"
}

func (r *I4InsecureFirmwareUpdateHTTPRule) Apply(ctx *Context) (Match, bool) {
	obs, ok := detectFirmwareUpdateObservation(ctx)
	if !ok || !obs.StrongHit || ctx == nil || ctx.HTTP == nil || ctx.TLS || !obs.External {
		return Match{}, false
	}

	return Match{
		Message: "Potential firmware/update delivery observed over plaintext external HTTP",
		Evidence: fmt.Sprintf(
			"%s plaintext=true risk_signals=firmware_update,plaintext_update,external_update",
			formatI4FirmwareEvidence(obs),
		),
	}, true
}

func detectFirmwareUpdateObservation(ctx *Context) (i4FirmwareUpdateObservation, bool) {
	if ctx == nil {
		return i4FirmwareUpdateObservation{}, false
	}

	if ctx.HTTP != nil {
		if obs, ok := detectHTTPFirmwareUpdateObservation(ctx); ok {
			return obs, true
		}
	}

	if ctx.TLSInfo != nil {
		if obs, ok := detectTLSFirmwareUpdateObservation(ctx); ok {
			return obs, true
		}
	}

	return i4FirmwareUpdateObservation{}, false
}

func detectHTTPFirmwareUpdateObservation(ctx *Context) (i4FirmwareUpdateObservation, bool) {
	host := strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"]))
	path := strings.ToLower(strings.TrimSpace(ctx.HTTP.Path))

	matches := make([]i4KeywordMatch, 0, 4)
	matches = append(matches, matchI4Keywords(path, "path")...)
	matches = append(matches, matchI4Keywords(host, "host")...)
	if len(matches) == 0 {
		return i4FirmwareUpdateObservation{}, false
	}

	endpoint := strings.TrimSpace(ctx.HTTP.Headers["host"])
	if endpoint == "" {
		endpoint = ctx.HTTP.Path
	}

	return i4FirmwareUpdateObservation{
		Endpoint:    endpoint,
		Indicators:  formatI4Indicators(matches),
		ObservedVia: "http",
		CommType:    "http",
		External:    IsPublicIPv4(ctx.DstIP),
		StrongHit:   hasI4StrongHit(matches),
	}, true
}

func detectTLSFirmwareUpdateObservation(ctx *Context) (i4FirmwareUpdateObservation, bool) {
	sni := strings.ToLower(strings.TrimSpace(ctx.TLSInfo.SNI))
	matches := matchI4Keywords(sni, "sni")
	if len(matches) == 0 {
		return i4FirmwareUpdateObservation{}, false
	}

	return i4FirmwareUpdateObservation{
		Endpoint:    strings.TrimSpace(ctx.TLSInfo.SNI),
		Indicators:  formatI4Indicators(matches),
		ObservedVia: "tls_sni",
		CommType:    "tls",
		External:    IsPublicIPv4(ctx.DstIP),
		StrongHit:   hasI4StrongHit(matches),
	}, true
}

func matchI4Keywords(text, field string) []i4KeywordMatch {
	if text == "" {
		return nil
	}

	out := make([]i4KeywordMatch, 0, 2)
	for _, keyword := range i4FirmwareUpdateStrongKeywords {
		if strings.Contains(text, keyword) && allowsI4KeywordInField(keyword, field) {
			out = append(out, i4KeywordMatch{
				Field:    field,
				Keyword:  keyword,
				Strength: i4KeywordStrengthStrong,
			})
		}
	}
	for _, keyword := range i4FirmwareUpdateWeakKeywords {
		if strings.Contains(text, keyword) {
			out = append(out, i4KeywordMatch{
				Field:    field,
				Keyword:  keyword,
				Strength: i4KeywordStrengthWeak,
			})
		}
	}
	return out
}

func allowsI4KeywordInField(keyword, field string) bool {
	if field == "path" {
		return true
	}
	for _, pathOnly := range i4FirmwareUpdateStrongOnlyPathKeywords {
		if keyword == pathOnly {
			return false
		}
	}
	return true
}

func hasI4StrongHit(matches []i4KeywordMatch) bool {
	for _, match := range matches {
		if match.Strength == i4KeywordStrengthStrong {
			return true
		}
	}
	return false
}

func formatI4Indicators(matches []i4KeywordMatch) []string {
	if len(matches) == 0 {
		return nil
	}

	out := make([]string, 0, len(matches))
	for _, field := range i4FirmwareEvidenceFieldOrder {
		for _, match := range matches {
			if match.Field != field {
				continue
			}
			out = append(out, fmt.Sprintf("%s_%s=%s", match.Strength, match.Field, match.Keyword))
		}
	}
	return out
}

func formatI4FirmwareEvidence(obs i4FirmwareUpdateObservation) string {
	return fmt.Sprintf(
		"endpoint=%s observed_via=%s comm_type=%s external=%t indicators=%s",
		obs.Endpoint,
		obs.ObservedVia,
		obs.CommType,
		obs.External,
		strings.Join(obs.Indicators, ","),
	)
}

func init() {
	Register(&I4FirmwareUpdateObservedRule{})
	Register(&I4InsecureFirmwareUpdateHTTPRule{})
}
