package rules

import (
	"bytes"
	"strings"
)

type I7HTTPAuthRule struct{}

func (r *I7HTTPAuthRule) ID() string         { return "I7_HTTP_AUTH" }
func (r *I7HTTPAuthRule) Category() string   { return "I7" }
func (r *I7HTTPAuthRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPAuthRule) Type() string       { return "INSECURE_HTTP_AUTH" }

func (r *I7HTTPAuthRule) Apply(ctx *Context) (Match, bool) {
	if ctx.HTTP == nil {
		return Match{}, false
	}

	if v, ok := ctx.HTTP.Headers["authorization"]; ok && v != "" {
		evidenceLower := strings.ToLower(v)
		evidence := "Authorization: ***"
		if strings.Contains(evidenceLower, "basic") {
			evidence = "Authorization: Basic ***"
		} else if strings.Contains(evidenceLower, "bearer") {
			evidence = "Authorization: Bearer ***"
		}

		return Match{
			Message:        "Authorization or authentication header was observed over plaintext HTTP.",
			Evidence:       evidence,
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Authorization header was observed over plaintext HTTP.",
			Inference:      "Credentials or authentication tokens may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine password strength, whether the credential is hardcoded, or whether the backend enforces additional controls.",
			Recommendation: "Use HTTPS, rotate exposed credentials if needed, and review device or application authentication settings.",
		}, true
	}

	if evidence, ok := DetectSensitiveHeader(ctx.HTTP.Headers); ok {
		return Match{
			Message:        "Sensitive authentication-related header was observed over plaintext HTTP.",
			Evidence:       evidence,
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Sensitive authentication-related header was observed over plaintext HTTP.",
			Inference:      "Credentials or API tokens may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine whether the value is active, hardcoded, or restricted by other controls.",
			Recommendation: "Use HTTPS, rotate exposed credentials if needed, and review device or application authentication settings.",
		}, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPAuthRule{})
}

var _ = bytes.MinRead
