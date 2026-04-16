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
			Message:  "Authorization header sent over plaintext HTTP",
			Evidence: evidence,
		}, true
	}

	if evidence, ok := DetectSensitiveHeader(ctx.HTTP.Headers); ok {
		return Match{
			Message:  "Sensitive authentication header sent over plaintext HTTP",
			Evidence: evidence,
		}, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPAuthRule{})
}

var _ = bytes.MinRead
