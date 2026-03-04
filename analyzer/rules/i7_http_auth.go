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

	s := string(ctx.Payload)
	lines := strings.Split(s, "\n")

	for _, line := range lines {

		l := strings.ToLower(strings.TrimSpace(line))

		if strings.HasPrefix(l, "authorization:") {

			evidence := "Authorization: ***"

			if strings.Contains(l, "basic") {
				evidence = "Authorization: Basic ***"
			}

			if strings.Contains(l, "bearer") {
				evidence = "Authorization: Bearer ***"
			}

			return Match{
				RuleID:   r.ID(),
				Category: r.Category(),
				Severity: r.Severity(),
				Type:     r.Type(),
				Message:  "Authorization header sent over plaintext HTTP",
				Evidence: evidence,
			}, true
		}
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPAuthRule{})
}

var _ = bytes.MinRead
