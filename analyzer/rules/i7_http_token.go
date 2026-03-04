package rules

import (
	"strings"
)

type I7HTTPTokenLeakRule struct{}

func (r *I7HTTPTokenLeakRule) ID() string         { return "I7_HTTP_TOKEN" }
func (r *I7HTTPTokenLeakRule) Category() string   { return "I7" }
func (r *I7HTTPTokenLeakRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPTokenLeakRule) Type() string       { return "INSECURE_HTTP_TOKEN" }

func (r *I7HTTPTokenLeakRule) Apply(ctx *Context) (Match, bool) {

	l := strings.ToLower(string(ctx.Payload))

	keys := []string{
		"password=",
		"passwd=",
		"pwd=",
		"token=",
		"access_token=",
		"apikey=",
		"api_key=",
		"secret=",
		"client_secret=",
	}

	for _, k := range keys {
		if strings.Contains(l, k) {
			return Match{
				RuleID:   r.ID(),
				Category: r.Category(),
				Severity: r.Severity(),
				Type:     r.Type(),
				Message:  "Sensitive parameter appears in plaintext HTTP payload",
				Evidence: k + "***",
			}, true
		}
	}
	return Match{}, false
}

func init() {
	Register(&I7HTTPTokenLeakRule{})
}
