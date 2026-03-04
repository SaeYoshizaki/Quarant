package rules

import "strings"

type I7HTTPCookieRule struct{}

func (r *I7HTTPCookieRule) ID() string         { return "I7_HTTP_COOKIE" }
func (r *I7HTTPCookieRule) Category() string   { return "I7" }
func (r *I7HTTPCookieRule) Severity() Severity { return SeverityWarning }
func (r *I7HTTPCookieRule) Type() string       { return "INSECURE_HTTP_COOKIE" }

func (r *I7HTTPCookieRule) Apply(ctx *Context) (Match, bool) {

	s := string(ctx.Payload)
	lower := strings.ToLower(s)

	if strings.Contains(lower, "\ncookie:") || strings.Contains(lower, "\r\ncookie:") || strings.HasPrefix(lower, "cookie:") {
		return Match{
			Message:  "Cookie header sent over plaintext HTTP",
			Evidence: "Cookie: ***",
		}, true
	}
	if strings.Contains(lower, "\nset-cookie:") || strings.Contains(lower, "\r\nset-cookie:") || strings.HasPrefix(lower, "set-cookie:") {
		return Match{
			RuleID:   r.ID(),
			Category: r.Category(),
			Severity: r.Severity(),
			Type:     r.Type(),
			Message:  "Cookie header sent over plaintext HTTP",
			Evidence: "Cookie: ***",
		}, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPCookieRule{})
}
