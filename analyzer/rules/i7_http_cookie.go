package rules

type I7HTTPCookieRule struct{}

func (r *I7HTTPCookieRule) ID() string         { return "I7_HTTP_COOKIE" }
func (r *I7HTTPCookieRule) Category() string   { return "I7" }
func (r *I7HTTPCookieRule) Severity() Severity { return SeverityWarning }
func (r *I7HTTPCookieRule) Type() string       { return "INSECURE_HTTP_COOKIE" }

func (r *I7HTTPCookieRule) Apply(ctx *Context) (Match, bool) {
	if ctx.HTTP == nil {
		return Match{}, false
	}

	if _, ok := ctx.HTTP.Headers["cookie"]; ok {
		return Match{
			Message:  "Cookie header sent over plaintext HTTP",
			Evidence: "Cookie: ***",
		}, true
	}
	if _, ok := ctx.HTTP.Headers["set-cookie"]; ok {
		return Match{
			Message:  "Set-Cookie header observed over plaintext HTTP",
			Evidence: "Set-Cookie: ***",
		}, true
	}
	return Match{}, false
}

func init() {
	Register(&I7HTTPCookieRule{})
}
