package rules

type I7HTTPCookieRule struct{}

func (r *I7HTTPCookieRule) ID() string         { return "I7_HTTP_COOKIE" }
func (r *I7HTTPCookieRule) Category() string   { return "I7" }
func (r *I7HTTPCookieRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPCookieRule) Type() string       { return "INSECURE_HTTP_COOKIE" }

func (r *I7HTTPCookieRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.HTTP == nil || ctx.TLS {
		return Match{}, false
	}

	if _, ok := ctx.HTTP.Headers["cookie"]; ok {
		return Match{
			Message:        "Cookie header was observed over plaintext HTTP.",
			Evidence:       "Cookie: ***",
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Cookie header was observed over plaintext HTTP.",
			Inference:      "Session identifiers or authentication state may be exposed in transit.",
			Limitation:     "Passive monitoring cannot confirm whether the cookie is authenticated, sensitive, or protected by additional server-side controls.",
			Recommendation: "Use HTTPS and review whether cookies carrying session state are restricted to secure transport.",
			Severity:       SeverityCritical,
		}, true
	}
	if _, ok := ctx.HTTP.Headers["set-cookie"]; ok {
		return Match{
			Message:        "Set-Cookie header was observed over plaintext HTTP.",
			Evidence:       "Set-Cookie: ***",
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Set-Cookie header was observed over plaintext HTTP.",
			Inference:      "Session identifiers or authentication state may be exposed in transit.",
			Limitation:     "Passive monitoring cannot confirm whether the cookie is sensitive or whether secure alternatives are available elsewhere.",
			Recommendation: "Use HTTPS and review whether cookies carrying session state are restricted to secure transport.",
			Severity:       SeverityCritical,
		}, true
	}
	return Match{}, false
}

func init() {
	Register(&I7HTTPCookieRule{})
}
