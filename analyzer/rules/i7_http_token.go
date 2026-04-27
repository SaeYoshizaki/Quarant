package rules

type I7HTTPTokenLeakRule struct{}

func (r *I7HTTPTokenLeakRule) ID() string         { return "I7_HTTP_TOKEN" }
func (r *I7HTTPTokenLeakRule) Category() string   { return "I7" }
func (r *I7HTTPTokenLeakRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPTokenLeakRule) Type() string       { return "INSECURE_HTTP_TOKEN" }

func (r *I7HTTPTokenLeakRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.HTTP == nil || ctx.TLS {
		return Match{}, false
	}

	if ev, ok := DetectSensitiveQuery(ctx.HTTP.Query); ok {
		return Match{
			Message:        "Sensitive token or identifier-like parameter was observed in a plaintext HTTP URL.",
			Evidence:       ev,
			Severity:       SeverityCritical,
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Sensitive token or identifier-like query parameter was observed over plaintext HTTP.",
			Inference:      "Credentials, session tokens, or stable identifiers may be exposed in transit and in URL logs.",
			Limitation:     "Passive monitoring cannot determine whether the value is still valid, whether it is hardcoded, or whether the API has additional protections.",
			Recommendation: "Avoid putting tokens in URLs, use HTTPS, and rotate exposed credentials or tokens if necessary.",
		}, true
	}
	return Match{}, false
}

func init() {
	Register(&I7HTTPTokenLeakRule{})
}
