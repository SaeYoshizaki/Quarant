package rules

type I7HTTPBodySecretRule struct{}

func (r *I7HTTPBodySecretRule) ID() string         { return "I7_HTTP_BODY_SECRET" }
func (r *I7HTTPBodySecretRule) Category() string   { return "I7" }
func (r *I7HTTPBodySecretRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPBodySecretRule) Type() string       { return "INSECURE_HTTP_BODY_SECRET" }

func (r *I7HTTPBodySecretRule) Apply(ctx *Context) (Match, bool) {
	if ctx.HTTP == nil {
		return Match{}, false
	}
	if len(ctx.HTTP.Body) == 0 {
		return Match{}, false
	}

	if msg, ev, ok := DetectSensitiveHTTPBody(ctx.HTTP.ContentType, ctx.HTTP.Body); ok {
		return Match{
			Message:        msg,
			Evidence:       ev,
			OWASPTags:      uniqueTags("I1", "I3", "I7"),
			Confidence:     "high",
			ObservedFact:   "Sensitive value patterns were observed in a plaintext HTTP body.",
			Inference:      "Credentials, tokens, or stable identifiers may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine whether the observed value is active, hardcoded, or accepted by the remote service.",
			Recommendation: "Use HTTPS, review which fields are sent in request bodies, and rotate exposed secrets if necessary.",
		}, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPBodySecretRule{})
}
