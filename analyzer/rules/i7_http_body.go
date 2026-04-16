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
			Message:  msg,
			Evidence: ev,
		}, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPBodySecretRule{})
}
