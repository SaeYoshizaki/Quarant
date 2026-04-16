package rules

type I7HTTPTokenLeakRule struct{}

func (r *I7HTTPTokenLeakRule) ID() string         { return "I7_HTTP_TOKEN" }
func (r *I7HTTPTokenLeakRule) Category() string   { return "I7" }
func (r *I7HTTPTokenLeakRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPTokenLeakRule) Type() string       { return "INSECURE_HTTP_TOKEN" }

func (r *I7HTTPTokenLeakRule) Apply(ctx *Context) (Match, bool) {
	if ctx.HTTP == nil {
		return Match{}, false
	}

	for k := range ctx.HTTP.Query {
		if HasSensitiveKey(k) {
			return Match{
				Message:  "Sensitive parameter appears in plaintext HTTP query",
				Evidence: k + "=***",
			}, true
		}
	}
	return Match{}, false
}

func init() {
	Register(&I7HTTPTokenLeakRule{})
}
