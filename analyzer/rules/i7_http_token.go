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

	keys := []string{
		"password", "passwd", "pwd",
		"token", "access_token",
		"apikey", "api_key",
		"secret", "client_secret",
	}

	for _, k := range keys {
		if _, ok := ctx.HTTP.Query[k]; ok {
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
