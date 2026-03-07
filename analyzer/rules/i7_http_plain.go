package rules

type I7HTTPPlaintextRule struct{}

func (r *I7HTTPPlaintextRule) ID() string         { return "I7_HTTP_PLAINTEXT" }
func (r *I7HTTPPlaintextRule) Category() string   { return "I7" }
func (r *I7HTTPPlaintextRule) Severity() Severity { return SeverityWarning }
func (r *I7HTTPPlaintextRule) Type() string       { return "INSECURE_HTTP" }

func (r *I7HTTPPlaintextRule) Apply(ctx *Context) (Match, bool) {

	if ctx.HTTP == nil {
		return Match{}, false
	}

	ev := Match{
		Message: "Plaintext HTTP detected",
	}

	if ctx.Debug {
		host := ctx.HTTP.Headers["host"]

		evidence := ctx.HTTP.Method + " " + ctx.HTTP.Path

		if host != "" {
			evidence += " host=" + host
		}

		ev.Evidence = evidence
	}

	return ev, true
}

func init() {
	Register(&I7HTTPPlaintextRule{})
}
