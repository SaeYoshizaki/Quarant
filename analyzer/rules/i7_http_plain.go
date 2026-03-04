package rules

import "bytes"

type I7HTTPPlaintextRule struct{}

func (r *I7HTTPPlaintextRule) ID() string         { return "I7_HTTP_PLAINTEXT" }
func (r *I7HTTPPlaintextRule) Category() string   { return "I7" }
func (r *I7HTTPPlaintextRule) Severity() Severity { return SeverityWarning }
func (r *I7HTTPPlaintextRule) Type() string       { return "INSECURE_HTTP" }

func (r *I7HTTPPlaintextRule) Apply(ctx *Context) (Match, bool) {
	p := ctx.Payload
	if len(p) == 0 {
		return Match{}, false
	}

	if bytes.HasPrefix(p, []byte("GET ")) ||
		bytes.HasPrefix(p, []byte("POST ")) ||
		bytes.HasPrefix(p, []byte("PUT ")) ||
		bytes.HasPrefix(p, []byte("DELETE ")) ||
		bytes.HasPrefix(p, []byte("HEAD ")) ||
		bytes.HasPrefix(p, []byte("OPTIONS ")) ||
		bytes.HasPrefix(p, []byte("PATCH ")) {

		ev := Match{
			Message: "Plaintext HTTP detected (first 16KB)",
		}
		if ctx.Debug {
			n := 32
			if len(p) < n {
				n = len(p)
			}
			ev.Evidence = string(p[:n])
		}
		return ev, true
	}

	return Match{}, false
}

func init() {
	Register(&I7HTTPPlaintextRule{})
}
