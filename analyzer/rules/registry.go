package rules

type Rule interface {
	ID() string
	Category() string
	Severity() Severity
	Type() string
	Apply(ctx *Context) (Match, bool)
}

var registered []Rule

func Register(r Rule) {
	registered = append(registered, r)
}

func Run(ctx *Context) []Match {
	return run(ctx, nil)
}

// contentHTTPRules are the rules that also see HTTP recognised by content on
// a port outside IsHTTPPort (D23): secrets and media in cleartext. The other
// HTTP rules stay on the standard ports, because applied to UPnP traffic they
// turned protocol-mandated description fetches into ~170k findings (D17).
var contentHTTPRules = map[string]bool{
	"I7_HTTP_AUTH":              true,
	"I7_HTTP_TOKEN":             true,
	"I7_HTTP_COOKIE":            true,
	"I7_HTTP_BODY_SECRET":       true,
	"I3_AUTH_TOKEN_IN_URL":      true,
	"I6_MEDIA_UPLOAD_CLEARTEXT": true,
}

// RunContentHTTP runs only the rules allowed on HTTP recognised by content.
func RunContentHTTP(ctx *Context) []Match {
	return run(ctx, contentHTTPRules)
}

// ContentHTTPRuleIDs lists the rules RunContentHTTP runs.
func ContentHTTPRuleIDs() []string {
	ids := make([]string, 0, len(contentHTTPRules))
	for id := range contentHTTPRules {
		ids = append(ids, id)
	}
	return ids
}

func run(ctx *Context, only map[string]bool) []Match {
	out := make([]Match, 0, 4)
	for _, r := range registered {
		if only != nil && !only[r.ID()] {
			continue
		}
		if m, ok := r.Apply(ctx); ok {
			if m.RuleID == "" {
				m.RuleID = r.ID()
			}
			if m.Category == "" {
				m.Category = r.Category()
			}
			if m.Severity == "" {
				m.Severity = r.Severity()
			}
			if m.Type == "" {
				m.Type = r.Type()
			}
			out = append(out, m)
		}
	}
	return out
}
