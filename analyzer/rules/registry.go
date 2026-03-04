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
	out := make([]Match, 0, 4)
	for _, r := range registered {
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
