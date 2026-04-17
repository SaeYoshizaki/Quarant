package rules

type I7TelnetPlaintextRule struct{}

func (r *I7TelnetPlaintextRule) ID() string         { return "I7_TELNET_PLAINTEXT" }
func (r *I7TelnetPlaintextRule) Category() string   { return "I7" }
func (r *I7TelnetPlaintextRule) Severity() Severity { return SeverityWarning }
func (r *I7TelnetPlaintextRule) Type() string       { return "INSECURE_TELNET" }

func (r *I7TelnetPlaintextRule) Apply(ctx *Context) (Match, bool) {
	if ctx.Telnet == nil || !ctx.Telnet.Plaintext {
		return Match{}, false
	}

	ev := Match{
		Message: "Plaintext Telnet detected",
	}
	if ctx.Debug {
		ev.Evidence = "service=telnet"
	}
	return ev, true
}

type I7TelnetCredentialsRule struct{}

func (r *I7TelnetCredentialsRule) ID() string         { return "I7_TELNET_CREDENTIALS" }
func (r *I7TelnetCredentialsRule) Category() string   { return "I7" }
func (r *I7TelnetCredentialsRule) Severity() Severity { return SeverityCritical }
func (r *I7TelnetCredentialsRule) Type() string       { return "INSECURE_TELNET_CREDENTIALS" }

func (r *I7TelnetCredentialsRule) Apply(ctx *Context) (Match, bool) {
	if ctx.Telnet == nil {
		return Match{}, false
	}

	if ctx.Telnet.PasswordPrompt && ctx.Telnet.ClientSubmitted {
		return Match{
			Message:  "Telnet password exchange observed over plaintext",
			Evidence: "telnet_password=***",
		}, true
	}

	if (ctx.Telnet.LoginPrompt || ctx.Telnet.UsernamePrompt) && ctx.Telnet.ClientSubmitted {
		return Match{
			Message:  "Telnet login identifier exchange observed over plaintext",
			Evidence: "telnet_login=***",
		}, true
	}

	return Match{}, false
}

type I7TelnetPayloadSecretRule struct{}

func (r *I7TelnetPayloadSecretRule) ID() string         { return "I7_TELNET_PAYLOAD_SECRET" }
func (r *I7TelnetPayloadSecretRule) Category() string   { return "I7" }
func (r *I7TelnetPayloadSecretRule) Severity() Severity { return SeverityCritical }
func (r *I7TelnetPayloadSecretRule) Type() string {
	return "INSECURE_TELNET_PAYLOAD_SECRET"
}

func (r *I7TelnetPayloadSecretRule) Apply(ctx *Context) (Match, bool) {
	if ctx.Telnet == nil || ctx.Telnet.SensitiveEvidence == "" {
		return Match{}, false
	}

	return Match{
		Message:  "Sensitive data appears in plaintext Telnet payload",
		Evidence: ctx.Telnet.SensitiveEvidence,
	}, true
}

func init() {
	Register(&I7TelnetPlaintextRule{})
	Register(&I7TelnetCredentialsRule{})
	Register(&I7TelnetPayloadSecretRule{})
}
