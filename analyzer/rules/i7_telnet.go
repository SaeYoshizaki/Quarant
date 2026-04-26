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
		Message:        "Plaintext Telnet traffic was observed.",
		OWASPTags:      uniqueTags("I2", "I7"),
		Confidence:     "high",
		ObservedFact:   "Telnet traffic was observed.",
		Inference:      "Telnet is a plaintext remote login service, so credentials and commands may be exposed in transit.",
		Limitation:     "Passive monitoring does not confirm whether Telnet is required or whether access is restricted to a trusted segment.",
		Recommendation: "Disable Telnet if not required, or replace it with SSH or a vendor-supported secure management method.",
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
			Message:        "Telnet password exchange was observed over plaintext transport.",
			Evidence:       "telnet_password=***",
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "Telnet password exchange was observed in plaintext traffic.",
			Inference:      "Credentials may be exposed in transit.",
			Limitation:     "Passive monitoring cannot determine password strength or whether the credential is default, shared, or hardcoded.",
			Recommendation: "Disable Telnet if not required, replace it with SSH if possible, and rotate exposed credentials if needed.",
		}, true
	}

	if (ctx.Telnet.LoginPrompt || ctx.Telnet.UsernamePrompt) && ctx.Telnet.ClientSubmitted {
		return Match{
			Message:        "Telnet login identifier exchange was observed over plaintext transport.",
			Evidence:       "telnet_login=***",
			OWASPTags:      uniqueTags("I1", "I2", "I7"),
			Confidence:     "high",
			ObservedFact:   "Telnet login identifier exchange was observed in plaintext traffic.",
			Inference:      "Authentication identifiers may be exposed in transit.",
			Limitation:     "Passive monitoring cannot confirm whether the identifier alone grants access or whether stronger controls are present.",
			Recommendation: "Disable Telnet if not required, replace it with SSH if possible, and review account exposure.",
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
		Message:        "Sensitive data appears in plaintext Telnet payload.",
		Evidence:       ctx.Telnet.SensitiveEvidence,
		OWASPTags:      uniqueTags("I1", "I2", "I7"),
		Confidence:     "high",
		ObservedFact:   "Sensitive data pattern was observed in plaintext Telnet payload.",
		Inference:      "Credentials, tokens, or identifiers may be exposed in transit.",
		Limitation:     "Passive monitoring cannot determine whether the value remains valid or whether the device provides a safer management channel.",
		Recommendation: "Disable Telnet if not required, replace it with SSH if possible, and review plaintext management exposure.",
	}, true
}

func init() {
	Register(&I7TelnetPlaintextRule{})
	Register(&I7TelnetCredentialsRule{})
	Register(&I7TelnetPayloadSecretRule{})
}
