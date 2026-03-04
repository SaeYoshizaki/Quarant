package rules

import "fmt"

type TLSClientHelloRule struct{}

func (r *TLSClientHelloRule) ID() string         { return "TLS_CLIENT_HELLO" }
func (r *TLSClientHelloRule) Category() string   { return "TLS" }
func (r *TLSClientHelloRule) Severity() Severity { return SeverityInfo }
func (r *TLSClientHelloRule) Type() string       { return "TLS_CLIENT_HELLO" }

func (r *TLSClientHelloRule) Apply(ctx *Context) (Match, bool) {
	if len(ctx.Payload) == 0 {
		return Match{}, false
	}

	info, ok := DetectTLSClientHello(ctx.Payload)
	if !ok {
		return Match{}, false
	}

	msg := fmt.Sprintf(
		"TLS ClientHello detected (record_ver=0x%04x client_ver=0x%04x)",
		info.RecordVersion, info.ClientVersion,
	)
	evidence := ""
	if info.SNI != "" {
		msg += fmt.Sprintf(" sni=%q", info.SNI)
		evidence = info.SNI
	}

	return Match{
		Message:  msg,
		Evidence: evidence,
	}, true
}

func init() {
	Register(&TLSClientHelloRule{})
}
