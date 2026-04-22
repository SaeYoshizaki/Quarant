package rules

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type I4SuspiciousUpdateSourceRule struct{}

func (r *I4SuspiciousUpdateSourceRule) ID() string         { return "I4_SUSPICIOUS_UPDATE_SOURCE" }
func (r *I4SuspiciousUpdateSourceRule) Category() string   { return "I4" }
func (r *I4SuspiciousUpdateSourceRule) Severity() Severity { return SeverityWarning }
func (r *I4SuspiciousUpdateSourceRule) Type() string       { return "I4_SUSPICIOUS_UPDATE_SOURCE" }

func (r *I4SuspiciousUpdateSourceRule) Apply(ctx *Context) (Match, bool) {
	obs, ok := detectFirmwareUpdateObservation(ctx)
	if !ok || !obs.StrongHit || !obs.External {
		return Match{}, false
	}

	signals := suspiciousI4UpdateSourceSignals(ctx, obs)
	if len(signals) == 0 {
		return Match{}, false
	}

	return Match{
		Message: "Firmware/update-like communication observed from a suspicious update source",
		Evidence: fmt.Sprintf(
			"%s suspicious_signals=%s",
			formatI4FirmwareEvidence(obs),
			strings.Join(signals, ","),
		),
	}, true
}

func suspiciousI4UpdateSourceSignals(ctx *Context, obs i4FirmwareUpdateObservation) []string {
	signals := make([]string, 0, 4)
	if isLiteralIP(obs.Endpoint) {
		signals = append(signals, "literal_ip_endpoint")
	}

	if ctx == nil {
		return signals
	}

	sni := safeTrim(ctx.TLSInfo)
	if ctx.TLS && sni == "" {
		signals = append(signals, "missing_sni")
	}

	var cert *TLSCertificateInfo
	if ctx.TLSServerInfo != nil {
		cert = ctx.TLSServerInfo.Cert
	}
	if cert == nil {
		return signals
	}
	if cert.SelfSigned {
		signals = append(signals, "self_signed_cert")
	}
	if sni != "" && !certLooksRelatedToSNI(cert, sni) {
		signals = append(signals, "cert_sni_mismatch")
	}

	return signals
}

func isLiteralIP(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}

	if parsed, err := url.Parse(value); err == nil && parsed.Host != "" {
		value = parsed.Host
	}

	value = strings.Trim(value, "[]")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}

	return net.ParseIP(value) != nil
}

func safeTrim(info *TLSClientHelloInfo) string {
	if info == nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(info.SNI))
}

func certLooksRelatedToSNI(cert *TLSCertificateInfo, sni string) bool {
	if cert == nil {
		return false
	}
	sni = strings.ToLower(strings.TrimSpace(sni))
	if sni == "" {
		return false
	}

	if tlsNameMatchesSNI(cert.Subject, sni) {
		return true
	}
	for _, san := range cert.SANs {
		if tlsNameMatchesSNI(san, sni) {
			return true
		}
	}
	return false
}

func tlsNameMatchesSNI(name, sni string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	if name == sni {
		return true
	}
	if strings.HasPrefix(name, "*.") {
		suffix := strings.TrimPrefix(name, "*")
		prefix := strings.TrimSuffix(sni, suffix)
		return strings.HasSuffix(sni, suffix) && prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}

func init() {
	Register(&I4SuspiciousUpdateSourceRule{})
}
