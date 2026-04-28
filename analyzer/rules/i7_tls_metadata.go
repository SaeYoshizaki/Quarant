package rules

import (
	"fmt"
	"strings"
)

type I7TLSWeakVersionRule struct{}

func (r *I7TLSWeakVersionRule) ID() string         { return "I7_TLS_WEAK_VERSION_OBSERVED" }
func (r *I7TLSWeakVersionRule) Category() string   { return "I7" }
func (r *I7TLSWeakVersionRule) Severity() Severity { return SeverityWarning }
func (r *I7TLSWeakVersionRule) Type() string       { return "I7_TLS_WEAK_VERSION_OBSERVED" }

func (r *I7TLSWeakVersionRule) Apply(ctx *Context) (Match, bool) {
	version := ObservedTLSVersion(ctx)
	classification, ok := ClassifyTLSVersion(version, "selected")
	if !ok {
		return Match{}, false
	}

	return Match{
		RuleID:         "I7_TLS_WEAK_VERSION_OBSERVED",
		Type:           "I7_TLS_WEAK_VERSION_OBSERVED",
		Category:       "I7",
		Message:        "Deprecated TLS version observed from passive TLS metadata.",
		Severity:       classification.Severity,
		Evidence:       tlsMetadataEvidence(ctx, fmt.Sprintf("risk_kind=%s tls_version=%s selected_or_offered=%s reason=%q observed_value=%s", classification.RiskKind, TLSVersionName(version), classification.SelectedOrOffered, classification.Reason, classification.ObservedValue)),
		OWASPTags:      uniqueTags("I7"),
		Confidence:     "high",
		ObservedFact:   "A deprecated TLS version was observed in TLS handshake metadata.",
		Inference:      "This may indicate legacy transport security behavior that requires review.",
		Limitation:     "HTTPS payload was not decrypted. Passive TLS metadata alone does not prove exploitable downgrade or compromise.",
		Recommendation: "Review whether the device or service can be updated to prefer TLS 1.2 or TLS 1.3 and retire legacy TLS where possible.",
	}, true
}

type I7TLSWeakCipherSuiteRule struct{}

func (r *I7TLSWeakCipherSuiteRule) ID() string         { return "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED" }
func (r *I7TLSWeakCipherSuiteRule) Category() string   { return "I7" }
func (r *I7TLSWeakCipherSuiteRule) Severity() Severity { return SeverityWarning }
func (r *I7TLSWeakCipherSuiteRule) Type() string       { return "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED" }

func (r *I7TLSWeakCipherSuiteRule) Apply(ctx *Context) (Match, bool) {
	match, ok := buildSelectedWeakCipherMatch(ctx, "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED", "I7_TLS_WEAK_CIPHER_SUITE_OBSERVED", "Weak TLS cipher suite observed from passive TLS metadata.")
	if !ok {
		return Match{}, false
	}
	return match, true
}

type I7TLSWeakCipherSelectedRule struct{}

func (r *I7TLSWeakCipherSelectedRule) ID() string         { return "I7_TLS_WEAK_CIPHER_SELECTED" }
func (r *I7TLSWeakCipherSelectedRule) Category() string   { return "I7" }
func (r *I7TLSWeakCipherSelectedRule) Severity() Severity { return SeverityWarning }
func (r *I7TLSWeakCipherSelectedRule) Type() string       { return "I7_TLS_WEAK_CIPHER_SELECTED" }

func (r *I7TLSWeakCipherSelectedRule) Apply(ctx *Context) (Match, bool) {
	return buildSelectedWeakCipherMatch(ctx, "I7_TLS_WEAK_CIPHER_SELECTED", "I7_TLS_WEAK_CIPHER_SELECTED", "Weak TLS cipher suite was selected in ServerHello passive metadata.")
}

func buildSelectedWeakCipherMatch(ctx *Context, ruleID, eventType, message string) (Match, bool) {
	if ctx == nil || ctx.TLSServerInfo == nil || ctx.TLSServerInfo.SelectedCipher == 0 {
		return Match{}, false
	}

	classification, ok := ClassifyTLSCipherSuite(ctx.TLSServerInfo.SelectedCipher, "selected")
	if !ok {
		return Match{}, false
	}

	version := ObservedTLSVersion(ctx)
	return Match{
		RuleID:         ruleID,
		Type:           eventType,
		Category:       "I7",
		Message:        message,
		Severity:       classification.Severity,
		Evidence:       tlsMetadataEvidence(ctx, fmt.Sprintf("risk_kind=%s cipher_suite_name=%s cipher_suite_id=0x%04X tls_version=%s selected_or_offered=%s reason=%q observed_value=%s", classification.RiskKind, classification.ObservedValue, ctx.TLSServerInfo.SelectedCipher, TLSVersionName(version), classification.SelectedOrOffered, classification.Reason, classification.ObservedValue)),
		OWASPTags:      uniqueTags("I7"),
		Confidence:     "medium",
		ObservedFact:   "A weak or legacy TLS cipher suite was selected in the ServerHello metadata.",
		Inference:      "This may indicate that the negotiated transport protection still allows legacy cipher choices and requires review.",
		Limitation:     "HTTPS payload was not decrypted. Passive TLS metadata does not confirm whether stronger suites were also available or preferred elsewhere.",
		Recommendation: "Review whether the device and remote service can prefer modern authenticated encryption suites and retire legacy cipher selections.",
	}, true
}

type I7TLSLegacyCipherOfferedRule struct{}

func (r *I7TLSLegacyCipherOfferedRule) ID() string         { return "I7_TLS_WEAK_CIPHER_OFFERED" }
func (r *I7TLSLegacyCipherOfferedRule) Category() string   { return "I7" }
func (r *I7TLSLegacyCipherOfferedRule) Severity() Severity { return SeverityLow }
func (r *I7TLSLegacyCipherOfferedRule) Type() string       { return "I7_TLS_WEAK_CIPHER_OFFERED" }

func (r *I7TLSLegacyCipherOfferedRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.TLSInfo == nil || len(ctx.TLSInfo.CipherSuites) == 0 {
		return Match{}, false
	}
	classifications := ClassifyOfferedTLSCiphers(ctx.TLSInfo.CipherSuites)
	if len(classifications) == 0 {
		return Match{}, false
	}

	severity := SeverityLow
	parts := make([]string, 0, len(classifications))
	for _, classification := range classifications {
		if classification.Severity == SeverityHigh || classification.Severity == SeverityWarning {
			severity = SeverityWarning
		}
		parts = append(parts, fmt.Sprintf("%s:%s", classification.RiskKind, classification.ObservedValue))
	}

	version := ObservedTLSVersion(ctx)
	return Match{
		RuleID:         "I7_TLS_WEAK_CIPHER_OFFERED",
		Type:           "I7_TLS_WEAK_CIPHER_OFFERED",
		Category:       "I7",
		Message:        "Weak TLS cipher suites were offered in ClientHello passive metadata.",
		Severity:       severity,
		Evidence:       tlsMetadataEvidence(ctx, fmt.Sprintf("risk_kind=weak_cipher_offered cipher_suite_name=%s cipher_suite_id=%s tls_version=%s selected_or_offered=offered reason=%q observed_value=%s", strings.Join(parts, ","), formatOfferedCipherIDs(ctx.TLSInfo.CipherSuites), TLSVersionName(version), "weak cipher suites were offered by the client", strings.Join(parts, ","))),
		OWASPTags:      uniqueTags("I7"),
		Confidence:     "medium",
		ObservedFact:   "The ClientHello offered one or more weak or legacy TLS cipher suites.",
		Inference:      "This may indicate legacy compatibility behavior that requires review.",
		Limitation:     "HTTPS payload was not decrypted. Passive TLS metadata does not show which offered suites would actually be accepted by the server.",
		Recommendation: "Review whether legacy cipher suites can be removed from the client or device TLS configuration.",
	}, true
}

type I7TLSOnlyLegacyCiphersOfferedRule struct{}

func (r *I7TLSOnlyLegacyCiphersOfferedRule) ID() string         { return "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED" }
func (r *I7TLSOnlyLegacyCiphersOfferedRule) Category() string   { return "I7" }
func (r *I7TLSOnlyLegacyCiphersOfferedRule) Severity() Severity { return SeverityWarning }
func (r *I7TLSOnlyLegacyCiphersOfferedRule) Type() string {
	return "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED"
}

func (r *I7TLSOnlyLegacyCiphersOfferedRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.TLSInfo == nil || len(ctx.TLSInfo.CipherSuites) == 0 {
		return Match{}, false
	}
	classifications := ClassifyOfferedTLSCiphers(ctx.TLSInfo.CipherSuites)
	if len(classifications) == 0 || HasModernOfferedTLSCipher(ctx.TLSInfo.CipherSuites) {
		return Match{}, false
	}

	parts := make([]string, 0, len(classifications))
	for _, classification := range classifications {
		parts = append(parts, fmt.Sprintf("%s:%s", classification.RiskKind, classification.ObservedValue))
	}

	version := ObservedTLSVersion(ctx)
	return Match{
		RuleID:         "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED",
		Type:           "I7_TLS_ONLY_LEGACY_CIPHERS_OFFERED",
		Category:       "I7",
		Message:        "Only legacy TLS cipher suites were offered in ClientHello passive metadata.",
		Severity:       SeverityWarning,
		Evidence:       tlsMetadataEvidence(ctx, fmt.Sprintf("risk_kind=only_legacy_ciphers_offered offered_weak_ciphers=%s tls_version=%s selected_or_offered=offered reason=%q observed_value=%s", strings.Join(parts, ","), TLSVersionName(version), "only legacy cipher suites were offered by the client", strings.Join(parts, ","))),
		OWASPTags:      uniqueTags("I7"),
		Confidence:     "medium",
		ObservedFact:   "The ClientHello only offered legacy or weak TLS cipher suites.",
		Inference:      "This may indicate a device or client stack that lacks modern cipher support.",
		Limitation:     "HTTPS payload was not decrypted. Passive TLS metadata does not prove whether the remote endpoint would support stronger suites if the client offered them.",
		Recommendation: "Review whether the device or TLS library can be updated to offer modern authenticated encryption cipher suites.",
	}, true
}

func formatOfferedCipherIDs(cipherSuites []uint16) string {
	classifications := ClassifyOfferedTLSCiphers(cipherSuites)
	if len(classifications) == 0 {
		return ""
	}
	out := make([]string, 0, len(classifications))
	seen := map[string]struct{}{}
	for _, id := range cipherSuites {
		classification, ok := ClassifyTLSCipherSuite(id, "offered")
		if !ok {
			continue
		}
		key := fmt.Sprintf("0x%04X", id)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		_ = classification
		out = append(out, key)
	}
	return strings.Join(out, ",")
}

type I7TLSCertificateAnomalyRule struct{}

func (r *I7TLSCertificateAnomalyRule) ID() string         { return "I7_TLS_CERTIFICATE_ANOMALY_OBSERVED" }
func (r *I7TLSCertificateAnomalyRule) Category() string   { return "I7" }
func (r *I7TLSCertificateAnomalyRule) Severity() Severity { return SeverityLow }
func (r *I7TLSCertificateAnomalyRule) Type() string       { return "I7_TLS_CERTIFICATE_ANOMALY_OBSERVED" }

func (r *I7TLSCertificateAnomalyRule) Apply(ctx *Context) (Match, bool) {
	if shouldSuppressI7TLSCertForUpdateFlow(ctx) {
		return Match{}, false
	}

	signals := TLSCertificateAnomalySignals(ctx)
	if len(signals) == 0 {
		return Match{}, false
	}

	cert := ctx.TLSServerInfo.Cert
	severity := SeverityLow
	if containsString(signals, "expired_cert") || containsString(signals, "not_yet_valid_cert") {
		severity = SeverityWarning
	} else if containsString(signals, "self_signed_cert") && !containsString(signals, "cert_sni_mismatch") {
		severity = SeverityLow
	} else {
		severity = SeverityWarning
	}

	parts := []string{
		fmt.Sprintf("cert_subject=%q", cert.Subject),
		fmt.Sprintf("cert_issuer=%q", cert.Issuer),
		fmt.Sprintf("cert_anomalies=%s", strings.Join(signals, ",")),
	}
	if !cert.NotBefore.IsZero() {
		parts = append(parts, fmt.Sprintf("not_before=%s", cert.NotBefore.UTC().Format("2006-01-02")))
	}
	if !cert.NotAfter.IsZero() {
		parts = append(parts, fmt.Sprintf("not_after=%s", cert.NotAfter.UTC().Format("2006-01-02")))
	}

	return Match{
		RuleID:         "I7_TLS_CERTIFICATE_ANOMALY_OBSERVED",
		Type:           "I7_TLS_CERTIFICATE_ANOMALY_OBSERVED",
		Category:       "I7",
		Message:        "TLS certificate anomaly observed from passive TLS metadata.",
		Severity:       severity,
		Evidence:       tlsMetadataEvidence(ctx, strings.Join(parts, " ")),
		OWASPTags:      uniqueTags("I7"),
		Confidence:     "medium",
		ObservedFact:   "Certificate metadata exposed in the observed TLS handshake contained anomaly indicators.",
		Inference:      "This may indicate a legacy, misconfigured, or private trust deployment that requires review.",
		Limitation:     "HTTPS payload was not decrypted. Passive TLS metadata does not prove that the connection was accepted without other compensating controls.",
		Recommendation: "Review whether the certificate, validity window, and hostname relationship are expected for this device and destination.",
	}, true
}

func tlsMetadataEvidence(ctx *Context, details string) string {
	parts := []string{details}
	if ctx != nil {
		parts = append(parts, fmt.Sprintf("src=%s:%d", ctx.SrcIP, ctx.SrcPort))
		parts = append(parts, fmt.Sprintf("dst=%s:%d", ctx.DstIP, ctx.DstPort))
		if ctx.TLSInfo != nil {
			if strings.TrimSpace(ctx.TLSInfo.SNI) != "" {
				parts = append(parts, fmt.Sprintf("sni=%s", strings.TrimSpace(ctx.TLSInfo.SNI)))
			}
			if ctx.TLSInfo.ClientVersion != 0 {
				parts = append(parts, fmt.Sprintf("client_legacy_version=%s", TLSVersionName(ctx.TLSInfo.ClientVersion)))
			}
			if len(ctx.TLSInfo.SupportedVersions) > 0 {
				parts = append(parts, fmt.Sprintf("client_supported_versions=%s", TLSVersionNames(ctx.TLSInfo.SupportedVersions)))
			}
		}
		if ctx.TLSServerInfo != nil {
			if ctx.TLSServerInfo.ServerVersion != 0 {
				parts = append(parts, fmt.Sprintf("server_legacy_version=%s", TLSVersionName(ctx.TLSServerInfo.ServerVersion)))
			}
			if ctx.TLSServerInfo.SelectedVersion != 0 {
				parts = append(parts, fmt.Sprintf("server_selected_version=%s", TLSVersionName(ctx.TLSServerInfo.SelectedVersion)))
			}
		}
	}
	parts = append(parts, "payload_decrypted=false")
	return strings.Join(parts, " ")
}

func shouldSuppressI7TLSCertForUpdateFlow(ctx *Context) bool {
	if ctx == nil {
		return false
	}
	obs, ok := detectFirmwareUpdateObservation(ctx)
	return ok && obs.StrongHit && obs.External
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func init() {
	Register(&I7TLSWeakVersionRule{})
	Register(&I7TLSWeakCipherSelectedRule{})
	Register(&I7TLSWeakCipherSuiteRule{})
	Register(&I7TLSLegacyCipherOfferedRule{})
	Register(&I7TLSOnlyLegacyCiphersOfferedRule{})
	Register(&I7TLSCertificateAnomalyRule{})
}
