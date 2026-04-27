package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I3APIOverPlaintextRule struct{}

func (r *I3APIOverPlaintextRule) ID() string         { return "I3_API_OVER_PLAINTEXT" }
func (r *I3APIOverPlaintextRule) Category() string   { return "I3" }
func (r *I3APIOverPlaintextRule) Severity() Severity { return SeverityWarning }
func (r *I3APIOverPlaintextRule) Type() string       { return "I3_API_OVER_PLAINTEXT" }

func (r *I3APIOverPlaintextRule) Apply(ctx *Context) (Match, bool) {
	if !isI3PlaintextHTTP(ctx) {
		return Match{}, false
	}

	host := i3Header(ctx.HTTP, "host")
	if !isAPIEndpoint(ctx.HTTP.Path, host) {
		return Match{}, false
	}

	severity := SeverityWarning
	if isSensitiveAPIEndpoint(ctx.HTTP.Path) {
		severity = SeverityHigh
	}

	return Match{
		RuleID:         "I3_API_OVER_PLAINTEXT",
		Type:           "I3_API_OVER_PLAINTEXT",
		Category:       "I3",
		Severity:       severity,
		Message:        "HTTP API-like communication was observed over plaintext transport.",
		Evidence:       fmt.Sprintf("method=%s path=%s host=%s", ctx.HTTP.Method, ctx.HTTP.Path, host),
		OWASPTags:      uniqueTags("I3", "I7"),
		Confidence:     "high",
		ObservedFact:   "HTTP API-like endpoint was observed without transport encryption.",
		Inference:      "This may indicate an insecure ecosystem interface or API transport risk.",
		Limitation:     "Passive monitoring does not prove that the API itself is vulnerable, lacks authentication, or has authorization flaws.",
		Recommendation: "Use HTTPS if supported and review firmware or app settings for API and cloud connectivity.",
	}, true
}

type I3AuthTokenInURLRule struct{}

func (r *I3AuthTokenInURLRule) ID() string         { return "I3_AUTH_TOKEN_IN_URL" }
func (r *I3AuthTokenInURLRule) Category() string   { return "I3" }
func (r *I3AuthTokenInURLRule) Severity() Severity { return SeverityHigh }
func (r *I3AuthTokenInURLRule) Type() string       { return "I3_AUTH_TOKEN_IN_URL" }

func (r *I3AuthTokenInURLRule) Apply(ctx *Context) (Match, bool) {
	if !isI3PlaintextHTTP(ctx) {
		return Match{}, false
	}

	keys := i3SensitiveURLKeys(ctx.HTTP.Query)
	if len(keys) == 0 {
		return Match{}, false
	}

	return Match{
		RuleID:         "I3_AUTH_TOKEN_IN_URL",
		Type:           "I3_AUTH_TOKEN_IN_URL",
		Category:       "I3",
		Severity:       i3AuthTokenSeverity(keys),
		Message:        "Authentication-related value was observed in the URL query string.",
		Evidence:       maskSensitiveQueryKeys(ctx.HTTP.Query, keys),
		OWASPTags:      uniqueTags("I1", "I3", "I7"),
		Confidence:     "high",
		ObservedFact:   "Authentication-related query parameter was observed in the URL.",
		Inference:      "URL parameters may be exposed through logs, proxies, browser history, or intermediary systems.",
		Limitation:     "Passive monitoring cannot determine whether the value is still valid or whether the backend has additional security controls.",
		Recommendation: "Avoid placing tokens or secrets in URLs, use headers or request bodies over HTTPS, and rotate exposed credentials if necessary.",
	}, true
}

type I3ManagementAPIExposedRule struct{}

func (r *I3ManagementAPIExposedRule) ID() string         { return "I3_MANAGEMENT_API_EXPOSED" }
func (r *I3ManagementAPIExposedRule) Category() string   { return "I3" }
func (r *I3ManagementAPIExposedRule) Severity() Severity { return SeverityWarning }
func (r *I3ManagementAPIExposedRule) Type() string       { return "I3_MANAGEMENT_API_EXPOSED" }

func (r *I3ManagementAPIExposedRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil {
		return Match{}, false
	}

	var path string
	var host string
	plaintext := false
	switch {
	case ctx.HTTP != nil:
		path = ctx.HTTP.Path
		host = i3Header(ctx.HTTP, "host")
		plaintext = !ctx.TLS
	case ctx.TLSInfo != nil:
		host = strings.TrimSpace(ctx.TLSInfo.SNI)
	default:
		return Match{}, false
	}

	if !isManagementEndpoint(path) && !strings.Contains(strings.ToLower(host), "admin") {
		return Match{}, false
	}

	return Match{
		RuleID:         "I3_MANAGEMENT_API_EXPOSED",
		Type:           "I3_MANAGEMENT_API_EXPOSED",
		Category:       "I3",
		Severity:       i3ManagementSeverity(ctx, path, plaintext),
		Message:        "Management or configuration endpoint-like communication was observed.",
		Evidence:       fmt.Sprintf("path=%s host=%s plaintext=%t", path, host, plaintext),
		OWASPTags:      uniqueTags("I2", "I3", "I7", "I9"),
		Confidence:     "medium",
		ObservedFact:   "Management, setup, diagnostic, or backup-related endpoint pattern was observed in traffic.",
		Inference:      "This may indicate a reachable management interface or configuration API that deserves review. It may also indicate that setup or administrative functionality remains reachable.",
		Limitation:     "Passive monitoring does not prove that authentication is missing, that the endpoint is externally reachable, or that any default settings remain unchanged.",
		Recommendation: "Confirm that management interfaces are expected, disable or restrict setup and management paths after provisioning, use HTTPS where supported, and verify that they are not exposed beyond trusted networks.",
	}, true
}

type I3WeakEcosystemCryptoSignalRule struct{}

func (r *I3WeakEcosystemCryptoSignalRule) ID() string { return "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL" }
func (r *I3WeakEcosystemCryptoSignalRule) Category() string {
	return "I3"
}
func (r *I3WeakEcosystemCryptoSignalRule) Severity() Severity { return SeverityWarning }
func (r *I3WeakEcosystemCryptoSignalRule) Type() string {
	return "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL"
}

func (r *I3WeakEcosystemCryptoSignalRule) Apply(ctx *Context) (Match, bool) {
	if !isI3PlaintextHTTP(ctx) {
		return Match{}, false
	}

	host := i3Header(ctx.HTTP, "host")
	path := ctx.HTTP.Path
	if !isCloudOrBackendHost(host) && !isCloudOrBackendPath(path) {
		return Match{}, false
	}

	severity := SeverityWarning
	if IsPublicIP(ctx.DstIP) {
		severity = SeverityHigh
	}

	return Match{
		RuleID:         "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL",
		Type:           "I3_WEAK_ECOSYSTEM_CRYPTO_SIGNAL",
		Category:       "I3",
		Severity:       severity,
		Message:        "Cloud or backend API-like communication was observed without transport encryption.",
		Evidence:       fmt.Sprintf("host=%s path=%s external=%t", host, path, IsPublicIP(ctx.DstIP)),
		OWASPTags:      uniqueTags("I3", "I7"),
		Confidence:     "medium",
		ObservedFact:   "Cloud, backend, or account-related HTTP communication was observed over plaintext transport.",
		Inference:      "This may indicate weak ecosystem interface transport protection for cloud or backend communication.",
		Limitation:     "Passive monitoring does not prove that the backend is vulnerable or reveal whether stronger transport is available but not used by this device.",
		Recommendation: "Use HTTPS if supported, review firmware and app settings, and confirm the device is using current vendor-supported connectivity.",
	}, true
}

type I3MobileAppBackendPatternObservedRule struct{}

func (r *I3MobileAppBackendPatternObservedRule) ID() string {
	return "I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED"
}
func (r *I3MobileAppBackendPatternObservedRule) Category() string   { return "I3" }
func (r *I3MobileAppBackendPatternObservedRule) Severity() Severity { return SeverityWarning }
func (r *I3MobileAppBackendPatternObservedRule) Type() string {
	return "I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED"
}

func (r *I3MobileAppBackendPatternObservedRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.HTTP == nil || ctx.TLS {
		return Match{}, false
	}

	host := i3Header(ctx.HTTP, "host")
	userAgent := i3Header(ctx.HTTP, "user-agent")
	if !isMobileBackendPattern(host, ctx.HTTP.Path, userAgent) {
		return Match{}, false
	}
	if !strings.Contains(strings.ToLower(ctx.HTTP.Path), "/mobile") &&
		!strings.Contains(strings.ToLower(ctx.HTTP.Path), "/app") &&
		!strings.Contains(strings.ToLower(ctx.HTTP.Path), "/account") &&
		!strings.Contains(strings.ToLower(ctx.HTTP.Path), "/pair") &&
		!strings.Contains(strings.ToLower(ctx.HTTP.Path), "/register") &&
		!strings.Contains(strings.ToLower(ctx.HTTP.Path), "/sync") &&
		!isCloudOrBackendHost(host) &&
		!isCloudOrBackendPath(ctx.HTTP.Path) &&
		!i3HasQuerySupportHint(ctx.HTTP.Query) {
		return Match{}, false
	}

	severity := SeverityWarning
	if i3ContainsSensitiveKey(ctx.HTTP.Query) {
		severity = SeverityHigh
	}

	return Match{
		RuleID:         "I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED",
		Type:           "I3_MOBILE_APP_BACKEND_PATTERN_OBSERVED",
		Category:       "I3",
		Severity:       severity,
		Message:        "Mobile app or account-backend-like communication was observed over plaintext HTTP.",
		Evidence:       fmt.Sprintf("host=%s path=%s user_agent=%s", host, ctx.HTTP.Path, summarizeI3UserAgent(userAgent)),
		OWASPTags:      uniqueTags("I3", "I7"),
		Confidence:     "medium",
		ObservedFact:   "Mobile app, user account, pairing, or notification backend pattern was observed in plaintext HTTP traffic.",
		Inference:      "This may indicate an ecosystem backend workflow where plaintext transport, token use, or unusual destinations increase risk.",
		Limitation:     "Passive monitoring does not prove that the backend is vulnerable or that the observed workflow is unintended.",
		Recommendation: "Review whether mobile-app and account synchronization traffic is expected, prefer HTTPS, and verify token handling in device and app settings.",
	}, true
}

type I3UnexpectedCloudEndpointRule struct {
	db *knowledge.DB
}

func NewI3UnexpectedCloudEndpointRule(db *knowledge.DB) *I3UnexpectedCloudEndpointRule {
	return &I3UnexpectedCloudEndpointRule{db: db}
}

func (r *I3UnexpectedCloudEndpointRule) ApplyAll(ctx *Context) []Match {
	if r == nil || r.db == nil || ctx == nil {
		return nil
	}

	var host, path string
	switch {
	case ctx.HTTP != nil:
		host = i3Header(ctx.HTTP, "host")
		path = ctx.HTTP.Path
	case ctx.TLSInfo != nil:
		host = strings.TrimSpace(ctx.TLSInfo.SNI)
	default:
		return nil
	}

	if host == "" || (!isCloudOrBackendHost(host) && !isCloudOrBackendPath(path) && !isAPIEndpoint(path, host)) {
		return nil
	}

	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = strings.TrimSpace(ctx.LocalDeviceCategory)
	}
	if category == "" {
		return nil
	}

	inference, ok := r.db.GetCategoryInference(category)
	if !ok {
		return nil
	}
	if hostMatchesRepresentativeDomains(host, inference.RepresentativeDomains) || hostMatchesRepresentativeDomains(host, inference.EcosystemDomains) {
		return nil
	}

	severity := SeverityWarning
	if isI3PlaintextHTTP(ctx) && (i3ContainsSensitiveKey(ctx.HTTP.Query) || isSensitiveAPIEndpoint(path)) {
		severity = SeverityHigh
	}

	match := Match{
		RuleID:   "I3_UNEXPECTED_CLOUD_ENDPOINT",
		Type:     "I3_UNEXPECTED_CLOUD_ENDPOINT",
		Category: "I3",
		Severity: severity,
		Message:  "Unexpected ecosystem endpoint signal observed for the inferred device category.",
		Evidence: fmt.Sprintf(
			"category=%s vendor_candidate=%s family_candidate=%s host=%s path=%s representative_domains=%s ecosystem_domains=%s plaintext=%t",
			category,
			strings.TrimSpace(ctx.VendorCandidate),
			strings.TrimSpace(ctx.FamilyCandidate),
			host,
			path,
			strings.Join(inference.RepresentativeDomains, ","),
			strings.Join(inference.EcosystemDomains, ","),
			isI3PlaintextHTTP(ctx),
		),
		OWASPTags:      uniqueTags("I3"),
		Confidence:     "medium",
		ObservedFact:   "API or cloud-like endpoint was observed outside the currently learned representative or ecosystem domains for the device category.",
		Inference:      "This may indicate an unexpected ecosystem interface destination that should be verified.",
		Limitation:     "Passive monitoring does not prove malicious behavior, compromise, or vendor-policy violation. The endpoint may be legitimate but missing from local knowledge.",
		Recommendation: "Verify that the cloud or API endpoint is expected for the device, firmware, or companion app, and review any new integrations or account-linking changes.",
	}
	return []Match{match}
}

func summarizeI3UserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return ""
	}
	if len(userAgent) > 48 {
		return userAgent[:48] + "..."
	}
	return userAgent
}

func init() {
	Register(&I3APIOverPlaintextRule{})
	Register(&I3AuthTokenInURLRule{})
	Register(&I3ManagementAPIExposedRule{})
	Register(&I3WeakEcosystemCryptoSignalRule{})
	Register(&I3MobileAppBackendPatternObservedRule{})
}
