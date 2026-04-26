package rules

import (
	"fmt"
	"strings"

	"quarant/analyzer/knowledge"
)

type I6PrivacyRule struct {
	db *knowledge.DB
}

func NewI6PrivacyRule(db *knowledge.DB) *I6PrivacyRule {
	return &I6PrivacyRule{db: db}
}

func (r *I6PrivacyRule) ID() string         { return "I6_PRIVACY" }
func (r *I6PrivacyRule) Category() string   { return "I6" }
func (r *I6PrivacyRule) Severity() Severity { return SeverityWarning }
func (r *I6PrivacyRule) Type() string       { return "I6_PRIVACY" }

func (r *I6PrivacyRule) Apply(ctx *Context) (Match, bool) {
	matches := r.ApplyAll(ctx)
	if len(matches) == 0 {
		return Match{}, false
	}
	return matches[0], true
}

func (r *I6PrivacyRule) ApplyAll(ctx *Context) []Match {
	if r.db == nil || ctx == nil || (ctx.HTTP == nil && ctx.TLSInfo == nil) {
		return nil
	}

	commType := detectI6CommunicationType(ctx)
	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = "unknown"
	}

	out := make([]Match, 0, 4)

	if mismatch := r.applyCategoryMismatch(ctx); mismatch != nil {
		out = append(out, *mismatch)
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		out = append(out, r.applyBehaviorBaselineAll(ctx, category, commType)...)
	}

	out = append(out, r.applyStorageSignalAll(ctx, category)...)

	if commType == "" {
		return out
	}

	hits := DetectPIIHits(ctx.HTTP, ctx.Payload)
	if len(hits) == 0 {
		return out
	}

	out = append(out, r.applyPIIUseSignalAll(ctx, category, commType, hits)...)

	if category != "unknown" && r.db.IsKnownCategory(category) {
		for _, hit := range hits {
			if r.db.IsSuspiciousCombination(category, commType, hit.Type) {
				out = append(out, Match{
					RuleID:   "I6_HTTP_PRIVACY_RISK_SIGNAL",
					Type:     "I6_HTTP_PRIVACY_RISK_SIGNAL",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Privacy-related communication risk signal observed for this device category.",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
					OWASPTags:      uniqueTags("I6", "I7"),
					Confidence:     "medium",
					ObservedFact:   "Privacy-related value was observed in traffic for a device category and communication type combination that local policy marks as suspicious.",
					Inference:      "This may indicate privacy-sensitive communication that deserves review.",
					Limitation:     "Passive monitoring cannot determine user consent, privacy policy compliance, or whether the observed data was used improperly.",
					Recommendation: "Review whether this communication type and destination are expected for the device and limit plaintext exposure where possible.",
				})
			}
		}

		if !r.db.IsAllowedCommunicationType(category, commType) {
			hit := hits[0]
			out = append(out, Match{
				RuleID:   "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Type:     "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Unexpected privacy-related communication was observed for this device category.",
				Evidence: fmt.Sprintf(
					"category=%s comm_type=%s pii_type=%s source=%s %s",
					category, commType, hit.Type, hit.Source, hit.Evidence,
				),
				OWASPTags:      uniqueTags("I6", "I7"),
				Confidence:     "medium",
				ObservedFact:   "Privacy-related value was observed in a communication type that is not normally allowed for this device category.",
				Inference:      "This may indicate an unexpected privacy destination or communication pattern.",
				Limitation:     "Passive monitoring cannot determine user consent or whether the device vendor documents this communication elsewhere.",
				Recommendation: "Verify that the destination and communication type are expected for the device.",
			})
		}

		for _, hit := range hits {
			if !r.db.IsAllowedPIIType(category, hit.Type) {
				out = append(out, Match{
					RuleID:   "I6_HTTP_UNEXPECTED_PII",
					Type:     "I6_HTTP_UNEXPECTED_PII",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Unexpected privacy-sensitive data type was observed for this device category.",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
					OWASPTags:      uniqueTags("I6", "I7"),
					Confidence:     "medium",
					ObservedFact:   "A privacy-sensitive data type was observed for a device category that does not normally require it.",
					Inference:      "This may indicate privacy-sensitive data exposure beyond the device's expected role.",
					Limitation:     "Passive monitoring cannot determine whether the data is user-approved, policy-compliant, or required by an undocumented feature.",
					Recommendation: "Review device settings, destinations, and whether this data type is expected for the device category.",
				})
			}
		}

		return dedupeMatches(out)
	}

	for _, hit := range hits {
		if commType == "analytics" || commType == "tracking" {
			out = append(out, Match{
				RuleID:   "I6_HTTP_PRIVACY_EXPOSURE",
				Type:     "I6_HTTP_PRIVACY_EXPOSURE",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-sensitive data exposure signal was observed in HTTP communication.",
				Evidence: fmt.Sprintf(
					"comm_type=%s pii_type=%s source=%s %s category=%s",
					commType, hit.Type, hit.Source, hit.Evidence, category,
				),
				OWASPTags:      uniqueTags("I6", "I7"),
				Confidence:     "medium",
				ObservedFact:   "Privacy-related value was observed in HTTP analytics or tracking-like communication.",
				Inference:      "This may indicate privacy-sensitive data exposure to an unexpected destination class.",
				Limitation:     "Passive monitoring cannot determine consent, policy compliance, or whether the value is pseudonymized elsewhere.",
				Recommendation: "Review whether the destination is expected and whether privacy-sensitive fields should be removed or encrypted.",
			})
		}
	}

	return dedupeMatches(out)
}

func (r *I6PrivacyRule) applyStorageSignalAll(ctx *Context, category string) []Match {
	if r.db == nil || r.db.I6StorageSignals == nil || ctx == nil || ctx.HTTP == nil {
		return nil
	}
	if !isHTTPUploadMethod(ctx.HTTP.Method) {
		return nil
	}

	host, path := observedEndpoint(ctx)
	if host == "" && path == "" {
		return nil
	}

	uploadBytes := ctx.UploadBytes
	if uploadBytes <= 0 && ctx.HTTP != nil {
		uploadBytes = len(ctx.HTTP.Body)
	}

	hits := DetectPIIHits(ctx.HTTP, ctx.Payload)
	identifierSignal := hasStableIdentifierHit(hits)
	out := make([]Match, 0, 2)

	for _, pattern := range r.db.I6StorageSignals.Patterns {
		if !methodAllowedByStoragePattern(ctx.HTTP.Method, pattern.Methods) {
			continue
		}
		if uploadBytes < pattern.MinUploadBytes {
			continue
		}
		matchedKeyword := firstMatchedStorageKeyword(host, path, ctx.HTTP.RawLine, pattern.Keywords)
		if matchedKeyword == "" {
			continue
		}

		corroboration := storageSignalCorroboration(ctx, category, uploadBytes)
		if len(corroboration) == 0 {
			continue
		}

		patternRiskSignal := strings.TrimSpace(pattern.RiskSignal)
		if patternRiskSignal == "" {
			patternRiskSignal = "stored_data_signal"
		}
		riskSignals := []string{patternRiskSignal, "storage_endpoint"}
		if isAccumulatedUpload(uploadBytes) {
			riskSignals = append(riskSignals, "accumulated_upload")
		}
		if ctx.StableIdentifierRepeatCount >= 2 {
			riskSignals = append(riskSignals, "stable_identifier_signal")
		}
		if ctx.StorageEndpointRepeatCount >= 2 {
			riskSignals = append(riskSignals, "repeated_storage_endpoint")
		}

		out = append(out, Match{
			RuleID:   "I6_STORED_DATA_SIGNAL_OBSERVED",
			Type:     "I6_STORED_DATA_SIGNAL_OBSERVED",
			Category: "I6",
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"Stored-data communication candidate observed | signal=%s | method=%s | keyword=%s | upload_bytes=%d | corroboration=%s | risk=%s",
				pattern.Signal,
				ctx.HTTP.Method,
				matchedKeyword,
				uploadBytes,
				strings.Join(corroboration, ","),
				strings.Join(riskSignals, ","),
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s path=%s method=%s upload_bytes=%d storage_signal=%s keyword=%s endpoint_repeat_count=%d stable_identifier_observed=%t stable_identifier_repeat_count=%d corroboration=%s signal_confidence=candidate indirect_at_rest=true direct_storage_observed=false risk_signals=%s",
				category,
				host,
				path,
				ctx.HTTP.Method,
				uploadBytes,
				pattern.Signal,
				matchedKeyword,
				ctx.StorageEndpointRepeatCount,
				identifierSignal,
				ctx.StableIdentifierRepeatCount,
				strings.Join(corroboration, ","),
				strings.Join(riskSignals, ","),
			),
			OWASPTags:      uniqueTags("I6"),
			Confidence:     "medium",
			ObservedFact:   "Upload traffic matched a storage-related endpoint pattern with corroborating network signals.",
			Inference:      "This may indicate stored-data synchronization or backup-related communication.",
			Limitation:     "Passive monitoring does not prove that personal data is stored at rest or reveal what the remote service does with the uploaded data.",
			Recommendation: "Confirm whether backup or history synchronization is expected for the device and review where the data is sent.",
		})
	}

	return dedupeMatches(out)
}

func I6StorageCandidateEndpointKey(ctx *Context, patterns []knowledge.I6StorageSignalPattern) string {
	if ctx == nil || ctx.HTTP == nil || !isHTTPUploadMethod(ctx.HTTP.Method) {
		return ""
	}
	host, path := observedEndpoint(ctx)
	if host == "" && path == "" {
		return ""
	}
	uploadBytes := ctx.UploadBytes
	if uploadBytes <= 0 {
		uploadBytes = len(ctx.HTTP.Body)
	}

	for _, pattern := range patterns {
		if !methodAllowedByStoragePattern(ctx.HTTP.Method, pattern.Methods) {
			continue
		}
		if uploadBytes < pattern.MinUploadBytes {
			continue
		}
		matchedKeyword := firstMatchedStorageKeyword(host, path, ctx.HTTP.RawLine, pattern.Keywords)
		if matchedKeyword == "" {
			continue
		}
		return strings.ToLower(strings.TrimSpace(ctx.HTTP.Method)) + "|" +
			strings.ToLower(strings.TrimSpace(host)) + "|" +
			normalizeStorageEndpointPath(path) + "|" +
			matchedKeyword
	}
	return ""
}

func (r *I6PrivacyRule) applyPIIUseSignalAll(ctx *Context, category, commType string, hits []PIIHit) []Match {
	if r.db == nil || ctx == nil || ctx.HTTP == nil || len(hits) == 0 {
		return nil
	}
	if category == "" || category == "unknown" || !r.db.IsKnownCategory(category) {
		return nil
	}

	unexpectedPIITypes := unexpectedPIITypesForCategory(r.db, category, hits)
	if len(unexpectedPIITypes) == 0 {
		return nil
	}

	host, path := observedEndpoint(ctx)
	destinationSignals, destinationDisposition := r.piiDestinationSignals(ctx, category, commType, host)
	if len(destinationSignals) == 0 {
		return nil
	}

	corroboration := piiUseCorroboration(ctx, commType)
	if len(corroboration) == 0 {
		return nil
	}

	riskSignals := []string{"potential_pii_misuse", "unexpected_pii_type"}
	riskSignals = append(riskSignals, destinationSignals...)
	if ctx.StableIdentifierRepeatCount >= 2 {
		riskSignals = append(riskSignals, "repeated_identifier_disclosure")
	}
	if ctx.PIIDistinctDestinationCount >= 2 {
		riskSignals = append(riskSignals, "broad_pii_destination")
	}
	riskSignals = uniqueStrings(riskSignals)

	return []Match{
		{
			RuleID:   "I6_PII_TO_UNEXPECTED_DESTINATION",
			Type:     "I6_PII_TO_UNEXPECTED_DESTINATION",
			Category: "I6",
			Severity: SeverityWarning,
			Message: fmt.Sprintf(
				"Unexpected privacy destination signal observed | category=%s | pii_types=%s | destination=%s | disposition=%s | corroboration=%s | risk=%s",
				category,
				strings.Join(unexpectedPIITypes, ","),
				host,
				destinationDisposition,
				strings.Join(corroboration, ","),
				strings.Join(riskSignals, ","),
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s path=%s comm_type=%s pii_types=%s destination_disposition=%s pii_destination_repeat_count=%d pii_distinct_destination_count=%d stable_identifier_repeat_count=%d corroboration=%s consent_observed=false consent_inferred=false risk_signals=%s",
				category,
				host,
				path,
				emptyAsUnknown(commType),
				strings.Join(unexpectedPIITypes, ","),
				destinationDisposition,
				ctx.PIIDestinationRepeatCount,
				ctx.PIIDistinctDestinationCount,
				ctx.StableIdentifierRepeatCount,
				strings.Join(corroboration, ","),
				strings.Join(riskSignals, ","),
			),
			OWASPTags:      uniqueTags("I6", "I7"),
			Confidence:     "medium",
			ObservedFact:   "Privacy-sensitive value types were observed being sent toward a destination that appears unexpected for the device category.",
			Inference:      "This may indicate a privacy risk signal involving unexpected destination use or repeated identifier disclosure.",
			Limitation:     "Passive monitoring cannot determine user consent, policy compliance, or whether the destination is contractually expected but not present in local knowledge.",
			Recommendation: "Verify that this destination is expected for the device and review whether privacy-sensitive fields can be reduced or encrypted.",
		},
	}
}

func (r *I6PrivacyRule) applyCategoryMismatch(ctx *Context) *Match {
	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)

	if localCategory == "" || flowCategory == "" {
		return nil
	}
	if localCategory == "GenericIoT" || flowCategory == "GenericIoT" {
		return nil
	}
	if localCategory == flowCategory {
		return nil
	}
	if !r.db.IsKnownCategory(localCategory) || !r.db.IsKnownCategory(flowCategory) {
		return nil
	}

	host, path := observedEndpoint(ctx)
	commType := detectI6CommunicationType(ctx)
	if commType == "" {
		commType = "unknown"
	}
	isExternal := IsPublicIP(ctx.DstIP)
	if ctx.TLS && !shouldEmitTLSCategoryMismatch(ctx, isExternal) {
		return nil
	}
	riskSignals := []string{"category_mismatch"}
	if ctx.TLS {
		riskSignals = append(riskSignals, "category_mismatch_over_tls")
	}
	riskScoreHint := 15
	if isExternal {
		riskSignals = append(riskSignals, "external_comm")
		riskScoreHint = 25
	}

	localConfidence := ""
	if inference, ok := r.db.GetCategoryInference(localCategory); ok {
		localConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
	}

	flowConfidence := ""
	if inference, ok := r.db.GetCategoryInference(flowCategory); ok {
		flowConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
	}

	return &Match{
		RuleID:   "I6_DEVICE_FLOW_CATEGORY_MISMATCH",
		Type:     "I6_DEVICE_FLOW_CATEGORY_MISMATCH",
		Category: "I6",
		Severity: SeverityWarning,
		Message: fmt.Sprintf(
			mismatchMessageBase(ctx),
			localCategory,
			flowCategory,
			commType,
			strings.Join(riskSignals, ","),
		),
		Evidence: fmt.Sprintf(
			"endpoint=%s local_category=%s flow_category=%s local_confidence=%s flow_confidence=%s comm_type=%s path=%s risk_signals=%s risk_score_hint=%d",
			host,
			localCategory,
			flowCategory,
			localConfidence,
			flowConfidence,
			commType,
			path,
			strings.Join(riskSignals, ","),
			riskScoreHint,
		),
		OWASPTags:      uniqueTags("I6"),
		Confidence:     "medium",
		ObservedFact:   "Observed flow characteristics fit a different device category than the locally learned category.",
		Inference:      "This may indicate ecosystem mismatch, unexpected third-party behavior, or privacy-relevant communication outside the device's normal role.",
		Limitation:     "Passive monitoring cannot confirm a compromise or determine whether the communication is documented but missing from local knowledge.",
		Recommendation: "Verify the device role, expected ecosystem integrations, and whether the destination or SNI is legitimate.",
	}
}

func shouldEmitTLSCategoryMismatch(ctx *Context, isExternal bool) bool {
	if ctx == nil || !ctx.TLS {
		return true
	}
	if !isExternal {
		return false
	}
	if strings.TrimSpace(ctx.LocalInferenceSource) != "known" {
		return false
	}
	if strings.TrimSpace(ctx.FlowInferenceSource) != "known" {
		return false
	}
	if ctx.TLSInfo == nil || strings.TrimSpace(ctx.TLSInfo.SNI) == "" {
		return false
	}
	return true
}

func (r *I6PrivacyRule) applyBehaviorBaselineAll(ctx *Context, category, commType string) []Match {
	baseline, ok := r.db.GetBehaviorBaseline(category)
	if !ok {
		return nil
	}

	host, path := observedEndpoint(ctx)
	isExternal := IsPublicIP(ctx.DstIP)
	suspicious := suspiciousPatternSummary(baseline.SuspiciousPatterns)
	inference, hasInference := r.db.GetCategoryInference(category)
	var representativeDomains []string
	var ecosystemDomains []string
	categoryConfidence := ""
	categoryConfidenceLevel := ""
	if hasInference {
		representativeDomains = inference.RepresentativeDomains
		ecosystemDomains = inference.EcosystemDomains
		categoryConfidence = formatConfidence(inference.Confidence, inference.ConfidenceLevel)
		categoryConfidenceLevel = strings.ToLower(strings.TrimSpace(inference.ConfidenceLevel))
	}
	riskSignals := collectRiskSignals(baseline, ctx, commType, host, path, isExternal, representativeDomains, ecosystemDomains, categoryConfidenceLevel)
	riskSummary := strings.Join(riskSignals, ",")
	baselineSeverity, riskScoreHint := classifyBaselineRisk(riskSignals, isExternal)
	out := make([]Match, 0, 4)

	if isExternal && !ctx.TLS && baseline.PlaintextTolerance == "low" {
		out = append(out, Match{
			RuleID:   "I6_HTTP_BASELINE_PLAINTEXT",
			Type:     "I6_HTTP_BASELINE_PLAINTEXT",
			Category: "I6",
			Severity: baselineSeverity,
			Message: formatBaselineMessage(
				"Category baseline expects encrypted external communication",
				suspicious,
				riskSummary,
				categoryConfidence,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_ip=%s dst_port=%d suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
				category, host, ctx.DstIP, ctx.DstPort, suspicious, riskSummary, riskScoreHint, categoryConfidence,
			),
			OWASPTags:      uniqueTags("I6", "I7"),
			Confidence:     "medium",
			ObservedFact:   "External plaintext HTTP communication was observed for a category whose baseline prefers encrypted communication.",
			Inference:      "This may indicate privacy-sensitive plaintext exposure or an unexpected transport downgrade.",
			Limitation:     "Passive monitoring cannot determine whether the remote service also supports HTTPS or whether the plaintext path is required for setup.",
			Recommendation: "Enable HTTPS if supported and review why this category is using plaintext external communication.",
		})
	}

	if ctx.HTTP != nil {
		if indicators, hasAdmin := DetectHTTPAdminIndicators(ctx.HTTP); hasAdmin && isExternal && !baseline.LocalAdminExpected {
			out = append(out, Match{
				RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
				Type:     "I6_HTTP_BASELINE_UNEXPECTED_ADMIN",
				Category: "I6",
				Severity: baselineSeverity,
				Message: formatBaselineMessage(
					"Category baseline does not expect external admin-style HTTP access",
					suspicious,
					riskSummary,
					categoryConfidence,
				),
				Evidence: fmt.Sprintf(
					"category=%s host=%s path=%s indicators=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
					category, host, path, strings.Join(indicators, ","), suspicious, riskSummary, riskScoreHint, categoryConfidence,
				),
				OWASPTags:      uniqueTags("I6", "I3", "I7"),
				Confidence:     "medium",
				ObservedFact:   "External HTTP admin-style indicators were observed for a category that does not normally expose them.",
				Inference:      "This may indicate unexpected management communication with privacy or ecosystem risk.",
				Limitation:     "Passive monitoring cannot confirm the exact administrative capability or whether the endpoint is intentionally exposed.",
				Recommendation: "Confirm whether the management endpoint is expected and restrict it to trusted networks.",
			})
		}
	}

	if commType != "" && isExternal && !matchesExpectedProtocol(baseline.ExpectedProtocols, ctx) {
		out = append(out, Match{
			RuleID:   "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Type:     "I6_HTTP_BASELINE_PROTOCOL_MISMATCH",
			Category: "I6",
			Severity: baselineSeverity,
			Message: formatBaselineMessage(
				"Observed protocol usage does not fit the category baseline",
				suspicious,
				riskSummary,
				categoryConfidence,
			),
			Evidence: fmt.Sprintf(
				"category=%s host=%s dst_port=%d expected_protocols=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
				category, host, ctx.DstPort, strings.Join(baseline.ExpectedProtocols, ","), suspicious, riskSummary, riskScoreHint, categoryConfidence,
			),
			OWASPTags:      uniqueTags("I6"),
			Confidence:     "medium",
			ObservedFact:   "Observed external protocol usage did not match the expected baseline for the device category.",
			Inference:      "This may indicate unexpected ecosystem behavior or a privacy-relevant communication path outside the normal role.",
			Limitation:     "Passive monitoring cannot determine whether the baseline is incomplete or whether the device recently changed behavior after an update.",
			Recommendation: "Verify whether the protocol is expected for the device and update local baselines if it is legitimate.",
		})
	}

	if ctx.TLS {
		if hasInference && host != "" && isExternal && !hostMatchesRepresentativeDomains(host, representativeDomains) {
			out = append(out, Match{
				RuleID:   "I6_TLS_BASELINE_UNEXPECTED_DOMAIN",
				Type:     "I6_TLS_BASELINE_UNEXPECTED_DOMAIN",
				Category: "I6",
				Severity: baselineSeverity,
				Message: formatBaselineMessage(
					"Observed TLS SNI does not fit the learned category baseline",
					suspicious,
					riskSummary,
					categoryConfidence,
				),
				Evidence: fmt.Sprintf(
					"category=%s local_category=%s flow_category=%s sni=%s representative_domains=%s ecosystem_domains=%s domain_disposition=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
					category, strings.TrimSpace(ctx.LocalDeviceCategory), strings.TrimSpace(ctx.FlowDeviceCategory), host, strings.Join(inference.RepresentativeDomains, ","), strings.Join(inference.EcosystemDomains, ","), domainDisposition(riskSignals), suspicious, riskSummary, riskScoreHint, categoryConfidence,
				),
				OWASPTags:      uniqueTags("I6"),
				Confidence:     "medium",
				ObservedFact:   "Observed TLS SNI did not fit the learned category baseline.",
				Inference:      "This may indicate an unexpected ecosystem destination or privacy-related communication outside the normal category profile.",
				Limitation:     "Passive monitoring cannot inspect encrypted payload contents or determine whether the destination is a newly added legitimate service.",
				Recommendation: "Verify that the cloud endpoint is expected for the device and update local baselines if it is legitimate.",
			})
		}
	} else if commType == "analytics" || commType == "tracking" || commType == "cloud_api" {
		if hasInference && host != "" && isExternal && !hostMatchesRepresentativeDomains(host, representativeDomains) {
			out = append(out, Match{
				RuleID:   "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Type:     "I6_HTTP_BASELINE_UNEXPECTED_DOMAIN",
				Category: "I6",
				Severity: baselineSeverity,
				Message: formatBaselineMessage(
					"Observed external domain does not fit the category baseline",
					suspicious,
					riskSummary,
					categoryConfidence,
				),
				Evidence: fmt.Sprintf(
					"category=%s host=%s representative_domains=%s ecosystem_domains=%s domain_disposition=%s suspicious_patterns=%s risk_signals=%s risk_score_hint=%d category_confidence=%s",
					category, host, strings.Join(inference.RepresentativeDomains, ","), strings.Join(inference.EcosystemDomains, ","), domainDisposition(riskSignals), suspicious, riskSummary, riskScoreHint, categoryConfidence,
				),
				OWASPTags:      uniqueTags("I6"),
				Confidence:     "medium",
				ObservedFact:   "Observed external domain did not fit the learned category baseline.",
				Inference:      "This may indicate an unexpected privacy destination or ecosystem communication path.",
				Limitation:     "Passive monitoring cannot confirm whether the domain is a newly added vendor endpoint or a third-party service authorized by the user.",
				Recommendation: "Verify that this cloud endpoint is expected for the device and update local baselines if it is legitimate.",
			})
		}
	}

	return dedupeMatches(out)
}

func mismatchMessageBase(ctx *Context) string {
	if ctx != nil && ctx.TLS {
		return "Observed TLS flow category does not match the learned device category | local=%s | flow=%s | comm_type=%s | risk=%s"
	}
	return "Observed flow category does not match the learned device category | local=%s | flow=%s | comm_type=%s | risk=%s"
}

func DetectCommunicationType(http *HTTPInfo) string {
	if http == nil {
		return ""
	}

	path := strings.ToLower(http.Path)
	host := strings.ToLower(http.Headers["host"])
	combined := host + " " + path

	switch {
	case containsAny(combined, "analytics", "metrics", "measure", "stat", "stats"):
		return "analytics"
	case containsAny(combined, "track", "tracking", "collect", "telemetry", "report"):
		return "tracking"
	case containsAny(combined, "/api/", "/v1/", "/v2/", "cloud"):
		return "cloud_api"
	default:
		return ""
	}
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func hostMatchesRepresentativeDomains(host string, domains []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func matchesExpectedProtocol(expected []string, ctx *Context) bool {
	observed := observedProtocols(ctx)
	for _, candidate := range observed {
		for _, allowed := range expected {
			if candidate == strings.ToLower(strings.TrimSpace(allowed)) {
				return true
			}
		}
	}
	return false
}

func observedProtocols(ctx *Context) []string {
	values := make([]string, 0, 3)
	if ctx.TLS {
		values = append(values, "https", "tls")
	} else if ctx.HTTP != nil {
		values = append(values, "http")
	}

	switch ctx.DstPort {
	case 554:
		values = append(values, "rtsp")
	case 8883:
		values = append(values, "mqtt", "tls")
	case 1883:
		values = append(values, "mqtt")
	case 5683:
		values = append(values, "coap")
	}

	return values
}

func suspiciousPatternSummary(patterns []string) string {
	if len(patterns) == 0 {
		return ""
	}

	const limit = 2
	if len(patterns) > limit {
		patterns = patterns[:limit]
	}
	return strings.Join(patterns, " | ")
}

func formatBaselineMessage(base, suspicious, riskSignals, categoryConfidence string) string {
	msg := base
	if suspicious != "" {
		msg += " | suspicious: " + suspicious
	}
	if riskSignals != "" {
		msg += " | risk: " + riskSignals
	}
	if categoryConfidence != "" {
		msg += " | category confidence: " + categoryConfidence
	}
	return msg
}

func collectRiskSignals(baseline knowledge.CategoryBehaviorBaseline, ctx *Context, commType, host, path string, isExternal bool, representativeDomains []string, ecosystemDomains []string, categoryConfidenceLevel string) []string {
	signals := make([]string, 0, 4)

	if isExternal && !ctx.TLS && baseline.PlaintextTolerance == "low" {
		signals = append(signals, "plaintext_external")
	}

	if ctx.HTTP != nil {
		if indicators, hasAdmin := DetectHTTPAdminIndicators(ctx.HTTP); hasAdmin && isExternal && !baseline.LocalAdminExpected {
			_ = indicators
			signals = append(signals, "unexpected_external_admin")
		}
	}

	if commType != "" && isExternal && !matchesExpectedProtocol(baseline.ExpectedProtocols, ctx) {
		signals = append(signals, "protocol_mismatch")
	}

	if ctx.TLS && host != "" && isExternal {
		if !hostMatchesRepresentativeDomains(host, representativeDomains) {
			signals = append(signals, classifyUnmatchedDomainSignals(ctx, host, isExternal, representativeDomains, ecosystemDomains, categoryConfidenceLevel)...)
		}
	}

	if !ctx.TLS && (commType == "analytics" || commType == "tracking" || commType == "cloud_api") && host != "" && isExternal {
		if !hostMatchesRepresentativeDomains(host, representativeDomains) {
			signals = append(signals, classifyUnmatchedDomainSignals(ctx, host, isExternal, representativeDomains, ecosystemDomains, categoryConfidenceLevel)...)
		}
	}

	if ctx.TLS && isExternal && host == "" {
		signals = append(signals, "external_tls_unknown")
	}

	if path != "" && (strings.Contains(path, "/admin") || strings.Contains(path, "/login") || strings.Contains(path, "/setup")) {
		signals = append(signals, "admin_like_path")
	}

	if categoryConfidenceLevel == "low" {
		signals = append(signals, "category_confidence_low")
	}

	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)
	if localCategory != "" &&
		flowCategory != "" &&
		localCategory != "GenericIoT" &&
		flowCategory != "GenericIoT" &&
		localCategory != flowCategory {
		signals = append(signals, "category_mismatch")
		if ctx.TLS {
			signals = append(signals, "category_mismatch_over_tls")
		}
	}

	return uniqueStrings(signals)
}

func classifyUnmatchedDomainSignals(ctx *Context, host string, isExternal bool, representativeDomains []string, ecosystemDomains []string, categoryConfidenceLevel string) []string {
	signals := []string{"unexpected_domain"}
	if strings.TrimSpace(host) == "" {
		return signals
	}

	ecosystemMatch := hostMatchesRepresentativeDomains(host, ecosystemDomains)
	if ctx != nil && ctx.TLS && isExternal && !ecosystemMatch {
		signals = append(signals, "tls_ecosystem_mismatch")
	}

	if isSuspiciousUnmatched(ctx, isExternal, ecosystemMatch, categoryConfidenceLevel) {
		signals = append(signals, "suspicious_unmatched")
		return signals
	}

	signals = append(signals, "baseline_novelty")
	return signals
}

func isSuspiciousUnmatched(ctx *Context, isExternal bool, ecosystemMatch bool, categoryConfidenceLevel string) bool {
	if !isExternal {
		return false
	}
	if !ecosystemMatch {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(categoryConfidenceLevel), "low") {
		return true
	}
	if ctx == nil || !ctx.TLS {
		return false
	}
	if ctx.TLSInfo == nil || strings.TrimSpace(ctx.TLSInfo.SNI) == "" {
		return false
	}
	if strings.TrimSpace(ctx.LocalInferenceSource) != "known" || strings.TrimSpace(ctx.FlowInferenceSource) != "known" {
		return false
	}

	localCategory := strings.TrimSpace(ctx.LocalDeviceCategory)
	flowCategory := strings.TrimSpace(ctx.FlowDeviceCategory)
	if localCategory == "" || flowCategory == "" {
		return false
	}
	if localCategory == "GenericIoT" || flowCategory == "GenericIoT" {
		return false
	}
	return localCategory != flowCategory
}

func domainDisposition(signals []string) string {
	for _, signal := range signals {
		switch signal {
		case "suspicious_unmatched":
			return "suspicious_unmatched"
		case "baseline_novelty":
			return "baseline_novelty"
		}
	}
	return ""
}

func detectI6CommunicationType(ctx *Context) string {
	if ctx == nil {
		return ""
	}
	if ctx.HTTP != nil {
		return DetectCommunicationType(ctx.HTTP)
	}
	if ctx.TLSInfo != nil && strings.TrimSpace(ctx.TLSInfo.SNI) != "" {
		return "tls_sni"
	}
	return ""
}

func observedEndpoint(ctx *Context) (host string, path string) {
	if ctx == nil {
		return "", ""
	}
	if ctx.HTTP != nil {
		return strings.ToLower(strings.TrimSpace(ctx.HTTP.Headers["host"])), strings.ToLower(strings.TrimSpace(ctx.HTTP.Path))
	}
	if ctx.TLSInfo != nil {
		return strings.ToLower(strings.TrimSpace(ctx.TLSInfo.SNI)), ""
	}
	return "", ""
}

func hostMatchesExpectedDomains(host string, representativeDomains []string, ecosystemDomains []string) bool {
	if hostMatchesRepresentativeDomains(host, representativeDomains) {
		return true
	}
	if hostMatchesRepresentativeDomains(host, ecosystemDomains) {
		return true
	}
	return false
}

func unexpectedPIITypesForCategory(db *knowledge.DB, category string, hits []PIIHit) []string {
	values := make([]string, 0, len(hits))
	for _, hit := range hits {
		if hit.Type == "" {
			continue
		}
		if !db.IsAllowedPIIType(category, hit.Type) {
			values = append(values, hit.Type)
		}
	}
	return uniqueStrings(values)
}

func (r *I6PrivacyRule) piiDestinationSignals(ctx *Context, category, commType, host string) ([]string, string) {
	signals := make([]string, 0, 3)
	disposition := ""

	if commType == "analytics" || commType == "tracking" {
		signals = append(signals, "tracking_or_analytics_destination")
		disposition = commType
	}
	if looksLikeThirdPartyPIIDestination(host) {
		signals = append(signals, "third_party_pii_destination")
		if disposition == "" {
			disposition = "third_party_like"
		}
	}

	isExternal := ctx != nil && IsPublicIP(ctx.DstIP)
	if host != "" && isExternal {
		if inference, ok := r.db.GetCategoryInference(category); ok {
			if !hostMatchesExpectedDomains(host, inference.RepresentativeDomains, inference.EcosystemDomains) {
				signals = append(signals, "unexpected_pii_destination")
				if disposition == "" {
					disposition = "baseline_unexpected"
				}
			}
		}
	}

	if disposition == "" && len(signals) > 0 {
		disposition = "unexpected"
	}
	return uniqueStrings(signals), disposition
}

func looksLikeThirdPartyPIIDestination(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	return containsAny(host,
		"analytics",
		"tracking",
		"track.",
		"metrics",
		"telemetry",
		"collect",
		"ads.",
		"adtech",
	)
}

func piiUseCorroboration(ctx *Context, commType string) []string {
	corroboration := make([]string, 0, 4)
	if ctx != nil && ctx.StableIdentifierRepeatCount >= 2 {
		corroboration = append(corroboration, "repeated_identifier")
	}
	if ctx != nil && ctx.PIIDestinationRepeatCount >= 2 {
		corroboration = append(corroboration, "repeated_pii_destination")
	}
	if ctx != nil && ctx.PIIDistinctDestinationCount >= 2 {
		corroboration = append(corroboration, "multiple_pii_destinations")
	}
	if (commType == "analytics" || commType == "tracking") && len(corroboration) > 0 {
		corroboration = append(corroboration, "tracking_or_analytics_destination")
	}
	return uniqueStrings(corroboration)
}

func emptyAsUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func isHTTPUploadMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH":
		return true
	default:
		return false
	}
}

func methodAllowedByStoragePattern(method string, allowed []string) bool {
	if len(allowed) == 0 {
		return isHTTPUploadMethod(method)
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, candidate := range allowed {
		if method == strings.ToUpper(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func firstMatchedStorageKeyword(host, path, rawLine string, keywords []string) string {
	combined := strings.ToLower(strings.TrimSpace(host + " " + path + " " + rawLine))
	for _, keyword := range keywords {
		normalized := strings.ToLower(strings.TrimSpace(keyword))
		if normalized == "" {
			continue
		}
		if strings.Contains(combined, normalized) {
			return normalized
		}
	}
	return ""
}

func storageSignalCorroboration(ctx *Context, category string, uploadBytes int) []string {
	corroboration := make([]string, 0, 4)
	privacySensitiveCategory := isPrivacySensitiveStorageCategory(category)
	if isAccumulatedUpload(uploadBytes) {
		corroboration = append(corroboration, "accumulated_upload")
	}
	if ctx != nil && ctx.StorageEndpointRepeatCount >= 2 {
		corroboration = append(corroboration, "repeated_storage_endpoint")
	}
	if ctx != nil && ctx.StableIdentifierRepeatCount >= 2 {
		corroboration = append(corroboration, "repeated_stable_identifier")
	}
	if privacySensitiveCategory && len(corroboration) > 0 {
		corroboration = append(corroboration, "privacy_sensitive_category")
	}
	return uniqueStrings(corroboration)
}

func isPrivacySensitiveStorageCategory(category string) bool {
	switch strings.TrimSpace(category) {
	case "Camera", "VoiceAssistant", "Wearable":
		return true
	default:
		return false
	}
}

func isAccumulatedUpload(uploadBytes int) bool {
	return uploadBytes >= 4096
}

func normalizeStorageEndpointPath(path string) string {
	path = strings.ToLower(strings.TrimSpace(path))
	if path == "" {
		return ""
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		if looksVariableStoragePathSegment(part) {
			parts[i] = "*"
		}
	}
	return strings.Join(parts, "/")
}

func looksVariableStoragePathSegment(segment string) bool {
	if len(segment) >= 8 && strings.ContainsAny(segment, "0123456789") {
		return true
	}
	if uuidLikeRegex.MatchString(segment) {
		return true
	}
	return false
}

func hasStableIdentifierHit(hits []PIIHit) bool {
	for _, hit := range hits {
		switch hit.Type {
		case "device_identifier", "user_identifier", "account_info":
			return true
		}
	}
	return false
}

func classifyBaselineRisk(signals []string, isExternal bool) (Severity, int) {
	score := 10
	has := make(map[string]bool, len(signals))
	for _, signal := range signals {
		has[signal] = true
		switch signal {
		case "suspicious_unmatched":
			score += 5
		case "baseline_novelty":
			score += 5
		case "plaintext_external":
			score += 20
		case "unexpected_external_admin":
			score += 20
		case "unexpected_domain":
			score += 15
		case "category_mismatch":
			score += 15
		case "protocol_mismatch":
			score += 10
		case "admin_like_path":
			score += 10
		case "external_comm":
			score += 5
		case "category_confidence_low":
			score += 5
		}
	}
	if score > 90 {
		score = 90
	}

	critical := false
	if has["unexpected_external_admin"] {
		critical = true
	}
	if has["plaintext_external"] && has["unexpected_domain"] {
		critical = true
	}
	if has["unexpected_domain"] && has["category_mismatch"] && isExternal {
		critical = true
	}
	if score >= 50 {
		critical = true
	}

	if critical {
		return SeverityCritical, score
	}
	return SeverityWarning, score
}

func formatConfidence(score float64, level string) string {
	if level == "" {
		level = "unknown"
	}
	return fmt.Sprintf("%s(%.2f)", level, score)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func dedupeMatches(matches []Match) []Match {
	if len(matches) == 0 {
		return matches
	}

	seen := make(map[string]struct{}, len(matches))
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		key := m.RuleID + "|" + m.Type + "|" + m.Evidence
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, m)
	}
	return out
}
