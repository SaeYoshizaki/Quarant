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
	if r.db == nil || ctx == nil || ctx.HTTP == nil {
		return Match{}, false
	}

	commType := DetectCommunicationType(ctx.HTTP)
	if commType == "" {
		return Match{}, false
	}

	hits := DetectPIIHits(ctx.HTTP, ctx.Payload)
	if len(hits) == 0 {
		return Match{}, false
	}

	category := strings.TrimSpace(ctx.DeviceCategory)
	if category == "" {
		category = "unknown"
	}

	if category != "unknown" && r.db.IsKnownCategory(category) {
		for _, hit := range hits {
			if r.db.IsSuspiciousCombination(category, commType, hit.Type) {
				return Match{
					RuleID:   "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Type:     "I6_HTTP_PRIVACY_POLICY_VIOLATION",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Privacy-related information violates device category policy",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				}, true
			}
		}

		if !r.db.IsAllowedCommunicationType(category, commType) {
			hit := hits[0]
			return Match{
				RuleID:   "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Type:     "I6_HTTP_UNEXPECTED_COMMUNICATION",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in unexpected communication type",
				Evidence: fmt.Sprintf(
					"category=%s comm_type=%s pii_type=%s source=%s %s",
					category, commType, hit.Type, hit.Source, hit.Evidence,
				),
			}, true
		}

		for _, hit := range hits {
			if !r.db.IsAllowedPIIType(category, hit.Type) {
				return Match{
					RuleID:   "I6_HTTP_UNEXPECTED_PII",
					Type:     "I6_HTTP_UNEXPECTED_PII",
					Category: "I6",
					Severity: SeverityWarning,
					Message:  "Unexpected privacy-related information observed for device category",
					Evidence: fmt.Sprintf(
						"category=%s comm_type=%s pii_type=%s source=%s %s",
						category, commType, hit.Type, hit.Source, hit.Evidence,
					),
				}, true
			}
		}

		return Match{}, false
	}

	for _, hit := range hits {
		if commType == "analytics" || commType == "tracking" {
			return Match{
				RuleID:   "I6_HTTP_PRIVACY_EXPOSURE",
				Type:     "I6_HTTP_PRIVACY_EXPOSURE",
				Category: "I6",
				Severity: SeverityWarning,
				Message:  "Privacy-related information observed in suspicious HTTP communication",
				Evidence: fmt.Sprintf(
					"comm_type=%s pii_type=%s source=%s %s category=%s",
					commType, hit.Type, hit.Source, hit.Evidence, category,
				),
			}, true
		}
	}

	return Match{}, false
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