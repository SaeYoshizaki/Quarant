package rules

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Match struct {
	RuleID   string
	Category string
	Severity Severity

	Type           string
	Message        string
	Evidence       string
	OWASPTags      []string
	Confidence     string
	ObservedFact   string
	Inference      string
	Limitation     string
	Recommendation string
	Debug          bool
}
