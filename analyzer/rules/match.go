package rules

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Match struct {
	RuleID   string
	Category string
	Severity Severity

	Type     string
	Message  string
	Evidence string
}
