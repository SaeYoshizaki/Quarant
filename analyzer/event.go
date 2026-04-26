package analyzer

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  Severity  `json:"severity"`

	RuleID         string   `json:"rule_id,omitempty"`
	Category       string   `json:"category,omitempty"`
	FlowKey        string   `json:"flow_key,omitempty"`
	Evidence       string   `json:"evidence,omitempty"`
	OWASPTags      []string `json:"owasp_tags,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	ObservedFact   string   `json:"observed_fact,omitempty"`
	Inference      string   `json:"inference,omitempty"`
	Limitation     string   `json:"limitation,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Debug          bool     `json:"debug,omitempty"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	Message string `json:"message,omitempty"`
}
