// analyzer/event.go
package analyzer

import "time"

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type      string    `json:"type"`
	Severity  Severity  `json:"severity"`

	RuleID   string `json:"rule_id,omitempty"`
	Category string `json:"category,omitempty"`
	FlowKey  string `json:"flow_key,omitempty"`
	Evidence string `json:"evidence,omitempty"`

	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort uint16 `json:"src_port,omitempty"`
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`

	Message string `json:"message,omitempty"`
}
