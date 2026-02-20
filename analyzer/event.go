package analyzer

import "time"

type Severity string

const (
	SeverityInfo Severity = "INFO"
	SeverityWarning Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

type Event struct {
	Timestamp time.Time `json:"ts"`
	Type string `json:"type"`
	Severity Severity `json:"severity"`

	SrcIP string `json:"sec_ip"`
	SrcPort uint16 `json:"src_port"`

	DstIP string `json:"dst_ip"`
	DstPort uint16 `json:"dst_port"`

	Message string `json:"message"`
}