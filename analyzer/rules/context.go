package rules

type Context struct {
	NowUnix int64

	FlowKey string

	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16

	Payload []byte
	Debug   bool

	HTTP *HTTPInfo

	TLS bool
}
