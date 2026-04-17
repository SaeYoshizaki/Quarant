package rules

type InferenceView struct {
	Category   string
	DeviceType string
	Source     string
	Confidence string
	Reasons    []string
}

type Context struct {
	NowUnix int64
	FlowKey string

	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16

	Payload       []byte
	ServerPayload []byte
	Debug         bool

	HTTP    *HTTPInfo
	MQTT    *MQTTInfo
	Telnet  *TelnetInfo
	TLS     bool
	TLSInfo *TLSClientHelloInfo

	DeviceCategory      string
	LocalDeviceCategory string
	FlowDeviceCategory  string
	VendorCandidate     string
	FamilyCandidate     string
	UpdateVisibility    string
	LegacySignals       []string

	DeviceInferenceSource     string
	LocalInferenceSource      string
	FlowInferenceSource       string
	DeviceInferenceConfidence string
	LocalInferenceConfidence  string
	FlowInferenceConfidence   string
	DeviceInferenceReasons    []string
	LocalInferenceReasons     []string
	FlowInferenceReasons      []string

	ContextClassification InferenceView
	LocalClassification   InferenceView
	FlowClassification    InferenceView
}
