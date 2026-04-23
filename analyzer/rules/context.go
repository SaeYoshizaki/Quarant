package rules

import "strings"

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
	UploadBytes   int

	StorageEndpointRepeatCount  int
	StableIdentifierRepeatCount int
	PIIDestinationRepeatCount   int
	PIIDistinctDestinationCount int

	HTTP          *HTTPInfo
	MQTT          *MQTTInfo
	Telnet        *TelnetInfo
	TLS           bool
	TLSInfo       *TLSClientHelloInfo
	TLSServerInfo *TLSServerInfo

	DeviceCategory      string
	LocalDeviceCategory string
	FlowDeviceCategory  string
	CategoryCandidate   string
	VendorCandidate     string
	FamilyCandidate     string
	CategoryConfidence  string
	VendorConfidence    string
	FamilyConfidence    string
	CategoryReasons     []string
	VendorReasons       []string
	FamilyReasons       []string
	ObservedHosts       []string
	ObservedUserAgents  []string
	ObservedSNIValues   []string
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

func (ctx *Context) FamilyConfidenceAtLeast(level string) bool {
	if ctx == nil {
		return false
	}
	return identityConfidenceRank(ctx.FamilyConfidence) >= identityConfidenceRank(level)
}

func (ctx *Context) VendorConfidenceAtLeast(level string) bool {
	if ctx == nil {
		return false
	}
	return identityConfidenceRank(ctx.VendorConfidence) >= identityConfidenceRank(level)
}

func (ctx *Context) HasConcreteFamilyCandidate() bool {
	return ctx != nil && strings.TrimSpace(ctx.FamilyCandidate) != "" && identityConfidenceRank(ctx.FamilyConfidence) >= identityConfidenceRank("medium")
}

func (ctx *Context) FamilyIsUncertain() bool {
	return ctx == nil || strings.TrimSpace(ctx.FamilyCandidate) == "" || identityConfidenceRank(ctx.FamilyConfidence) < identityConfidenceRank("medium")
}

func (ctx *Context) HasMeaningfulVendorCandidate() bool {
	return ctx != nil && strings.TrimSpace(ctx.VendorCandidate) != "" && identityConfidenceRank(ctx.VendorConfidence) >= identityConfidenceRank("medium")
}

func (ctx *Context) VendorWithoutConcreteFamily() bool {
	return ctx.HasMeaningfulVendorCandidate() && !ctx.HasConcreteFamilyCandidate()
}

func (ctx *Context) IdentityIsWeak() bool {
	if ctx == nil {
		return true
	}
	return !ctx.HasConcreteFamilyCandidate() && !ctx.HasMeaningfulVendorCandidate()
}

func identityConfidenceRank(level string) int {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "strong":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
