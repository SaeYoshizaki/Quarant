package rules

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// HTTPResponseInfo is the first response a server sent in a flow.
type HTTPResponseInfo struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
}

// HTTPExchange pairs the first request of a flow with the first response,
// in the flow's client -> server direction. It is only set on packets after
// the server answered, so rules that need the outcome of a request (was it
// accepted?) can use it without guessing.
type HTTPExchange struct {
	Request     *HTTPInfo
	Response    *HTTPResponseInfo
	ClientIP    string
	ServerIP    string
	ServerPort  uint16
	ServerLocal bool
}

// ParseHTTPResponse parses a status line and headers. The body is whatever
// follows the header block in the buffer (possibly truncated).
func ParseHTTPResponse(payload []byte) (*HTTPResponseInfo, bool) {
	if !bytes.HasPrefix(payload, []byte("HTTP/1.")) {
		return nil, false
	}
	end := bytes.Index(payload, []byte("\r\n\r\n"))
	sep := 4
	if end < 0 {
		end, sep = bytes.Index(payload, []byte("\n\n")), 2
	}
	if end < 0 {
		return nil, false
	}
	lines := strings.Split(string(payload[:end]), "\n")
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil || code < 100 || code > 599 {
		return nil, false
	}
	h := map[string]string{}
	for _, ln := range lines[1:] {
		ln = strings.TrimRight(ln, "\r")
		col := strings.IndexByte(ln, ':')
		if col <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:col]))
		if _, exists := h[k]; !exists {
			h[k] = strings.TrimSpace(ln[col+1:])
		}
	}
	return &HTTPResponseInfo{StatusCode: code, Headers: h, Body: payload[end+sep:]}, true
}

// LooksLikeHTTPRequest reports whether a client's first payload starts with
// an HTTP request line. It is used to recognise HTTP on ports outside
// IsHTTPPort (UPnP devices serve on 49152-49154, 5000, 2869, ...).
func LooksLikeHTTPRequest(data []byte) bool {
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if bytes.HasPrefix(data, []byte(m)) {
			line := data
			if end := bytes.IndexByte(data, '\n'); end >= 0 {
				line = data[:end]
			}
			return bytes.Contains(line, []byte(" HTTP/1."))
		}
	}
	return false
}

func soapAction(req *HTTPInfo) string {
	v := strings.Trim(strings.TrimSpace(req.Headers["soapaction"]), `"`)
	if i := strings.LastIndexByte(v, '#'); i >= 0 {
		return v[i+1:]
	}
	return ""
}

var upnpArgRe = regexp.MustCompile(`<(NewExternalPort|NewProtocol|NewInternalPort|NewInternalClient|NewLeaseDuration)>\s*([^<\s]{0,64})\s*</`)

// I9UPnPPortMappingRule reports a device asking the gateway, over UPnP IGD,
// to forward an external port to it. The request and the gateway's answer
// are both visible on the LAN.
type I9UPnPPortMappingRule struct{}

func (r *I9UPnPPortMappingRule) ID() string         { return "I9_UPNP_PORT_MAPPING_REQUESTED" }
func (r *I9UPnPPortMappingRule) Category() string   { return "I9" }
func (r *I9UPnPPortMappingRule) Severity() Severity { return SeverityWarning }
func (r *I9UPnPPortMappingRule) Type() string       { return "I9_UPNP_PORT_MAPPING_REQUESTED" }

func (r *I9UPnPPortMappingRule) Apply(ctx *Context) (Match, bool) {
	ex := ctx.HTTPExchange
	if ex == nil || ex.Request == nil || ex.Response == nil || !ex.ServerLocal {
		return Match{}, false
	}
	action := soapAction(ex.Request)
	if action != "AddPortMapping" && action != "AddAnyPortMapping" {
		return Match{}, false
	}
	args := map[string]string{}
	for _, m := range upnpArgRe.FindAllStringSubmatch(string(ex.Request.Body), -1) {
		args[m[1]] = m[2]
	}
	accepted := ex.Response.StatusCode >= 200 && ex.Response.StatusCode < 300
	severity := SeverityWarning
	fact := "The device asked the gateway over UPnP to forward an external port to it, and the gateway accepted (HTTP 2xx)."
	if !accepted {
		severity = SeverityLow
		fact = "The device asked the gateway over UPnP to forward an external port to it; the gateway refused."
	}
	return Match{
		Severity: severity,
		Message:  "Device requested a UPnP port mapping on the gateway.",
		Evidence: fmt.Sprintf("action=%s external_port=%s protocol=%s internal_port=%s internal_client=%s lease=%s gateway=%s:%d status=%d accepted=%t",
			action, orUnknown(args["NewExternalPort"]), orUnknown(args["NewProtocol"]), orUnknown(args["NewInternalPort"]),
			orUnknown(args["NewInternalClient"]), orUnknown(args["NewLeaseDuration"]), ex.ServerIP, ex.ServerPort, ex.Response.StatusCode, accepted),
		OWASPTags:      uniqueTags("I2", "I9"),
		Confidence:     "high",
		ObservedFact:   fact,
		Inference:      "A service of the device may be reachable from the internet through the forwarded port, without the user configuring the router.",
		Limitation:     "Passive monitoring cannot tell whether the user enabled this feature, whether the mapping is still active, or whether the forwarded service requires authentication. Mappings made before or outside the capture are not seen.",
		Recommendation: "Check whether the device needs inbound access from the internet; disable UPnP on the gateway or the feature on the device if not.",
	}, true
}

// I3UnauthenticatedDeviceControlRule reports a request that invokes a
// function of a local device (a UPnP SOAP action, or a state-changing HTTP
// method) without any credential visible in the request, and which the
// device answered with success.
type I3UnauthenticatedDeviceControlRule struct{}

func (r *I3UnauthenticatedDeviceControlRule) ID() string {
	return "I3_UNAUTHENTICATED_DEVICE_CONTROL"
}
func (r *I3UnauthenticatedDeviceControlRule) Category() string   { return "I3" }
func (r *I3UnauthenticatedDeviceControlRule) Severity() Severity { return SeverityWarning }
func (r *I3UnauthenticatedDeviceControlRule) Type() string {
	return "I3_UNAUTHENTICATED_DEVICE_CONTROL"
}

var responseErrorMarkers = [][]byte{[]byte(`"error"`), []byte("Fault>"), []byte("UPnPError")}

func (r *I3UnauthenticatedDeviceControlRule) Apply(ctx *Context) (Match, bool) {
	ex := ctx.HTTPExchange
	if ex == nil || ex.Request == nil || ex.Response == nil || !ex.ServerLocal || ctx.TLS {
		return Match{}, false
	}
	req := ex.Request
	action := soapAction(req)
	switch {
	case action != "":
	case req.Method == "POST", req.Method == "PUT", req.Method == "PATCH", req.Method == "DELETE":
	default:
		return Match{}, false
	}
	if ex.Response.StatusCode < 200 || ex.Response.StatusCode >= 300 {
		return Match{}, false
	}
	for _, m := range responseErrorMarkers {
		if bytes.Contains(ex.Response.Body, m) {
			return Match{}, false
		}
	}
	if hasVisibleCredential(req) {
		return Match{}, false
	}
	target := "method=" + req.Method + " path=" + truncate(req.Path, 80)
	if action != "" {
		target += " soap_action=" + action
	}
	return Match{
		Message:        "A device function was invoked over the network without visible authentication and the device answered with success.",
		Evidence:       fmt.Sprintf("%s device=%s:%d status=%d credentials=none_visible", target, ex.ServerIP, ex.ServerPort, ex.Response.StatusCode),
		OWASPTags:      uniqueTags("I1", "I3"),
		Confidence:     "medium",
		ObservedFact:   "A request without Authorization header, cookie, token parameter or credential in its body invoked a device function, and the device returned HTTP 2xx without an error body.",
		Inference:      "The device may accept this function from any host on the network without authentication.",
		Limitation:     "Authentication may happen in a way that is not visible here (earlier pairing, an allow-list of hosts, a physical button, network-level controls). Passive monitoring cannot tell whether the function is security-relevant or whether it was actually carried out.",
		Recommendation: "Check whether the device offers a setting that requires authentication for local control, and restrict which hosts can reach it.",
	}, true
}

// hasVisibleCredential reports whether a request carries anything that may
// authenticate it: credential headers, cookies, token-like query values,
// token-like path segments (e.g. a Hue API key in /api/<key>/lights) or
// credential fields in the body.
func hasVisibleCredential(req *HTTPInfo) bool {
	if req.Headers["authorization"] != "" || req.Headers["cookie"] != "" {
		return true
	}
	if _, ok := DetectSensitiveHeader(req.Headers); ok {
		return true
	}
	if _, ok := DetectSensitiveQuery(req.Query); ok {
		return true
	}
	for _, seg := range strings.Split(req.Path, "/") {
		if looksLikeLongRandomToken(seg) {
			return true
		}
	}
	if _, _, ok := DetectSensitiveHTTPBody(req.ContentType, req.Body); ok {
		return true
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func init() {
	Register(&I9UPnPPortMappingRule{})
	Register(&I3UnauthenticatedDeviceControlRule{})
}
