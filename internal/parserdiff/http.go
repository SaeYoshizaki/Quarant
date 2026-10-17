package parserdiff

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"net/textproto"
	"sort"
	"strings"

	"quarant/analyzer/rules"
)

// HTTPRequest is the normalised view of an HTTP request head used for
// comparison. Header names are lower case; every value of a repeated header
// is kept so that duplicate-header ambiguity is visible.
type HTTPRequest struct {
	Method   string
	Path     string
	RawQuery string
	Proto    string
	Headers  map[string][]string
}

// securityHeaders are the request headers that Quarant's rules read
// (credentials, cookies, identity, body type). Mismatches on other headers do
// not change any finding and are not compared.
var securityHeaders = []string{"authorization", "cookie", "host", "user-agent", "content-type", "x-token", "x-auth-token", "x-api-key", "proxy-authorization"}

// ReferenceHTTPRequest parses the request head with Go's net/http server
// parser. ok is false when net/http rejects the bytes as a request.
func ReferenceHTTPRequest(data []byte) (HTTPRequest, error) {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return HTTPRequest{}, err
	}
	path, rawQuery := req.RequestURI, ""
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path, rawQuery = path[:i], path[i+1:]
	}
	h := map[string][]string{}
	for k, v := range req.Header {
		h[strings.ToLower(k)] = append([]string(nil), v...)
	}
	// net/http moves Host out of the header map.
	if req.Host != "" {
		h["host"] = []string{req.Host}
	}
	return HTTPRequest{Method: req.Method, Path: path, RawQuery: rawQuery, Proto: req.Proto, Headers: h}, nil
}

// QuarantHTTPRequest is the production path: the LooksLikeHTTP gate followed
// by rules.ParseHTTP, which keeps only the first value of each header.
func QuarantHTTPRequest(data []byte) (HTTPRequest, bool) {
	if !rules.LooksLikeHTTP(data) {
		return HTTPRequest{}, false
	}
	info, ok := rules.ParseHTTP(data)
	if !ok {
		return HTTPRequest{}, false
	}
	// ParseHTTP keeps the decoded query only; recover the raw form from the
	// request target the same way ParseHTTP splits it.
	rawQuery := ""
	if parts := strings.Split(info.RawLine, " "); len(parts) >= 2 {
		if i := strings.IndexByte(parts[1], '?'); i >= 0 {
			rawQuery = parts[1][i+1:]
		}
	}
	h := map[string][]string{}
	for k, v := range info.Headers {
		h[k] = []string{v}
	}
	return HTTPRequest{Method: info.Method, Path: info.Path, RawQuery: rawQuery, Proto: info.Version, Headers: h}, true
}

// HTTPResult is one differential comparison of an HTTP request.
type HTTPResult struct {
	QuarantOK   bool
	ReferenceOK bool
	RefErr      string
	Mismatches  []Mismatch
	// Leniency names the RFC 9112 rule net/http enforces and Quarant does
	// not, when only Quarant accepts the input.
	Leniency string
	// GatedMethod is set when net/http accepts a request whose method is
	// outside the analyzer's LooksLikeHTTP list (a deliberate gate against
	// reading non-HTTP bytes as HTTP).
	GatedMethod string
}

// Class buckets the comparison:
//
//	agree, both_reject, reference_only (Quarant missed a valid request),
//	gated_method (missed because the method is not in the LooksLikeHTTP list),
//	field_mismatch (both parsed, a security-relevant field differs),
//	ambiguous_duplicate (a security header is repeated: the two parsers keep
//	different values, and so may the device's server),
//	quarant_lenient (only Quarant accepts; the RFC rule it skips is named),
//	quarant_only (only Quarant accepts, for no recognised reason).
func (r HTTPResult) Class() string {
	switch {
	case r.QuarantOK && r.ReferenceOK && len(r.Mismatches) == 0 && r.Leniency != "":
		return "quarant_lenient"
	case r.QuarantOK && r.ReferenceOK && len(r.Mismatches) == 0:
		return "agree"
	case !r.QuarantOK && !r.ReferenceOK:
		return "both_reject"
	case !r.QuarantOK && r.GatedMethod != "":
		return "gated_method"
	case !r.QuarantOK:
		return "reference_only"
	case !r.ReferenceOK && r.Leniency != "":
		return "quarant_lenient"
	case !r.ReferenceOK:
		return "quarant_only"
	}
	for _, m := range r.Mismatches {
		if !strings.HasPrefix(m.Field, "duplicate:") {
			return "field_mismatch"
		}
	}
	return "ambiguous_duplicate"
}

// CompareHTTPRequest runs both parsers on data, which must start with the
// request line.
func CompareHTTPRequest(data []byte) HTTPResult {
	q, qok := QuarantHTTPRequest(data)
	ref, err := ReferenceHTTPRequest(data)
	res := HTTPResult{QuarantOK: qok, ReferenceOK: err == nil}
	if err != nil {
		res.RefErr = err.Error()
		if qok {
			res.Leniency = httpLeniency(data, err)
		}
		return res
	}
	if !qok {
		if !rules.LooksLikeHTTP(data) {
			res.GatedMethod = ref.Method
		}
		return res
	}
	add := func(field, a, b string) {
		if a != b {
			res.Mismatches = append(res.Mismatches, Mismatch{Field: field, Quarant: a, Reference: b})
		}
	}
	add("method", q.Method, ref.Method)
	add("path", q.Path, ref.Path)
	add("query", q.RawQuery, ref.RawQuery)
	add("proto", q.Proto, ref.Proto)
	// net/http keeps "Cookie :" (whitespace before the colon, forbidden by
	// RFC 9112 5.1) as a header named "cookie "; Quarant trims the name.
	// The value still crossed the network, so this is leniency, not a
	// misread.
	spaced := map[string]bool{}
	for k := range ref.Headers {
		if t := strings.TrimRight(k, " \t"); t != k {
			spaced[t] = true
		}
	}
	for _, name := range securityHeaders {
		rv := ref.Headers[name]
		qv := q.Headers[name]
		if spaced[name] && len(rv) == 0 {
			res.Leniency = "whitespace_before_colon"
			continue
		}
		if len(rv) > 1 {
			res.Mismatches = append(res.Mismatches, Mismatch{Field: "duplicate:" + name, Quarant: strings.Join(qv, "|"), Reference: strings.Join(rv, "|")})
			continue
		}
		add("header:"+name, strings.Join(qv, "|"), strings.Join(rv, "|"))
	}
	return res
}

// httpLeniency explains why net/http rejected an input Quarant accepted,
// when the reason is a known RFC 9112 strictness rule that lenient embedded
// servers commonly skip. An empty string means the reason is not recognised.
func httpLeniency(data []byte, err error) string {
	msg := err.Error()
	head := data
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		head = data[:i]
	} else if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		head = data[:i]
	}
	switch {
	case strings.Contains(msg, "malformed HTTP version"):
		return "invalid_version_token"
	case strings.Contains(msg, "malformed HTTP request"):
		return "invalid_request_line"
	case strings.Contains(msg, "invalid method"):
		return "invalid_method_token"
	case strings.Contains(msg, "malformed MIME header") || strings.Contains(msg, "invalid header field"):
		return "invalid_header_line"
	case strings.Contains(msg, "missing required Host header") || strings.Contains(msg, "too many Host headers"):
		return "host_header_rule"
	case strings.Contains(msg, "invalid URI") || strings.Contains(msg, "invalid control character in URL") || strings.Contains(msg, "parse "):
		return "invalid_request_target"
	case strings.Contains(msg, "Content-Length") || strings.Contains(msg, "Transfer-Encoding") || strings.Contains(msg, "transfer encoding"):
		return "message_framing_rule"
	case strings.Contains(msg, "unsupported protocol version"):
		return "unsupported_version"
	case bytes.Contains(head, []byte("\n ")) || bytes.Contains(head, []byte("\n\t")):
		return "obsolete_line_folding"
	}
	if _, perr := textproto.NewReader(bufio.NewReader(bytes.NewReader(data))).ReadLine(); perr != nil {
		return "unterminated_line"
	}
	return ""
}

// HTTPReport summarises the HTTP differential over the client streams of a
// capture.
type HTTPReport struct {
	Streams         int            `json:"http_streams"`
	Classes         map[string]int `json:"classes"`
	FieldMismatches map[string]int `json:"field_mismatches,omitempty"`
	Leniency        map[string]int `json:"quarant_lenient_reasons,omitempty"`
	GatedMethods    map[string]int `json:"gated_methods,omitempty"`
	// MultiSegment: the request head spans more than one TCP segment.
	MultiSegment int `json:"head_spans_multiple_segments"`
	// OrderSensitive: arrival-order concatenation (what the analyzer did
	// before sequence-aware assembly) parses differently from sequence order.
	OrderSensitive int `json:"arrival_order_changes_result"`
	Retransmitted  int `json:"streams_with_retransmitted_segments"`
	// ArrivalBytesDiffer: the arrival-order buffer differs from the
	// sequence-order stream (duplicated or misplaced bytes that body rules
	// would read), within the 16 KB capture limit.
	ArrivalBytesDiffer int `json:"arrival_bytes_differ"`
	// NonHTTPPort: valid requests on ports the analyzer does not parse as
	// HTTP (rules.IsHTTPPort); they are not in the counts above.
	NonHTTPPort        int            `json:"requests_on_unparsed_ports"`
	NonHTTPPortPorts   map[uint16]int `json:"unparsed_ports,omitempty"`
	NonHTTPPortMethods map[string]int `json:"unparsed_port_methods,omitempty"`
	Examples           []Example      `json:"examples,omitempty"`
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (r *HTTPReport) add(st *stream) {
	ordered := st.ordered()
	if !rules.IsHTTPPort(st.dstPort) {
		if req, err := ReferenceHTTPRequest(ordered); err == nil {
			r.NonHTTPPort++
			r.NonHTTPPortPorts[st.dstPort]++
			r.NonHTTPPortMethods[req.Method]++
		}
		return
	}
	r.Streams++
	if len(st.segments) > 1 {
		r.MultiSegment++
	}
	if st.retransmitted {
		r.Retransmitted++
	}
	res := CompareHTTPRequest(ordered)
	class := res.Class()
	r.Classes[class]++
	for _, m := range res.Mismatches {
		r.FieldMismatches[m.Field]++
	}
	if res.Leniency != "" {
		r.Leniency[res.Leniency]++
	}
	if res.GatedMethod != "" {
		r.GatedMethods[res.GatedMethod]++
	}
	if class != "agree" && class != "both_reject" && len(r.Examples) < 20 {
		detail := res.Leniency
		if res.RefErr != "" {
			detail = strings.TrimSpace(detail + " " + res.RefErr)
		}
		if len(res.Mismatches) > 0 {
			// Field names only: header values can hold credentials.
			fields := make([]string, 0, len(res.Mismatches))
			for _, m := range res.Mismatches {
				fields = append(fields, m.Field)
			}
			detail = strings.Join(fields, ",")
		}
		r.Examples = append(r.Examples, Example{Flow: st.key, Class: class, Detail: detail})
	}
	if !bytes.Equal(capBytes(st.arrival), ordered) {
		r.ArrivalBytesDiffer++
	}
	a, aok := QuarantHTTPRequest(st.arrival)
	o, ook := QuarantHTTPRequest(ordered)
	if aok != ook || fmt.Sprint(a) != fmt.Sprint(o) {
		r.OrderSensitive++
	}
}

func capBytes(b []byte) []byte {
	if len(b) > maxHelloBytes {
		return b[:maxHelloBytes]
	}
	return b
}
