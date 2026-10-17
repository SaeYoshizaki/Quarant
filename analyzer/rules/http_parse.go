package rules

import (
	"bytes"
	"net/url"
	"strings"
)

type HTTPInfo struct {
	Method  string
	Path    string
	Query   url.Values
	Version string

	Headers     map[string]string
	RawLine     string
	Body        []byte
	ContentType string
}

// httpHeadEnd finds the empty line that ends the request head, scanning line
// by line as net/http does: lines end in "\n" with an optional "\r", so the
// terminator can be "\r\n\r\n", "\n\n" or a mix. Searching for a fixed
// terminator instead found a later "\r\n\r\n" inside the body after a
// "\n\n" head and read body lines as headers (internal/parserdiff).
func httpHeadEnd(payload []byte) (headEnd, bodyStart int, ok bool) {
	for start := 0; start < len(payload); {
		nl := bytes.IndexByte(payload[start:], '\n')
		if nl < 0 {
			return 0, 0, false
		}
		line := payload[start : start+nl]
		if start > 0 && (len(line) == 0 || (len(line) == 1 && line[0] == '\r')) {
			return start, start + nl + 1, true
		}
		start += nl + 1
	}
	return 0, 0, false
}

func ParseHTTP(payload []byte) (*HTTPInfo, bool) {
	i, bodyStart, ok := httpHeadEnd(payload)
	if !ok {
		return nil, false
	}

	head := payload[:i]

	lines := strings.Split(string(head), "\n")
	if len(lines) == 0 {
		return nil, false
	}

	reqLine := strings.TrimRight(lines[0], "\r")
	parts := strings.Split(reqLine, " ")
	if len(parts) < 3 {
		return nil, false
	}

	method := parts[0]
	target := parts[1]
	version := parts[2]

	if method == "" || !strings.HasPrefix(version, "HTTP/") {
		return nil, false
	}

	path := target
	rawQuery := ""
	if q := strings.IndexByte(target, '?'); q >= 0 {
		path = target[:q]
		rawQuery = target[q+1:]
	}

	qv, _ := url.ParseQuery(rawQuery)

	h := map[string]string{}
	// foldKey is the header a continuation line extends ("" when the last
	// header line was a duplicate that was not stored).
	foldKey := ""
	for _, ln := range lines[1:] {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			break
		}
		if ln[0] == ' ' || ln[0] == '\t' {
			// Obsolete line folding (RFC 9112 5.2): the line continues the
			// previous header value, as net/http reads it. Dropping it read
			// "Authorization:\n Basic ..." as an empty credential.
			if foldKey != "" {
				h[foldKey] = strings.TrimSpace(h[foldKey] + " " + strings.TrimSpace(ln))
			}
			continue
		}
		foldKey = ""
		col := strings.IndexByte(ln, ':')
		if col <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:col]))
		v := strings.TrimSpace(ln[col+1:])
		if _, exists := h[k]; !exists {
			h[k] = v
			foldKey = k
		}
	}

	body := payload[bodyStart:]
	if len(body) == 0 {
		body = nil
	}

	ct := ""
	if v, ok := h["content-type"]; ok {
		ct = strings.ToLower(strings.TrimSpace(strings.Split(v, ";")[0]))
	}

	return &HTTPInfo{
		Method:      method,
		Path:        path,
		Query:       qv,
		Version:     version,
		Headers:     h,
		RawLine:     reqLine,
		Body:        body,
		ContentType: ct,
	}, true
}
