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

	Headers map[string]string
	RawLine string
}

func ParseHTTP(payload []byte) (*HTTPInfo, bool) {
	i := bytes.Index(payload, []byte("\r\n\r\n"))
	if i < 0 {
		i = bytes.Index(payload, []byte("\n\n"))
	}
	if i < 0 {
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
	for _, ln := range lines[1:] {
		ln = strings.TrimRight(ln, "\r")
		if ln == "" {
			break
		}
		col := strings.IndexByte(ln, ':')
		if col <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(ln[:col]))
		v := strings.TrimSpace(ln[col+1:])
		if _, exists := h[k]; !exists {
			h[k] = v
		}
	}

	return &HTTPInfo{
		Method:  method,
		Path:    path,
		Query:   qv,
		Version: version,
		Headers: h,
		RawLine: reqLine,
	}, true
}
