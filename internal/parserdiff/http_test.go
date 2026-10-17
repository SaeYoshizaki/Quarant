package parserdiff

import "testing"

func seedRequests() [][]byte {
	return [][]byte{
		[]byte("GET /index.html HTTP/1.1\r\nHost: cam.local\r\nUser-Agent: ipcam/1.0\r\n\r\n"),
		[]byte("POST /api/login?next=%2F HTTP/1.1\r\nHost: 192.168.1.20\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 2\r\n\r\n{}"),
		[]byte("GET /cgi-bin/status?a=1&b=2 HTTP/1.0\r\nCookie: sid=abc\r\n\r\n"),
		[]byte("PUT /fw HTTP/1.1\r\nHost: h\r\nX-Token: t\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"),
	}
}

func TestHTTPParsersAgreeOnWellFormedRequests(t *testing.T) {
	for i, req := range seedRequests() {
		res := CompareHTTPRequest(req)
		if res.Class() != "agree" {
			t.Errorf("seed %d: %s %s %+v", i, res.Class(), res.RefErr, res.Mismatches)
		}
	}
}

// Ambiguities found by FuzzHTTPRequestDifferential and fixed in
// rules.ParseHTTP; each must now agree with net/http.
func TestHTTPDifferentialRegressions(t *testing.T) {
	cases := map[string]string{
		// Header names are case-insensitive and may be repeated: the
		// credential a server uses is not necessarily the first copy.
		"duplicate_authorization": "GET / HTTP/1.1\r\nHost: h\r\nAuthorization: Basic Zm9vOmJhcg==\r\nauthorization: Bearer x\r\n\r\n",
		// The head ends at the first empty line whatever the line endings;
		// a later "\r\n\r\n" in the body must not pull body lines into the
		// headers (they looked like a cleartext Authorization header).
		"lf_head_crlf_body": "POST /x HTTP/1.1\nHost: h\n\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n",
		"mixed_terminator":  "GET * HTTP/1.0\n\r\n",
		// Obsolete line folding continues the previous header value.
		"folded_authorization": "POST / HTTP/1.1\r\nHost: h\r\nAuthorization:\r\n Basic Zm9vOmJhcg==\r\n\r\n",
	}
	for name, raw := range cases {
		res := CompareHTTPRequest([]byte(raw))
		switch res.Class() {
		case "agree", "ambiguous_duplicate":
		default:
			t.Errorf("%s: %s %s %+v", name, res.Class(), res.RefErr, res.Mismatches)
		}
	}
}

// FuzzHTTPRequestDifferential looks for request heads that Quarant and
// net/http read differently. Rejections by both, and inputs only Quarant
// accepts for a named RFC 9112 strictness rule, are not findings.
//
//	go test ./internal/parserdiff -run '^$' -fuzz FuzzHTTPRequestDifferential -fuzztime 60s
func FuzzHTTPRequestDifferential(f *testing.F) {
	for _, r := range seedRequests() {
		f.Add(r)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		res := CompareHTTPRequest(data)
		switch res.Class() {
		case "agree", "both_reject", "quarant_lenient", "ambiguous_duplicate", "gated_method":
		default:
			t.Errorf("%s: ref=%q %+v", res.Class(), res.RefErr, res.Mismatches)
		}
	})
}
