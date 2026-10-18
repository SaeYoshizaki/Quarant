package rules

import (
	"bytes"
	"strings"
)

// Rules added after E14 (YourThings 2018, unseen devices): a hub logging
// into an external FTP server in cleartext, and a hub receiving an API key
// in the body of a cleartext HTTP response.

// I7FTPCredentialsRule reports FTP USER/PASS commands sent in cleartext
// (RFC 959 4.1.1). Only the presence of the commands is recorded.
type I7FTPCredentialsRule struct{}

func (r *I7FTPCredentialsRule) ID() string         { return "I7_FTP_CREDENTIALS" }
func (r *I7FTPCredentialsRule) Category() string   { return "I7" }
func (r *I7FTPCredentialsRule) Severity() Severity { return SeverityCritical }
func (r *I7FTPCredentialsRule) Type() string       { return "INSECURE_FTP_CREDENTIALS" }

func (r *I7FTPCredentialsRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.TLS || ctx.DstPort != 21 || !ftpPasswordSent(ctx.Payload) {
		return Match{}, false
	}
	return Match{
		Message:        "FTP login credentials were sent over plaintext FTP.",
		Evidence:       "ftp_user=*** ftp_password=***",
		OWASPTags:      uniqueTags("I1", "I2", "I7"),
		Confidence:     "high",
		ObservedFact:   "The client sent FTP USER and PASS commands with a non-empty password in cleartext.",
		Inference:      "The password can be read by anyone on the network path.",
		Limitation:     "Passive monitoring cannot tell whether the login succeeded, whether the password is shared or default, or what the account can access.",
		Recommendation: "Use SFTP or FTPS if the device supports it, and change the password if it may have been exposed.",
	}, true
}

// ftpPasswordSent reports a PASS command with a non-empty argument at the
// start of a line of the client's control-channel data.
func ftpPasswordSent(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("PASS ")) && len(bytes.TrimSpace(line[5:])) > 0 {
			return true
		}
	}
	return false
}

// I7HTTPResponseSecretRule reports secrets in the body of a cleartext HTTP
// response (an API key or token handed to the device). Only structured API
// bodies are read (JSON, XML, form, plain text declared as such): web pages
// and scripts mention "password" or "token" as words far more often than
// they carry one.
type I7HTTPResponseSecretRule struct{}

func (r *I7HTTPResponseSecretRule) ID() string         { return "I7_HTTP_RESPONSE_SECRET" }
func (r *I7HTTPResponseSecretRule) Category() string   { return "I7" }
func (r *I7HTTPResponseSecretRule) Severity() Severity { return SeverityCritical }
func (r *I7HTTPResponseSecretRule) Type() string       { return "INSECURE_HTTP_RESPONSE_SECRET" }

func (r *I7HTTPResponseSecretRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.TLS || ctx.HTTPExchange == nil || ctx.HTTPExchange.Response == nil {
		return Match{}, false
	}
	resp := ctx.HTTPExchange.Response
	ct := strings.ToLower(strings.TrimSpace(strings.Split(resp.Headers["content-type"], ";")[0]))
	if !structuredResponse(ct, resp.Body) {
		return Match{}, false
	}
	_, ev, ok := DetectSensitiveHTTPBody(ct, resp.Body)
	if !ok {
		return Match{}, false
	}
	return Match{
		Message:        "A secret appears in the body of a plaintext HTTP response.",
		Evidence:       "response " + ev,
		OWASPTags:      uniqueTags("I1", "I3", "I7"),
		Confidence:     "medium",
		ObservedFact:   "A field named like a credential, token or key, with a token-like value, was observed in a plaintext HTTP response body.",
		Inference:      "A credential or key given to the client may be readable by anyone on the network path.",
		Limitation:     "Field names and value shapes are heuristics; the value is not checked and may be a public identifier, a placeholder or already encrypted.",
		Recommendation: "Use HTTPS for the service, and rotate the exposed key if it is secret.",
	}, true
}

func structuredResponse(ct string, body []byte) bool {
	switch ct {
	case "application/json", "application/xml", "text/xml", "application/x-www-form-urlencoded", "text/plain":
		return true
	case "":
		t := bytes.TrimSpace(body)
		return len(t) > 0 && (t[0] == '{' || t[0] == '[')
	}
	return strings.HasSuffix(ct, "+json") || strings.HasSuffix(ct, "+xml")
}

func init() {
	Register(&I7FTPCredentialsRule{})
	Register(&I7HTTPResponseSecretRule{})
}
