package rules

import (
	"strings"
	"testing"
)

func TestI7HTTPQueryExpandedKeys(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"refresh_token": {"abc"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected query leak to be detected")
	}
	if match.Evidence != "refresh_token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
	if match.Severity != SeverityCritical {
		t.Fatalf("expected CRITICAL severity, got %s", match.Severity)
	}
}

func TestI7HTTPQuerySessionRequiresSensitiveValueShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"session": {"abc"},
			},
		},
	}

	if _, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx); ok {
		t.Fatal("did not expect short session value to be detected")
	}
}

func TestI7HTTPQuerySessionDetectsJWTValue(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"session": {"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected jwt-like session to be detected")
	}
	if match.Evidence != "session=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPQueryDeviceIDNeedsIdentifierShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"device_id": {"abc"},
			},
		},
	}

	if _, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak device_id value to be detected")
	}
}

func TestI7HTTPQueryDeviceIDDetectsIdentifierShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"device_id": {"dev-12345678"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected device identifier to be detected")
	}
	if match.Evidence != "device_id=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPAuthExtendedHeader(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-api-key": "secret-value",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected header leak to be detected")
	}
	if match.Evidence != "X-Api-Key: ***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
	if !containsAll(match.OWASPTags, "I1", "I3", "I7") {
		t.Fatalf("expected OWASP tags, got: %v", match.OWASPTags)
	}
	if match.Limitation == "" {
		t.Fatalf("expected limitation, got empty match: %+v", match)
	}
}

func TestI7HTTPAuthExtendedProxyAuthorizationHeader(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"proxy-authorization": "Basic Zm9vOmJhcg==",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected proxy authorization header to be detected")
	}
	if match.Evidence != "Proxy-Authorization: ***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
	if !containsAll(match.OWASPTags, "I1", "I3", "I7") {
		t.Fatalf("expected OWASP tags, got: %v", match.OWASPTags)
	}
}

func TestI7HTTPAuthExtendedAuthTokenHeader(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-auth-token": "secret-value",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected x-auth-token header to be detected")
	}
	if match.Evidence != "X-Auth-Token: ***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPAuthDetectsCustomTokenHeaderByValueShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-device-token": "AbCdEf1234567890ZYXWVutsrq",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected custom token header to be detected")
	}
	if match.Evidence != "x-device-token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPAuthDoesNotDetectBenignCustomHeader(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-device-token": "abc",
			},
		},
	}

	if _, ok := (&I7HTTPAuthRule{}).Apply(ctx); ok {
		t.Fatal("did not expect benign custom header to be detected")
	}
}

func TestI7HTTPBodyInfersFormWithoutContentType(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Body: []byte("ssid=mywifi&psk=supersecret"),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected inferred form body leak to be detected")
	}
	if match.Evidence != "ssid=***" && match.Evidence != "psk=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
	if !containsAll(match.OWASPTags, "I1", "I3", "I7") {
		t.Fatalf("expected OWASP tags, got: %v", match.OWASPTags)
	}
}

func TestI7HTTPBodySSIDAloneDoesNotTrigger(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Body: []byte("ssid=guest"),
		},
	}

	if _, ok := (&I7HTTPBodySecretRule{}).Apply(ctx); ok {
		t.Fatal("did not expect standalone ssid to be detected")
	}
}

func TestI7HTTPBodyDetectsMultipartSecrets(t *testing.T) {
	body := []byte("--boundary\r\nContent-Disposition: form-data; name=\"mqtt_pass\"\r\n\r\nhunter2\r\n--boundary--\r\n")
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "multipart/form-data",
			Body:        body,
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected multipart body leak to be detected")
	}
	if match.Evidence != "mqtt_pass=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPPlaintextOnlyIsWarning(t *testing.T) {
	match, ok := (&I7HTTPPlaintextRule{}).Apply(&Context{
		HTTP: &HTTPInfo{
			Method:  "GET",
			Path:    "/",
			Headers: map[string]string{"host": "device.local"},
		},
	})
	if !ok {
		t.Fatal("expected plaintext HTTP signal")
	}
	if match.Severity != SeverityWarning {
		t.Fatalf("expected WARNING severity, got %s", match.Severity)
	}
}

func TestI7HTTPRulesDoNotFireOnTLSContext(t *testing.T) {
	ctx := &Context{
		TLS: true,
		HTTP: &HTTPInfo{
			Method:      "GET",
			Path:        "/api/config",
			Query:       map[string][]string{"token": {"abcdef1234567890ABCDEF"}},
			Headers:     map[string]string{"authorization": "Bearer abcdef1234567890ABCDEF", "cookie": "sid=abcdef1234567890ABCDEF"},
			ContentType: "application/json",
			Body:        []byte(`{"password":"secret-value"}`),
		},
	}

	if _, ok := (&I7HTTPPlaintextRule{}).Apply(ctx); ok {
		t.Fatal("did not expect plaintext HTTP signal on TLS context")
	}
	if _, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx); ok {
		t.Fatal("did not expect HTTP token signal on TLS context")
	}
	if _, ok := (&I7HTTPAuthRule{}).Apply(ctx); ok {
		t.Fatal("did not expect HTTP auth signal on TLS context")
	}
	if _, ok := (&I7HTTPBodySecretRule{}).Apply(ctx); ok {
		t.Fatal("did not expect HTTP body secret signal on TLS context")
	}
	if _, ok := (&I7HTTPCookieRule{}).Apply(ctx); ok {
		t.Fatal("did not expect HTTP cookie signal on TLS context")
	}
}

func TestI7HTTPBodyDetectsXMLSecrets(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "application/xml",
			Body:        []byte("<config><serial>SN12345678</serial></config>"),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected xml body leak to be detected")
	}
	if match.Evidence != "serial=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPBodyDetectsBase64LikeSession(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "application/json",
			Body:        []byte(`{"session":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9"}`),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected base64-like session to be detected")
	}
	if match.Evidence != "session=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPBodyDoesNotDetectBenignSerialValue(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "application/json",
			Body:        []byte(`{"serial":"123"}`),
		},
	}

	if _, ok := (&I7HTTPBodySecretRule{}).Apply(ctx); ok {
		t.Fatal("did not expect benign serial value to be detected")
	}
}

func TestI7HTTPTokenMetadataDoesNotExposeRawValue(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"token": {"super-secret-token-value"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected token leak to be detected")
	}
	if strings.Contains(match.Evidence, "super-secret-token-value") {
		t.Fatalf("raw token should not be exposed: %s", match.Evidence)
	}
	if !containsAll(match.OWASPTags, "I1", "I3", "I7") {
		t.Fatalf("expected OWASP tags, got: %v", match.OWASPTags)
	}
	if match.Limitation == "" {
		t.Fatalf("expected limitation, got empty match: %+v", match)
	}
}

func TestSensitiveFieldIgnoresWebSocketHandshakeKey(t *testing.T) {
	if ev, ok := detectSensitiveField("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==", nil); ok {
		t.Fatalf("WebSocket handshake nonce must not be reported as a secret: %s", ev)
	}
	if _, ok := detectSensitiveField("api_key", "dGhlIHNhbXBsZSBub25jZQ==", nil); !ok {
		t.Fatal("expected api_key with a token value to be reported")
	}
}

func TestI7HTTPAuthNamesChallengeResponseSchemes(t *testing.T) {
	for header, want := range map[string]string{
		"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20211102/us-east-2/s3/aws4_request, Signature=abc": "Authorization: AWS4-HMAC-SHA256 ***",
		"Digest username=\"admin\", response=\"6629fae49393a053\"":                                  "Authorization: Digest ***",
		"Basic YWRtaW46YWRtaW4=":         "Authorization: Basic ***",
		"Token abc123":                   "Authorization: ***",
		"OSS LTAIexample:c2lnbmF0dXJl":   "Authorization: OSS ***",
		"WSSE profile=\"UsernameToken\"": "Authorization: WSSE ***",
		"ossabc123secret":                "Authorization: ***",
	} {
		m, ok := (&I7HTTPAuthRule{}).Apply(&Context{HTTP: &HTTPInfo{Headers: map[string]string{"authorization": header}}})
		if !ok || m.Evidence != want {
			t.Errorf("%q: got %q", header, m.Evidence)
		}
		if strings.Contains(m.Evidence, "AKIDEXAMPLE") || strings.Contains(m.Evidence, "admin") || strings.Contains(m.Evidence, "LTAI") || strings.Contains(m.Evidence, "abc123") {
			t.Errorf("value leaked: %q", m.Evidence)
		}
	}
}

// The bytes after a GET without Content-Length belong to the next request on
// a kept-alive connection, not to a body (E12: a camera web UI's password
// cookie in the following GET was reported as a body secret).
func TestParseHTTPKeepAliveRequestHasNoBody(t *testing.T) {
	raw := "GET / HTTP/1.1\r\nHost: cam\r\n\r\nGET /next HTTP/1.1\r\nHost: cam\r\nCookie: user=a; pwd=b\r\n\r\n"
	h, ok := ParseHTTP([]byte(raw))
	if !ok || h.Body != nil {
		t.Fatalf("ok=%v body=%q", ok, h.Body)
	}
	if _, _, found := DetectSensitiveHTTPBody(h.ContentType, h.Body); found {
		t.Fatal("the next request was read as a body")
	}
	post := "POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloGET /b HTTP/1.1\r\n\r\n"
	if p, _ := ParseHTTP([]byte(post)); string(p.Body) != "hello" {
		t.Fatalf("body %q", p.Body)
	}
}
