package rules

import (
	"strings"
	"testing"
)

func TestFTPCredentials(t *testing.T) {
	ctx := &Context{DstPort: 21, Payload: []byte("USER vera\r\nPASS s3cretpw\r\nTYPE I\r\n")}
	m, ok := (&I7FTPCredentialsRule{}).Apply(ctx)
	if !ok || m.Evidence != "ftp_user=*** ftp_password=***" || strings.Contains(m.Evidence, "s3cret") {
		t.Fatalf("got %v %q", ok, m.Evidence)
	}
	for _, neg := range []*Context{
		{DstPort: 21, Payload: []byte("USER anonymous\r\nPASS \r\n")}, // empty password
		{DstPort: 21, Payload: []byte("USER vera\r\n")},               // no PASS yet
		{DstPort: 2121, Payload: []byte("PASS x\r\n")},                // not the FTP control port
	} {
		if _, ok := (&I7FTPCredentialsRule{}).Apply(neg); ok {
			t.Errorf("unexpected finding for %q on %d", neg.Payload, neg.DstPort)
		}
	}
}

func TestHTTPResponseSecret(t *testing.T) {
	resp := func(ct, body string) *Context {
		return &Context{HTTPExchange: &HTTPExchange{Response: &HTTPResponseInfo{StatusCode: 200, Headers: map[string]string{"content-type": ct}, Body: []byte(body)}}}
	}
	m, ok := (&I7HTTPResponseSecretRule{}).Apply(resp("application/json", `{"Logitech-API-Key":"3f2a9c7e1b4d8f6a0e5c2b7d9a1f4e8c"}`))
	if !ok || strings.Contains(m.Evidence, "3f2a9c7e") {
		t.Fatalf("got %v %q", ok, m.Evidence)
	}
	if _, ok := (&I7HTTPResponseSecretRule{}).Apply(resp("text/html", `<script>var token="3f2a9c7e1b4d8f6a0e5c2b7d9a1f4e8c";</script>`)); ok {
		t.Fatal("web pages are not read")
	}
	c := resp("application/json", `{"api_key":"3f2a9c7e1b4d8f6a0e5c2b7d9a1f4e8c"}`)
	c.TLS = true
	if _, ok := (&I7HTTPResponseSecretRule{}).Apply(c); ok {
		t.Fatal("TLS must not be reported")
	}
}
