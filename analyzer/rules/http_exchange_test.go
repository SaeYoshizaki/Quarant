package rules

import "testing"

func exchange(t *testing.T, req, resp string) *Context {
	t.Helper()
	r, ok := ParseHTTP([]byte(req))
	if !ok {
		t.Fatal("request not parsed")
	}
	s, ok := ParseHTTPResponse([]byte(resp))
	if !ok {
		t.Fatal("response not parsed")
	}
	return &Context{HTTPExchange: &HTTPExchange{Request: r, Response: s, ServerIP: "192.168.1.129", ServerPort: 80, ServerLocal: true}}
}

func TestUnauthenticatedControlSkipsAPIKeyInPath(t *testing.T) {
	ctx := exchange(t, "PUT /api/qJ53MnTftOEAJtRVJdk0miwa5wHaOce3s6d4NA/lights/1/state HTTP/1.1\r\nHost: hue\r\n\r\n{\"on\":true}",
		"HTTP/1.1 200 OK\r\n\r\n[{\"success\":{}}]")
	if _, ok := (&I3UnauthenticatedDeviceControlRule{}).Apply(ctx); ok {
		t.Fatal("an API key in the path is a credential")
	}
}

func TestUnauthenticatedControlSkipsErrorBodies(t *testing.T) {
	// Hue answers a pairing request without the link button with 200 and an error.
	ctx := exchange(t, "POST /api HTTP/1.1\r\nHost: hue\r\n\r\n{\"devicetype\":\"app\"}",
		"HTTP/1.1 200 OK\r\n\r\n[{\"error\":{\"type\":101,\"description\":\"link button not pressed\"}}]")
	if _, ok := (&I3UnauthenticatedDeviceControlRule{}).Apply(ctx); ok {
		t.Fatal("a 200 carrying an error is not a successful call")
	}
}

func TestUnauthenticatedControlIgnoresReads(t *testing.T) {
	ctx := exchange(t, "GET /setup.xml HTTP/1.1\r\nHost: plug\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n<root/>")
	if _, ok := (&I3UnauthenticatedDeviceControlRule{}).Apply(ctx); ok {
		t.Fatal("UPnP descriptions are public by protocol design")
	}
}

func TestPortMappingRefused(t *testing.T) {
	ctx := exchange(t, "POST / HTTP/1.1\r\nSOAPAction: \"#AddPortMapping\"\r\n\r\n<NewExternalPort>80</NewExternalPort>",
		"HTTP/1.1 500 Internal Server Error\r\n\r\n<UPnPError/>")
	m, ok := (&I9UPnPPortMappingRule{}).Apply(ctx)
	if !ok || m.Severity != SeverityLow {
		t.Fatalf("a refused mapping is reported at low severity, got %v %+v", ok, m)
	}
}

func TestLooksLikeHTTPRequest(t *testing.T) {
	for in, want := range map[string]bool{
		"POST /upnp/control/basicevent1 HTTP/1.1\r\n": true,
		"GET / HTTP/1.0\r\n":                          true,
		"GET something binary":                        false,
		"HTTP/1.1 200 OK\r\n":                         false,
	} {
		if got := LooksLikeHTTPRequest([]byte(in)); got != want {
			t.Errorf("%q: got %t", in, got)
		}
	}
}
