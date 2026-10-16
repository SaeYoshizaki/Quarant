package viewer

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLocalAccessGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := withLocalAccessGuard(ok, "127.0.0.1:8080")

	cases := []struct {
		name       string
		method     string
		host       string
		origin     string
		wantStatus int
		wantACAO   string
	}{
		{name: "same origin", method: http.MethodGet, host: "127.0.0.1:8080", wantStatus: http.StatusOK},
		{name: "localhost dev origin", method: http.MethodGet, host: "127.0.0.1:8080", origin: "http://localhost:3000", wantStatus: http.StatusOK, wantACAO: "http://localhost:3000"},
		{name: "foreign origin gets no CORS grant", method: http.MethodGet, host: "127.0.0.1:8080", origin: "https://evil.example", wantStatus: http.StatusOK},
		{name: "dns rebinding host rejected", method: http.MethodGet, host: "evil.example:8080", wantStatus: http.StatusForbidden},
		{name: "ipv6 loopback host", method: http.MethodGet, host: "[::1]:8080", wantStatus: http.StatusOK},
		{name: "post rejected", method: http.MethodPost, host: "127.0.0.1:8080", wantStatus: http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/report", nil)
			req.Host = tc.host
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want %d", rec.Code, tc.wantStatus)
			}
			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.wantACAO {
				t.Fatalf("ACAO=%q want %q", got, tc.wantACAO)
			}
		})
	}
}

func TestLocalAccessGuardAllowsConfiguredLANHost(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := withLocalAccessGuard(ok, "192.168.50.10:8080")
	req := httptest.NewRequest(http.MethodGet, "/api/report", nil)
	req.Host = "192.168.50.10:8080"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}
