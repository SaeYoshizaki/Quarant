package rules

import (
	"strings"
	"testing"
)

func mediaCtx(t *testing.T, dst, raw string) *Context {
	t.Helper()
	h, ok := ParseHTTP([]byte(raw))
	if !ok {
		t.Fatal("not parsed")
	}
	return &Context{DstIP: dst, HTTP: h}
}

func TestMediaUploadDeclaredAndSniffed(t *testing.T) {
	ctx := mediaCtx(t, "52.219.84.124", "PUT /bucket/snap.jpg HTTP/1.1\r\nHost: b.s3.amazonaws.com\r\nContent-Type: image/jpeg\r\nContent-Length: 9\r\nAuthorization: AWS4-HMAC-SHA256 x\r\n\r\n\xff\xd8\xff\xe0JFIF")
	m, ok := (&I6MediaUploadCleartextRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected a finding")
	}
	if m.Evidence != "method=PUT host=b.s3.amazonaws.com content_type=image/jpeg content_magic=jpeg content_length=9" {
		t.Fatalf("evidence %q", m.Evidence)
	}
	if strings.Contains(m.Evidence, "snap.jpg") || strings.Contains(m.Evidence, "AWS4") {
		t.Fatal("path or credentials must not be in the evidence")
	}
}

func TestMediaUploadMultipartPart(t *testing.T) {
	ctx := mediaCtx(t, "203.0.113.7", "POST /upload HTTP/1.1\r\nHost: cam.example\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 4096\r\n\r\n--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\xff\xd8\xff")
	m, ok := (&I6MediaUploadCleartextRule{}).Apply(ctx)
	if !ok || !strings.Contains(m.Evidence, "content_type=multipart:image/jpeg") {
		t.Fatalf("got %v %q", ok, m.Evidence)
	}
}

func TestMediaUploadIgnoresLocalTLSAndDownloads(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n"
	if _, ok := (&I6MediaUploadCleartextRule{}).Apply(mediaCtx(t, "192.168.1.10", raw)); ok {
		t.Fatal("LAN destination must not be reported")
	}
	c := mediaCtx(t, "203.0.113.7", raw)
	c.TLS = true
	if _, ok := (&I6MediaUploadCleartextRule{}).Apply(c); ok {
		t.Fatal("TLS must not be reported")
	}
	if _, ok := (&I6MediaUploadCleartextRule{}).Apply(mediaCtx(t, "203.0.113.7", "GET /a.jpg HTTP/1.1\r\nHost: h\r\n\r\n")); ok {
		t.Fatal("downloads are not uploads")
	}
	if _, ok := (&I6MediaUploadCleartextRule{}).Apply(mediaCtx(t, "203.0.113.7", "POST /api HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\n\r\n{\"a\":1}")); ok {
		t.Fatal("non-media body must not be reported")
	}
}

// A camera streaming to its cloud relay sent a text part first and the video
// part after it (E11, TP-Link camera on UNSW 2016).
func TestMediaUploadMultipartLaterPart(t *testing.T) {
	raw := "POST /relay HTTP/1.1\r\nHost: relay.example\r\nContent-Type: multipart/x-mixed-replace; boundary=b\r\nContent-Length: 1073741824\r\n\r\n" +
		"--b\r\nContent-Type: text/http-header\r\n\r\nHTTP/1.1 200 OK\r\n\r\n--b\r\nContent-Type: video/x-h264\r\n\r\n\x00\x00\x00\x01"
	m, ok := (&I6MediaUploadCleartextRule{}).Apply(mediaCtx(t, "203.0.113.7", raw))
	if !ok || !strings.Contains(m.Evidence, "content_type=multipart:video/x-h264") {
		t.Fatalf("got %v %q", ok, m.Evidence)
	}
}

// An empty PUT that only declares an image type carries no media (E12).
func TestMediaUploadIgnoresEmptyDeclaredBody(t *testing.T) {
	raw := "PUT /bucket/x.jpg HTTP/1.1\r\nHost: b.example\r\nContent-Type: image/jpg\r\nContent-Length: 0\r\n\r\n"
	if _, ok := (&I6MediaUploadCleartextRule{}).Apply(mediaCtx(t, "203.0.113.7", raw)); ok {
		t.Fatal("an empty upload must not be reported")
	}
}
