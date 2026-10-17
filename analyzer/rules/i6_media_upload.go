package rules

import (
	"bytes"
	"fmt"
	"strings"
)

// I6MediaUploadCleartextRule reports a device uploading images, video or
// audio to a remote service over plaintext HTTP. Camera snapshots and
// recordings are personal data (EN 303 645 5.8-1); in cleartext anyone on
// the path can read them.
type I6MediaUploadCleartextRule struct{}

func (r *I6MediaUploadCleartextRule) ID() string         { return "I6_MEDIA_UPLOAD_CLEARTEXT" }
func (r *I6MediaUploadCleartextRule) Category() string   { return "I6" }
func (r *I6MediaUploadCleartextRule) Severity() Severity { return SeverityHigh }
func (r *I6MediaUploadCleartextRule) Type() string       { return "I6_MEDIA_UPLOAD_CLEARTEXT" }

var mediaMagic = []struct {
	prefix []byte
	kind   string
}{
	{[]byte{0xff, 0xd8, 0xff}, "jpeg"},
	{[]byte("\x89PNG\r\n\x1a\n"), "png"},
	{[]byte("GIF8"), "gif"},
	{[]byte("RIFF"), "riff"}, // WAV, AVI, WebP
	{[]byte("ID3"), "mp3"},
	{[]byte{0x1a, 0x45, 0xdf, 0xa3}, "webm"},
}

func (r *I6MediaUploadCleartextRule) Apply(ctx *Context) (Match, bool) {
	if ctx == nil || ctx.HTTP == nil || ctx.TLS || !IsPublicIP(ctx.DstIP) {
		return Match{}, false
	}
	req := ctx.HTTP
	if req.Method != "POST" && req.Method != "PUT" {
		return Match{}, false
	}
	declared, sniffed := mediaInRequest(req)
	if declared == "" && sniffed == "" {
		return Match{}, false
	}
	host := strings.ToLower(strings.TrimSpace(req.Headers["host"]))
	if host == "" {
		host = ctx.DstIP
	}
	return Match{
		Message: "Media (image, video or audio) was uploaded to a remote service over plaintext HTTP.",
		Evidence: fmt.Sprintf("method=%s host=%s content_type=%s content_magic=%s content_length=%s",
			req.Method, truncate(host, 80), orUnknown(declared), orUnknown(sniffed), orUnknown(req.Headers["content-length"])),
		OWASPTags:      uniqueTags("I6", "I7"),
		Confidence:     "high",
		ObservedFact:   "A POST/PUT request over plaintext HTTP to a public address carried media content (declared by Content-Type or recognised from the file signature).",
		Inference:      "Camera snapshots, recordings or voice clips may be readable by anyone on the network path.",
		Limitation:     "The content itself is not inspected or stored; whether it shows people or the home, and whether it is protected by other means (e.g. encrypted inside the file), is not known.",
		Recommendation: "Check whether the device or its app offers encrypted (HTTPS) upload, and whether cloud upload can be disabled.",
	}, true
}

// mediaInRequest returns the media type declared by the request (or by a
// multipart part) and the type recognised from the body's leading bytes.
func mediaInRequest(req *HTTPInfo) (declared, sniffed string) {
	ct := strings.ToLower(req.ContentType)
	if isMediaType(ct) {
		declared = ct
	} else if ct == "multipart/form-data" || strings.HasPrefix(ct, "multipart/") {
		low := bytes.ToLower(req.Body)
		if i := bytes.Index(low, []byte("content-type:")); i >= 0 {
			rest := strings.TrimSpace(string(low[i+len("content-type:"):]))
			if j := strings.IndexAny(rest, "\r\n;"); j >= 0 {
				rest = rest[:j]
			}
			if isMediaType(rest) {
				declared = "multipart:" + rest
			}
		}
	}
	body := req.Body
	if len(body) > 0 {
		for _, m := range mediaMagic {
			if bytes.HasPrefix(body, m.prefix) {
				sniffed = m.kind
				break
			}
		}
		if sniffed == "" && len(body) >= 12 && bytes.Equal(body[4:8], []byte("ftyp")) {
			sniffed = "mp4"
		}
	}
	return declared, sniffed
}

func isMediaType(ct string) bool {
	return strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/")
}

func init() {
	Register(&I6MediaUploadCleartextRule{})
}
