// Package parserdiff compares Quarant's protocol parsers with independent
// reference implementations (differential testing). A disagreement means one
// side misreads the bytes; when it is Quarant, detections built on that field
// (weak TLS, JA3, SNI-based identity) can be wrong, and an attacker who knows
// the discrepancy could evade the monitor. Everything here runs offline on
// byte buffers: nothing is sent to any device.
package parserdiff

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"

	"quarant/analyzer/rules"
)

// Hello is the normalised view of a ClientHello used for comparison.
type Hello struct {
	SNI               string
	CipherSuites      []uint16
	Extensions        []uint16
	SupportedGroups   []uint16
	ECPointFormats    []uint8
	SupportedVersions []uint16 // only from the supported_versions extension
}

var errCaptured = errors.New("parserdiff: hello captured")

// ReferenceClientHello parses a TLS ClientHello with Go's crypto/tls server
// implementation. data must start with the TLS record. ok is false when the
// standard library rejects the bytes as a ClientHello.
func ReferenceClientHello(data []byte) (Hello, bool) {
	h, err := ReferenceClientHelloErr(data)
	return h, err == nil
}

// ReferenceClientHelloErr is ReferenceClientHello returning crypto/tls's
// reason for rejecting the input.
func ReferenceClientHelloErr(data []byte) (Hello, error) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	captured := make(chan *tls.ClientHelloInfo, 1)
	cfg := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			captured <- info
			return nil, errCaptured
		},
	}
	server := tls.Server(serverSide, cfg)
	done := make(chan struct{})
	var hsErr error
	go func() {
		_ = serverSide.SetDeadline(time.Now().Add(2 * time.Second))
		hsErr = server.Handshake()
		close(done)
	}()
	go func() {
		_ = clientSide.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = clientSide.Write(data)
		// Drain whatever the server answers (alerts) so it never blocks.
		buf := make([]byte, 512)
		_ = clientSide.SetReadDeadline(time.Now().Add(2 * time.Second))
		for {
			if _, err := clientSide.Read(buf); err != nil {
				return
			}
		}
	}()

	select {
	case info := <-captured:
		<-done
		return fromStdlib(info, hasSupportedVersionsExt(info.Extensions)), nil
	case <-done:
		if hsErr == nil {
			hsErr = errors.New("handshake ended without a ClientHello")
		}
		return Hello{}, hsErr
	}
}

func hasSupportedVersionsExt(exts []uint16) bool {
	for _, e := range exts {
		if e == 43 {
			return true
		}
	}
	return false
}

func fromStdlib(info *tls.ClientHelloInfo, withVersions bool) Hello {
	h := Hello{
		SNI:            info.ServerName,
		CipherSuites:   append([]uint16(nil), info.CipherSuites...),
		Extensions:     append([]uint16(nil), info.Extensions...),
		ECPointFormats: append([]uint8(nil), info.SupportedPoints...),
	}
	for _, c := range info.SupportedCurves {
		h.SupportedGroups = append(h.SupportedGroups, uint16(c))
	}
	if withVersions {
		// crypto/tls synthesises SupportedVersions from the legacy version
		// when the extension is absent; only the extension is comparable.
		h.SupportedVersions = append([]uint16(nil), info.SupportedVersions...)
	}
	return h
}

// QuarantClientHello parses data with Quarant's production parser.
func QuarantClientHello(data []byte) (Hello, bool) {
	info, ok := rules.DetectTLSClientHello(data)
	if !ok {
		return Hello{}, false
	}
	return Hello{
		SNI:               info.SNI,
		CipherSuites:      info.CipherSuites,
		Extensions:        info.Extensions,
		SupportedGroups:   info.SupportedGroups,
		ECPointFormats:    info.ECPointFormats,
		SupportedVersions: info.SupportedVersions,
	}, true
}

// Mismatch describes one field on which the parsers disagree.
type Mismatch struct {
	Field     string `json:"field"`
	Quarant   string `json:"quarant"`
	Reference string `json:"reference"`
}

// Result is the outcome of comparing both parsers on one input.
type Result struct {
	QuarantOK   bool       `json:"quarant_ok"`
	ReferenceOK bool       `json:"reference_ok"`
	Mismatches  []Mismatch `json:"mismatches,omitempty"`
	// LenientExtension is set when Quarant accepted a hello that the
	// reference rejects only because of an extension Quarant does not
	// interpret (e.g. a malformed key_share); the fields Quarant reports
	// are unaffected.
	LenientExtension uint16 `json:"lenient_extension,omitempty"`
	// ReferenceRFCInvalid: the reference accepted a hello that violates RFC
	// 8446 length limits (session_id > 32 bytes or no cipher suites), which
	// Quarant correctly rejects; the handshake would fail later anyway.
	ReferenceRFCInvalid bool `json:"reference_rfc_invalid,omitempty"`
}

// interpretedExtensions are the extensions whose content Quarant reports.
var interpretedExtensions = map[uint16]bool{0: true, 10: true, 11: true, 43: true}

// Class summarises a Result: agree, both_reject, quarant_only (Quarant
// reports a hello the reference rejects: possible phantom detection),
// reference_only (Quarant misses a valid hello: possible missed detection),
// or field_mismatch.
func (r Result) Class() string {
	switch {
	case r.QuarantOK && r.ReferenceOK && len(r.Mismatches) == 0:
		return "agree"
	case !r.QuarantOK && !r.ReferenceOK:
		return "both_reject"
	case r.QuarantOK && !r.ReferenceOK && r.LenientExtension != 0:
		return "lenient_unparsed_extension"
	case r.QuarantOK && !r.ReferenceOK:
		return "quarant_only"
	case !r.QuarantOK && r.ReferenceOK && r.ReferenceRFCInvalid:
		return "reference_lenient_rfc_invalid"
	case !r.QuarantOK && r.ReferenceOK:
		return "reference_only"
	default:
		return "field_mismatch"
	}
}

// CompareClientHello runs both parsers on data.
func CompareClientHello(data []byte) Result {
	q, qok := QuarantClientHello(data)
	ref, rok := ReferenceClientHello(data)
	res := Result{QuarantOK: qok, ReferenceOK: rok}
	if qok && !rok {
		res.LenientExtension = blameUninterpreted(data, q.Extensions)
	}
	if !qok && rok {
		res.ReferenceRFCInvalid = violatesHelloLimits(data)
	}
	if !qok || !rok {
		return res
	}
	add := func(field string, a, b any) {
		as, bs := fmt.Sprint(a), fmt.Sprint(b)
		if as != bs {
			res.Mismatches = append(res.Mismatches, Mismatch{Field: field, Quarant: as, Reference: bs})
		}
	}
	add("sni", q.SNI, ref.SNI)
	add("cipher_suites", q.CipherSuites, ref.CipherSuites)
	add("extensions", q.Extensions, ref.Extensions)
	add("supported_groups", q.SupportedGroups, ref.SupportedGroups)
	add("ec_point_formats", q.ECPointFormats, ref.ECPointFormats)
	add("supported_versions", q.SupportedVersions, ref.SupportedVersions)
	sort.Slice(res.Mismatches, func(i, j int) bool { return res.Mismatches[i].Field < res.Mismatches[j].Field })
	return res
}

// withoutExtension rebuilds a single-record ClientHello without extension
// typ, fixing up all length fields. It is a debugging aid for attributing a
// rejection to one extension.
func withoutExtension(data []byte, typ uint16) ([]byte, bool) {
	if len(data) < 9 || data[0] != 22 || data[5] != 1 {
		return nil, false
	}
	hl := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if 9+hl > len(data) {
		return nil, false
	}
	ch := data[9 : 9+hl]
	i := 34
	if i >= len(ch) {
		return nil, false
	}
	i += 1 + int(ch[i])
	if i+2 > len(ch) {
		return nil, false
	}
	i += 2 + (int(ch[i])<<8 | int(ch[i+1]))
	if i >= len(ch) {
		return nil, false
	}
	i += 1 + int(ch[i])
	if i+2 > len(ch) {
		return nil, false
	}
	extStart := i + 2
	el := int(ch[i])<<8 | int(ch[i+1])
	if extStart+el > len(ch) {
		return nil, false
	}
	exts := ch[extStart : extStart+el]
	var kept []byte
	found := false
	for j := 0; j+4 <= len(exts); {
		t := uint16(exts[j])<<8 | uint16(exts[j+1])
		l := int(exts[j+2])<<8 | int(exts[j+3])
		if j+4+l > len(exts) {
			return nil, false
		}
		if t == typ {
			found = true
		} else {
			kept = append(kept, exts[j:j+4+l]...)
		}
		j += 4 + l
	}
	if !found {
		return nil, false
	}
	body := append(append([]byte(nil), ch[:i]...), byte(len(kept)>>8), byte(len(kept)))
	body = append(body, kept...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := append([]byte{22, data[1], data[2], byte(len(hs) >> 8), byte(len(hs))}, hs...)
	return rec, true
}

// blameUninterpreted returns an uninterpreted extension whose removal makes
// the reference accept data. When several are malformed, all of them are
// removed together and the first is reported.
func blameUninterpreted(data []byte, exts []uint16) uint16 {
	var unparsed []uint16
	for _, ext := range exts {
		if interpretedExtensions[ext] {
			continue
		}
		unparsed = append(unparsed, ext)
		if mod, ok := withoutExtension(data, ext); ok {
			if _, accepted := ReferenceClientHello(mod); accepted {
				return ext
			}
		}
	}
	mod := data
	for _, ext := range unparsed {
		if m, ok := withoutExtension(mod, ext); ok {
			mod = m
		}
	}
	if len(unparsed) > 0 {
		if _, accepted := ReferenceClientHello(mod); accepted {
			return unparsed[0]
		}
	}
	return 0
}

// violatesHelloLimits checks the RFC 8446 §4.1.2 length limits that
// crypto/tls's parser does not enforce: legacy_session_id <0..32> and
// cipher_suites <2..2^16-2>.
func violatesHelloLimits(data []byte) bool {
	if len(data) < 9+35 {
		return false
	}
	ch := data[9:]
	sid := int(ch[34])
	if sid > 32 {
		return true
	}
	i := 35 + sid
	if i+2 > len(ch) {
		return false
	}
	return int(ch[i])<<8|int(ch[i+1]) < 2
}
