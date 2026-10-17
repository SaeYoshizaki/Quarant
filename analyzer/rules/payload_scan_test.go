package rules

import (
	"strings"
	"testing"
)

func TestDetectCleartextCredentialPairs(t *testing.T) {
	// A camera P2P login as seen in E11 (values replaced).
	p2p := append([]byte{0xf1, 0xd0, 0x00, 0x60, 0xd1, 0x00, 0x00, 0x01}, []byte("cmd=check_user&user=admin&pwd=xyz123&loginuse=admin")...)
	keys, ok := DetectCleartextCredentialPairs(p2p)
	if !ok || strings.Join(keys, ",") != "cmd,user,pwd,loginuse" {
		t.Fatalf("got %v %v", keys, ok)
	}
	for _, k := range keys {
		if strings.Contains(k, "xyz") {
			t.Fatal("a value was returned")
		}
	}
	for _, neg := range []string{
		"user=admin&name=camera", // no password-like key
		"user=admin&pwd=",        // empty password
		"pwd=abc",                // a single pair, no list
		`Username="u", PasswordDigest="d", Nonce="n"`, // WSSE header: digest, not a key=value list
	} {
		if keys, ok := DetectCleartextCredentialPairs([]byte(neg)); ok {
			t.Errorf("%q: unexpected %v", neg, keys)
		}
	}
}

func TestFindMediaSignature(t *testing.T) {
	jpeg := append([]byte{0xa1, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}, []byte("JFIF\x00\x01")...)
	if kind, off, ok := FindMediaSignature(jpeg); !ok || kind != "jpeg" || off != 8 {
		t.Fatalf("jpeg: %s %d %v", kind, off, ok)
	}
	if kind, _, ok := FindMediaSignature([]byte("xx\x89PNG\r\n\x1a\nIHDR")); !ok || kind != "png" {
		t.Fatalf("png: %s %v", kind, ok)
	}
	if _, _, ok := FindMediaSignature([]byte{0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00}); ok {
		t.Fatal("a bare JPEG start must not count")
	}
}
