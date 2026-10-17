package rules

import (
	"bytes"
	"regexp"
	"strings"
)

// Protocol-independent payload checks (D23). They read one packet at a time
// and never return values, only the names of what matched.

// udpCredentialKeys are key names whose value is a password or a token.
// Usernames alone are not secrets; they only count next to one of these.
var udpCredentialKeys = map[string]bool{
	"pwd": true, "pass": true, "passwd": true, "password": true, "passcode": true,
	"token": true, "access_token": true, "auth_token": true, "secret": true,
	"api_key": true, "apikey": true,
}

var kvPairRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]{0,31})=([^&\s;,"'{}]*)`)

// DetectCleartextCredentialPairs looks for printable key=value lists joined
// by '&' (the form used by camera P2P logins, E11) that carry a password or
// token key with a non-empty value. It returns the key names, sorted as they
// appear, or false.
func DetectCleartextCredentialPairs(payload []byte) ([]string, bool) {
	for _, run := range printableRuns(payload, 12) {
		if !bytes.Contains(run, []byte("&")) {
			continue
		}
		pairs := kvPairRe.FindAllSubmatch(run, 16)
		if len(pairs) < 2 {
			continue
		}
		var keys []string
		secret := false
		for _, p := range pairs {
			k := strings.ToLower(string(p[1]))
			keys = append(keys, k)
			if udpCredentialKeys[k] && len(p[2]) > 0 {
				secret = true
			}
		}
		if secret {
			return keys, true
		}
	}
	return nil, false
}

// printableRuns returns the runs of printable ASCII of at least min bytes.
func printableRuns(b []byte, min int) [][]byte {
	var out [][]byte
	start := -1
	for i := 0; i <= len(b); i++ {
		printable := i < len(b) && b[i] >= 0x20 && b[i] < 0x7f
		if printable && start < 0 {
			start = i
		} else if !printable && start >= 0 {
			if i-start >= min {
				out = append(out, b[start:i])
			}
			start = -1
		}
	}
	return out
}

// FindMediaSignature reports the kind and offset of the first image
// signature inside a payload. Only signatures long enough not to occur by
// chance in other data count: JPEG with its JFIF or Exif header, and PNG. A
// bare JPEG start (FF D8 FF) is too short to look for inside arbitrary bytes.
func FindMediaSignature(payload []byte) (string, int, bool) {
	best, kind := -1, ""
	for off := 0; ; {
		i := bytes.Index(payload[off:], []byte{0xff, 0xd8, 0xff})
		if i < 0 {
			break
		}
		at := off + i
		if at+11 <= len(payload) {
			app, id := payload[at+3], payload[at+6:at+11]
			if (app == 0xe0 && bytes.Equal(id, []byte("JFIF\x00"))) || (app == 0xe1 && bytes.Equal(id, []byte("Exif\x00"))) {
				best, kind = at, "jpeg"
				break
			}
		}
		off = at + 1
	}
	if i := bytes.Index(payload, []byte("\x89PNG\r\n\x1a\n")); i >= 0 && (best < 0 || i < best) {
		best, kind = i, "png"
	}
	return kind, best, best >= 0
}
