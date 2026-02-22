package rules

import "bytes"

var httpPrefixed = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
	[]byte("HTTP/1."),
}

func LooksLikeHTTP(data []byte) bool {
	trimmed := bytes.TrimLeft(data, "\r\n\t")
	if len(trimmed) == 0 {
		return false
	}
	for _, p := range httpPrefixed {
		if bytes.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}
