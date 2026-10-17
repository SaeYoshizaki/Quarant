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
	// UPnP eventing (GENA, UPnP Device Architecture 2.0 section 4) runs
	// over HTTP/1.1 on TCP; NOTIFY carries device state changes.
	[]byte("SUBSCRIBE "),
	[]byte("UNSUBSCRIBE "),
	[]byte("NOTIFY "),
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
