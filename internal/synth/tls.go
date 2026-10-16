package synth

import (
	"crypto/tls"
	"net"
	"time"
)

// TLSClientHello returns the first TLS record a real crypto/tls client sends
// for the given SNI and version range. Using the standard library keeps the
// bytes realistic (extensions, GREASE-free cipher order, supported_versions).
//
// Note: crypto/tls draws key shares from crypto/rand even when Config.Rand is
// set, so the bytes differ between calls. Everything Quarant analyzes (SNI,
// versions, cipher suites, extensions, JA3) is identical across runs.
func TLSClientHello(sni string, minVersion, maxVersion uint16) []byte {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	cfg := &tls.Config{
		ServerName:         sni,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		InsecureSkipVerify: true, // never completes; we only need the hello
		Rand:               &counterReader{},
	}
	if maxVersion < tls.VersionTLS12 {
		// Legacy devices offer CBC/3DES suites; crypto/tls only sends them when asked.
		cfg.CipherSuites = []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		}
	}
	client := tls.Client(clientSide, cfg)
	go func() { _ = client.Handshake() }()

	_ = serverSide.SetReadDeadline(time.Now().Add(2 * time.Second))
	header := make([]byte, 5)
	if _, err := readFull(serverSide, header); err != nil {
		panic("synth: read client hello header: " + err.Error())
	}
	n := int(header[3])<<8 | int(header[4])
	body := make([]byte, n)
	if _, err := readFull(serverSide, body); err != nil {
		panic("synth: read client hello body: " + err.Error())
	}
	return append(header, body...)
}

func readFull(c net.Conn, buf []byte) (int, error) {
	read := 0
	for read < len(buf) {
		n, err := c.Read(buf[read:])
		read += n
		if err != nil {
			return read, err
		}
	}
	return read, nil
}

// counterReader is a deterministic byte stream used as crypto/tls randomness
// so that generated fixtures are as reproducible as the library allows.
type counterReader struct{ n byte }

func (r *counterReader) Read(p []byte) (int, error) {
	for i := range p {
		r.n++
		p[i] = r.n
	}
	return len(p), nil
}
