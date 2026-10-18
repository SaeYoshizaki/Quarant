package analyzer

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
	"quarant/internal/synth"
)

// Regression tests for the misses found in E11 (docs/assessment/miss-audit.md).

// runConnEvents analyses one synthetic connection and returns its events.
func runConnEvents(t *testing.T, build func(b *synth.Builder)) []Event {
	t.Helper()
	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	events, _ := NewJSONSink(filepath.Join(dir, "events.jsonl"))
	h := NewFlowHandlerWithObservations(events, nil, nil, false, db)
	b := &synth.Builder{}
	build(b)
	var pcap bytes.Buffer
	if err := b.WritePCAP(&pcap); err != nil {
		t.Fatal(err)
	}
	if err := NewEngine(h).RunPCAPStream(&pcap); err != nil {
		t.Fatal(err)
	}
	_ = events.Close()
	var out []Event
	readJSONL(t, filepath.Join(dir, "events.jsonl"), func(line []byte) {
		var e Event
		_ = json.Unmarshal(line, &e)
		if !e.Debug {
			out = append(out, e)
		}
	})
	return out
}

// serverHello builds a minimal TLS ServerHello record without extensions.
func serverHello(version, cipher uint16) []byte {
	body := make([]byte, 0, 38)
	body = binary.BigEndian.AppendUint16(body, version)
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id length
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0) // compression
	hs := append([]byte{2, 0, 0, byte(len(body))}, body...)
	rec := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(rec[3:], uint16(len(hs)))
	return append(rec, hs...)
}

func eventsOfType(evs []Event, typ string) []Event {
	var out []Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// A device that sends the 5-byte TLS record header in a segment of its own
// to a port outside rules.IsTLSPort must still be recognised as TLS.
func TestTLSByContentWithHeaderOnlyFirstSegment(t *testing.T) {
	hello := synth.TLSClientHello("bp.example.test", tls.VersionTLS10, tls.VersionTLS10)
	meter := synth.NewHost("74:6a:89:00:00:01", "192.168.50.60")
	cloud := synth.Host{MAC: reasmPhone.MAC, IP: net.ParseIP("198.51.100.77").To4()}
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(meter, cloud, 4116, 8777).Handshake(reasmStart).
			ClientSegments([][]byte{hello[:5], hello[5:]}, []int{0, 1}).Close()
	})
	if len(eventsOfType(evs, "I7_TLS_WEAK_VERSION_OBSERVED")) == 0 {
		t.Fatalf("TLS 1.0 behind a header-only first segment on port 8777 was not recognised")
	}
}

// A local TLS server that selects TLS 1.0 although the client offered TLS 1.2
// is the device with the weak cryptography: the finding goes to the server.
func TestWeakTLSVersionChosenByLocalServerIsTheServers(t *testing.T) {
	camera := synth.NewHost("00:62:6e:00:00:01", "192.168.50.70")
	hello := synth.TLSClientHello("", tls.VersionTLS10, tls.VersionTLS12)
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, camera, 50110, 443).Handshake(reasmStart).
			Client(hello).Server(serverHello(tls.VersionTLS10, 0x002F)).Close()
	})
	weak := eventsOfType(evs, "I7_TLS_WEAK_VERSION_OBSERVED")
	if len(weak) == 0 {
		t.Fatal("no weak-version finding")
	}
	for _, e := range weak {
		if e.DeviceKey != camera.IP.String() {
			t.Fatalf("device_key=%s, want the camera %s", e.DeviceKey, camera.IP)
		}
	}
}

// When the client itself offers at most TLS 1.0, the finding stays with the
// client.
func TestWeakTLSVersionOfferedByClientStaysWithClient(t *testing.T) {
	camera := synth.NewHost("00:62:6e:00:00:02", "192.168.50.71")
	hello := synth.TLSClientHello("", tls.VersionTLS10, tls.VersionTLS10)
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, camera, 50111, 443).Handshake(reasmStart).
			Client(hello).Server(serverHello(tls.VersionTLS10, 0x002F)).Close()
	})
	for _, e := range eventsOfType(evs, "I7_TLS_WEAK_VERSION_OBSERVED") {
		if e.DeviceKey != reasmPhone.IP.String() {
			t.Fatalf("device_key=%s, want the client %s", e.DeviceKey, reasmPhone.IP)
		}
	}
}

// HTTP on a port outside rules.IsHTTPPort reaches the secret and media rules
// (D23): a phone app logged into a camera with credentials in the URL on
// port 34100, and the camera is the device whose interface takes them.
func TestContentHTTPOnOtherPortReachesSecretRules(t *testing.T) {
	camera := synth.NewHost("00:62:6e:00:00:03", "192.168.50.72")
	req := []byte("GET /cgi-bin/login.cgi?usr=admin&pwd=hunter2&cmd=login HTTP/1.1\r\nHost: 192.168.50.72:34100\r\n\r\n")
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, camera, 50120, 34100).Handshake(reasmStart).Client(req).
			Server([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).Close()
	})
	var found []Event
	for _, e := range evs {
		if e.Type == "INSECURE_HTTP_TOKEN" || e.Type == "I3_AUTH_TOKEN_IN_URL" || e.Type == "INSECURE_HTTP_AUTH" {
			found = append(found, e)
		}
	}
	if len(found) == 0 {
		t.Fatalf("credentials in a URL on port 34100 not reported; got %v", evs)
	}
	for _, e := range found {
		if e.DeviceKey != camera.IP.String() {
			t.Errorf("%s attributed to %s, want the camera", e.Type, e.DeviceKey)
		}
		if bytes.Contains([]byte(e.Evidence), []byte("hunter2")) {
			t.Errorf("value leaked: %s", e.Evidence)
		}
	}
}

// The other HTTP rules stay on the standard ports: fetching a UPnP device
// description on 49153 is not plaintext-HTTP or setup-endpoint evidence.
func TestContentHTTPKeepsOtherRulesOnStandardPorts(t *testing.T) {
	plug := synth.NewHost("ec:1a:59:00:00:01", "192.168.50.73")
	req := []byte("GET /setup.xml HTTP/1.1\r\nHost: 192.168.50.73:49153\r\n\r\n")
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(reasmPhone, plug, 50121, 49153).Handshake(reasmStart).Client(req).
			Server([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 0\r\n\r\n")).Close()
	})
	for _, e := range evs {
		if e.Type == "INSECURE_HTTP" || e.Type == "I9_SETUP_ENDPOINT_STILL_ACTIVE" || e.Type == "I3_API_OVER_PLAINTEXT" {
			t.Errorf("unexpected %s for a UPnP description fetch", e.Type)
		}
	}
}

// A camera receiving its app's login from a WAN peer over a UDP P2P protocol
// (E11, Luohe camera on CIC 2022).
func TestUDPCleartextCredentialsFromRemotePeer(t *testing.T) {
	camera := synth.NewHost("7c:a7:b0:00:00:01", "192.168.50.80")
	peer := synth.Host{MAC: reasmPhone.MAC, IP: net.ParseIP("198.51.100.20").To4()}
	msg := append([]byte{0xf1, 0xd0, 0x00, 0x60, 0xd1, 0x00, 0x00, 0x05}, []byte("cmd=login&user=admin&pwd=s3cret&x=1")...)
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.UDP(reasmStart, peer, camera, 5988, 25020, msg)
		b.UDP(reasmStart.Add(time.Second), peer, camera, 5988, 25020, msg)
	})
	got := eventsOfType(evs, "INSECURE_UDP_CREDENTIALS")
	if len(got) != 1 {
		t.Fatalf("want one finding per device and peer, got %d", len(got))
	}
	e := got[0]
	if e.DeviceKey != camera.IP.String() || e.Basis != BasisObserved {
		t.Fatalf("device_key=%s basis=%s", e.DeviceKey, e.Basis)
	}
	if bytes.Contains([]byte(e.Evidence), []byte("s3cret")) || bytes.Contains([]byte(e.Evidence), []byte("admin")) {
		t.Fatalf("value leaked: %s", e.Evidence)
	}
}

// A camera sending a JPEG inside a proprietary TCP protocol to its cloud
// (E11, Borun camera on CIC 2022, port 8899).
func TestImageInsideNonHTTPTCPToPublicAddress(t *testing.T) {
	camera := synth.NewHost("c0:e7:bf:00:00:01", "192.168.50.81")
	cloud := synth.Host{MAC: reasmPhone.MAC, IP: net.ParseIP("198.51.100.30").To4()}
	frame := append([]byte{0xa1, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10}, []byte("JFIF\x00\x01\x01")...)
	evs := runConnEvents(t, func(b *synth.Builder) {
		b.TCP(camera, cloud, 33153, 8899).Handshake(reasmStart).Client(frame).Close()
	})
	got := eventsOfType(evs, "I6_MEDIA_UPLOAD_CLEARTEXT")
	if len(got) != 1 || got[0].DeviceKey != camera.IP.String() || got[0].Evidence != "protocol=unparsed_tcp content_magic=jpeg offset=8" {
		t.Fatalf("got %+v", got)
	}
	// The same bytes to a LAN host are not counted (D23: device to public only).
	lan := synth.NewHost("02:00:00:00:00:09", "192.168.50.90")
	evs = runConnEvents(t, func(b *synth.Builder) {
		b.TCP(camera, lan, 33154, 8899).Handshake(reasmStart).Client(frame).Close()
	})
	if n := len(eventsOfType(evs, "I6_MEDIA_UPLOAD_CLEARTEXT")); n != 0 {
		t.Fatalf("LAN destination reported %d times", n)
	}
}

// TLS that starts after a plaintext XMPP preamble (STARTTLS, RFC 6120 5.4):
// E12 found a device negotiating TLS 1.0 with 3DES this way on port 5222.
func TestStartTLSAfterXMPPPreamble(t *testing.T) {
	dev := synth.NewHost("00:16:6c:00:00:01", "192.168.50.82")
	xmpp := synth.Host{MAC: reasmPhone.MAC, IP: net.ParseIP("198.51.100.40").To4()}
	hello := synth.TLSClientHello("chat.example.test", tls.VersionTLS10, tls.VersionTLS10)
	build := func(askUpgrade bool) func(b *synth.Builder) {
		return func(b *synth.Builder) {
			c := b.TCP(dev, xmpp, 34533, 5222).Handshake(reasmStart).
				Client([]byte("<?xml version='1.0'?><stream:stream to='chat.example.test' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")).
				Server([]byte("<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>"))
			if askUpgrade {
				c = c.Client([]byte("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")).
					Server([]byte("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"))
			}
			c.Client(hello).Server(serverHello(tls.VersionTLS10, 0xC012)).Close()
		}
	}
	evs := runConnEvents(t, build(true))
	if len(eventsOfType(evs, "I7_TLS_WEAK_VERSION_OBSERVED")) == 0 {
		t.Fatal("TLS 1.0 after STARTTLS not recognised")
	}
	sel := eventsOfType(evs, "I7_TLS_WEAK_CIPHER_SELECTED")
	if len(sel) == 0 || !bytes.Contains([]byte(sel[0].Evidence), []byte("risk_kind=3des_cipher")) {
		t.Fatalf("3DES selected after STARTTLS not reported: %+v", sel)
	}
	// Without the client's upgrade request a handshake-looking segment in the
	// middle of a stream is not taken for TLS.
	if n := len(eventsOfType(runConnEvents(t, build(false)), "TLS_CLIENT_HELLO")); n != 0 {
		t.Fatalf("mid-stream ClientHello without STARTTLS was parsed %d times", n)
	}
}
