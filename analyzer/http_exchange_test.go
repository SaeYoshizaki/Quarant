package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"quarant/analyzer/knowledge"
	"quarant/internal/synth"
)

func soapRequest(path, action, body string) []byte {
	return []byte(fmt.Sprintf("POST %s HTTP/1.1\r\nHost: 192.168.50.1\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPACTION: \"%s\"\r\nContent-Length: %d\r\n\r\n%s", path, action, len(body), body))
}

func TestHTTPExchangeRulesOnLocalUPnP(t *testing.T) {
	db, err := knowledge.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	sink, _ := NewJSONSink(filepath.Join(dir, "events.jsonl"))
	h := NewFlowHandlerWithObservations(sink, nil, nil, false, db)

	b := &synth.Builder{}
	start := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	gw := synth.NewHost("02:00:00:00:00:01", "192.168.50.1")
	cam := synth.NewHost("02:00:00:00:00:02", "192.168.50.2")
	plug := synth.NewHost("02:00:00:00:00:03", "192.168.50.3")
	hub := synth.NewHost("02:00:00:00:00:04", "192.168.50.4")
	ok := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 10\r\n\r\n<s:Body/>")

	// The camera opens an inbound port on the gateway (UPnP IGD on 5000).
	b.TCP(cam, gw, 40001, 5000).Handshake(start).
		Client(soapRequest("/ctl/IPConn", "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping",
			"<u:AddPortMapping><NewRemoteHost></NewRemoteHost><NewExternalPort>8443</NewExternalPort><NewProtocol>TCP</NewProtocol><NewInternalPort>443</NewInternalPort><NewInternalClient>192.168.50.2</NewInternalClient><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping>")).
		Server(ok).Close()
	// The hub switches the plug over UPnP SOAP without credentials.
	b.TCP(hub, plug, 40002, 49153).Handshake(start.Add(time.Second)).
		Client(soapRequest("/upnp/control/basicevent1", "urn:Belkin:service:basicevent:1#SetBinaryState", "<u:SetBinaryState><BinaryState>1</BinaryState></u:SetBinaryState>")).
		Server(ok).Close()
	// Controls: a refused action, and one carrying a credential.
	b.TCP(hub, plug, 40003, 49153).Handshake(start.Add(2 * time.Second)).
		Client(soapRequest("/upnp/control/basicevent1", "urn:Belkin:service:basicevent:1#GetHomeInfo", "<u:GetHomeInfo/>")).
		Server([]byte("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")).Close()
	b.TCP(hub, cam, 40004, 8080).Handshake(start.Add(3 * time.Second)).
		Client([]byte("POST /cgi-bin/ptz HTTP/1.1\r\nHost: cam\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nContent-Length: 0\r\n\r\n")).
		Server(ok).Close()
	var pcap bytes.Buffer
	_ = b.WritePCAP(&pcap)
	if err := NewEngine(h).RunPCAPStream(&pcap); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	var mappings, unauth []Event
	readJSONL(t, filepath.Join(dir, "events.jsonl"), func(line []byte) {
		var e Event
		_ = json.Unmarshal(line, &e)
		switch e.Type {
		case "I9_UPNP_PORT_MAPPING_REQUESTED":
			mappings = append(mappings, e)
		case "I3_UNAUTHENTICATED_DEVICE_CONTROL":
			unauth = append(unauth, e)
		}
	})
	if len(mappings) != 1 || mappings[0].DeviceKey != "192.168.50.2" || mappings[0].Basis != BasisObserved {
		t.Fatalf("want one observed mapping attributed to the camera, got %+v", mappings)
	}
	if want := "action=AddPortMapping external_port=8443 protocol=TCP internal_port=443 internal_client=192.168.50.2 lease=0 gateway=192.168.50.1:5000 status=200 accepted=true"; mappings[0].Evidence != want {
		t.Fatalf("evidence = %q", mappings[0].Evidence)
	}
	devices := map[string]bool{}
	for _, e := range unauth {
		devices[e.DeviceKey] = true
		if e.SrcIP == e.DeviceKey {
			t.Fatalf("unauthenticated control must be attributed to the server, got %+v", e)
		}
	}
	// The plug (SetBinaryState) and the gateway (IGD has no authentication)
	// are reported; the refused action and the authenticated request are not.
	if !devices["192.168.50.3"] || !devices["192.168.50.1"] || devices["192.168.50.2"] || len(unauth) != 2 {
		t.Fatalf("unexpected unauthenticated-control findings: %+v", unauth)
	}
}
