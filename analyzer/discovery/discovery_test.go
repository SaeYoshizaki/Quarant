package discovery

import (
	"net"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"quarant/internal/synth"
)

func TestLookupMAC(t *testing.T) {
	hik, _ := net.ParseMAC("0c:75:d2:1a:2b:3c")
	info := LookupMAC(hik)
	if !strings.Contains(info.Vendor, "Hikvision") || info.LocallyAdministered {
		t.Fatalf("unexpected vendor lookup: %+v", info)
	}

	random, _ := net.ParseMAC("da:a1:19:20:30:40")
	info = LookupMAC(random)
	if info.Vendor != "" || !info.LocallyAdministered {
		t.Fatalf("randomized MAC must not get a vendor: %+v", info)
	}

	unknown, _ := net.ParseMAC("00:00:00:00:00:01")
	if LookupMAC(unknown).Vendor == "" {
		t.Fatal("expected registered OUI 000000 to resolve")
	}
	if !strings.Contains(OUISource(), "IEEE") {
		t.Fatalf("missing OUI provenance: %q", OUISource())
	}
}

func decodeDHCP(t *testing.T, payload []byte) *layers.DHCPv4 {
	t.Helper()
	p := gopacket.NewPacket(payload, layers.LayerTypeDHCPv4, gopacket.Default)
	d, ok := p.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok {
		t.Fatal("failed to decode DHCP")
	}
	return d
}

func TestParseDHCPClient(t *testing.T) {
	mac, _ := net.ParseMAC("10:06:1c:3a:4f:1c")
	payload := synth.DHCPClientMessage(mac, synth.DHCPOptions{
		MsgType: layers.DHCPMsgTypeRequest, Hostname: "ESP_3A4F1C\x00\x01", VendorClass: "udhcp 1.20.2",
		ParamRequest: []byte{1, 3, 6, 15}, RequestedIP: net.ParseIP("192.168.50.21"), Xid: 7,
	})
	info, ok := ParseDHCPClient(decodeDHCP(t, payload))
	if !ok {
		t.Fatal("expected DHCP client info")
	}
	if info.Hostname != "ESP_3A4F1C" {
		t.Fatalf("hostname not sanitized: %q", info.Hostname)
	}
	if info.VendorClass != "udhcp 1.20.2" || info.ParamRequestList != "1,3,6,15" || info.MessageType != "Request" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if !info.ClientIP.Equal(net.ParseIP("192.168.50.21")) || info.ClientMAC.String() != "10:06:1c:3a:4f:1c" {
		t.Fatalf("unexpected addresses: %+v", info)
	}
}

func TestParseMDNSAnnouncement(t *testing.T) {
	payload := synth.MDNSAnnounce("_http._tcp.local", "smartplug-3a4f1c", []string{"model=SP10", "fw=1.0.3"})
	p := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)
	d := p.Layer(layers.LayerTypeDNS).(*layers.DNS)
	info, ok := ParseMDNSAnnouncement(d)
	if !ok {
		t.Fatal("expected mDNS info")
	}
	if len(info.Services) != 1 || info.Services[0] != "_http._tcp.local" {
		t.Fatalf("services: %v", info.Services)
	}
	if len(info.Instances) != 1 || info.Instances[0] != "smartplug-3a4f1c" {
		t.Fatalf("instances: %v", info.Instances)
	}
	if strings.Join(info.TXT, ";") != "fw=1.0.3;model=SP10" {
		t.Fatalf("txt: %v", info.TXT)
	}
}

func TestParseSSDP(t *testing.T) {
	info, ok := ParseSSDP([]byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://192.168.50.20/d.xml\r\nNT: upnp:rootdevice\r\nSERVER: Linux/3.10 UPnP/1.0 IPCamera/5.4.1\r\n\r\n"))
	if !ok || info.Kind != "notify" || info.Server != "Linux/3.10 UPnP/1.0 IPCamera/5.4.1" || info.Location != "http://192.168.50.20/d.xml" || info.Target != "upnp:rootdevice" {
		t.Fatalf("unexpected SSDP info: %+v ok=%v", info, ok)
	}
	if _, ok := ParseSSDP([]byte("garbage")); ok {
		t.Fatal("garbage must not parse")
	}
	if _, ok := ParseSSDP(nil); ok {
		t.Fatal("empty payload must not parse")
	}
}

func FuzzParseSSDP(f *testing.F) {
	f.Add([]byte("NOTIFY * HTTP/1.1\r\nSERVER: x\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		info, _ := ParseSSDP(data)
		if len(info.Server) > 200 {
			t.Fatal("server header not bounded")
		}
	})
}
