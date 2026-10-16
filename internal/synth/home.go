package synth

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket/layers"
)

// Label is one ground-truth statement about the synthetic scenario. Labels
// let evaluation code measure what Quarant detects (true positives), what it
// misses (false negatives) and what it reports without a label (candidate
// false positives).
type Label struct {
	ID        string `json:"id"`
	DeviceIP  string `json:"device_ip"`
	Kind      string `json:"kind"`
	Malicious bool   `json:"malicious"`
	// Visibility states whether the condition is observable from packets at
	// all: "observable" means passive monitoring could detect it; "hidden"
	// means it exists in the scenario but cannot be seen on the wire, which
	// documents a limitation rather than a detector bug.
	Visibility  string `json:"visibility"`
	Description string `json:"description"`
}

// Scenario bundles generated traffic with its ground truth.
type Scenario struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Start       time.Time         `json:"start"`
	End         time.Time         `json:"end"`
	LocalNet    string            `json:"local_net"`
	Devices     map[string]string `json:"devices"`
	Labels      []Label           `json:"labels"`

	Builder *Builder `json:"-"`
}

// Addresses used by the home scenario. RFC 1918 for the LAN, RFC 5737
// documentation ranges for "internet" hosts, and OUIs of real vendors so that
// MAC-vendor lookup can be exercised.
var (
	homeGateway = NewHost("02:00:5e:00:00:01", "192.168.50.1")
	homeCamera  = NewHost("0c:75:d2:1a:2b:3c", "192.168.50.20") // Hikvision OUI
	homePlug    = NewHost("10:06:1c:3a:4f:1c", "192.168.50.21") // Espressif OUI
	homeDVR     = NewHost("68:dd:b7:55:66:77", "192.168.50.22") // TP-Link OUI
	homePhone   = NewHost("da:a1:19:20:30:40", "192.168.50.30") // locally administered (randomized)

	camCloud   = "198.51.100.10"
	camUpload  = "198.51.100.11"
	camFW      = "198.51.100.12"
	plugBroker = "198.51.100.20"
	beaconC2   = "203.0.113.66"
	ntpServer  = "203.0.113.123"
	phoneWeb   = "198.51.100.80"
	dnsServer  = homeGateway
)

func remote(ip string) Host {
	// Off-LAN hosts are reached via the gateway, so their frames carry the
	// gateway MAC.
	return Host{MAC: homeGateway.MAC, IP: net.ParseIP(ip).To4()}
}

// HomeScenario builds one hour of synthetic household IoT traffic containing
// a set of deliberately insecure behaviours plus benign controls.
func HomeScenario(start time.Time) *Scenario {
	b := &Builder{}
	at := func(d time.Duration) time.Time { return start.Add(d) }

	// --- DHCP: identity hints (hostname, vendor class, option 55 list) ------
	bcast := Host{MAC: net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, IP: net.IPv4bcast.To4()}
	dhcp := func(ts time.Time, h Host, hostname, vendorClass string, prl []byte, xid uint32) {
		src := Host{MAC: h.MAC, IP: net.IPv4zero.To4()}
		b.UDP(ts, src, bcast, 68, 67, DHCPClientMessage(h.MAC, DHCPOptions{
			MsgType: layers.DHCPMsgTypeDiscover, Hostname: hostname, VendorClass: vendorClass, ParamRequest: prl, Xid: xid,
		}))
		b.UDP(ts.Add(5*time.Millisecond), src, bcast, 68, 67, DHCPClientMessage(h.MAC, DHCPOptions{
			MsgType: layers.DHCPMsgTypeRequest, Hostname: hostname, VendorClass: vendorClass, ParamRequest: prl, RequestedIP: h.IP, Xid: xid,
		}))
	}
	dhcp(at(0), homeCamera, "IPCAM-1A2B3C", "udhcp 1.20.2", []byte{1, 3, 6, 12, 15, 28, 42}, 0x1001)
	dhcp(at(2*time.Second), homePlug, "ESP_3A4F1C", "", []byte{1, 3, 28, 6, 15, 44, 46, 47, 31, 33, 121, 43}, 0x1002)
	dhcp(at(4*time.Second), homeDVR, "dvr", "udhcp 1.19.4", []byte{1, 3, 6, 12, 15, 28, 42}, 0x1003)
	dhcp(at(6*time.Second), homePhone, "phone-01", "", []byte{1, 121, 3, 6, 15, 108, 114, 119, 252}, 0x1004)

	// --- discovery: SSDP and mDNS -------------------------------------------
	ssdpGroup := Host{MAC: net.HardwareAddr{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}, IP: net.ParseIP("239.255.255.250").To4()}
	b.UDP(at(10*time.Second), homeCamera, ssdpGroup, 1900, 1900, []byte("NOTIFY * HTTP/1.1\r\n"+
		"HOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=1800\r\n"+
		"LOCATION: http://192.168.50.20:80/upnp/device.xml\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n"+
		"SERVER: Linux/3.10 UPnP/1.0 IPCamera/5.4.1\r\nUSN: uuid:cam-0001::upnp:rootdevice\r\n\r\n"))
	mdnsGroup := Host{MAC: net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}, IP: net.ParseIP("224.0.0.251").To4()}
	b.UDP(at(12*time.Second), homePlug, mdnsGroup, 5353, 5353, MDNSAnnounce("_http._tcp.local", "smartplug-3a4f1c", []string{"model=SP10", "fw=1.0.3"}))

	// --- DNS lookups -------------------------------------------------------
	dns := func(ts time.Time, h Host, id uint16, name, answer string) {
		b.UDP(ts, h, dnsServer, 40000+id, 53, DNSQuery(id, name))
		b.UDP(ts.Add(3*time.Millisecond), dnsServer, h, 53, 40000+id, DNSResponse(id, name, net.ParseIP(answer)))
	}
	dns(at(20*time.Second), homeCamera, 1, "ipc-cloud.example-cam.test", camCloud)
	dns(at(21*time.Second), homeCamera, 2, "upload.example-cam.test", camUpload)
	dns(at(22*time.Second), homeCamera, 3, "fw.example-cam.test", camFW)
	dns(at(23*time.Second), homePlug, 4, "mqtt.plug-cloud.test", plugBroker)
	dns(at(24*time.Second), homePhone, 5, "www.example.com", phoneWeb)
	dns(at(25*time.Second), homeDVR, 6, "update.dvr-vendor.test", beaconC2)

	// --- camera: legacy TLS to its cloud -----------------------------------
	b.TCP(homeCamera, remote(camCloud), 50001, 443).Handshake(at(30 * time.Second)).
		Client(TLSClientHello("ipc-cloud.example-cam.test", tls.VersionTLS10, tls.VersionTLS10)).Close()

	// --- camera: HTTP Basic auth in cleartext ------------------------------
	cred := base64.StdEncoding.EncodeToString([]byte("admin:synthetic-pass"))
	b.TCP(homeCamera, remote(camUpload), 50002, 80).Handshake(at(40 * time.Second)).
		Client([]byte("POST /api/v1/snapshot HTTP/1.1\r\nHost: upload.example-cam.test\r\n" +
			"Authorization: Basic " + cred + "\r\nUser-Agent: IPCamera/5.4.1\r\nContent-Type: image/jpeg\r\nContent-Length: 4\r\n\r\nJPEG")).
		Server([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")).Close()

	// --- camera: firmware check over plain HTTP ------------------------------
	b.TCP(homeCamera, remote(camFW), 50003, 80).Handshake(at(50 * time.Second)).
		Client([]byte("GET /firmware/check?model=DS-2CD&version=5.4.1 HTTP/1.1\r\nHost: fw.example-cam.test\r\nUser-Agent: IPCamera/5.4.1\r\n\r\n")).
		Server([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 31\r\n\r\n{\"latest\":\"5.4.1\",\"url\":null}  ")).Close()

	// --- phone -> camera: telnet login prompt and HTTP admin page on the LAN --
	b.TCP(homePhone, homeCamera, 51000, 23).Handshake(at(5 * time.Minute)).
		Server([]byte{0xff, 0xfd, 0x01, 0xff, 0xfd, 0x1f}).
		Server([]byte("\r\nIPCAM login: ")).
		Client([]byte("admin\r\n")).
		Server([]byte("Password: ")).Close()
	b.TCP(homePhone, homeCamera, 51001, 80).Handshake(at(6 * time.Minute)).
		Client([]byte("GET /doc/page/login.asp HTTP/1.1\r\nHost: 192.168.50.20\r\nUser-Agent: Mozilla/5.0\r\n\r\n")).
		Server([]byte("HTTP/1.1 200 OK\r\nServer: App-webs/\r\nContent-Type: text/html\r\nContent-Length: 38\r\n\r\n<html><title>Login</title></html>     ")).Close()

	// --- smart plug: MQTT with username/password in cleartext ---------------
	b.TCP(homePlug, remote(plugBroker), 50100, 1883).Handshake(at(60 * time.Second)).
		Client(MQTTConnect("plug-3a4f1c", "plug-user", "synthetic-mqtt-pass")).
		Server([]byte{0x20, 0x02, 0x00, 0x00}).Close()
	b.UDP(at(65*time.Second), homePlug, remote(ntpServer), 123, 123, ntpClientRequest())

	// --- phone: benign modern TLS (negative control) ------------------------
	b.TCP(homePhone, remote(phoneWeb), 52000, 443).Handshake(at(70 * time.Second)).
		Client(TLSClientHello("www.example.com", tls.VersionTLS12, tls.VersionTLS13)).Close()

	// --- DVR: periodic beacon every 60 s ------------------------------------
	for i := 0; i < 50; i++ {
		ts := at(2*time.Minute + time.Duration(i)*time.Minute)
		b.TCP(homeDVR, remote(beaconC2), uint16(53000+i), 8080).Handshake(ts).
			Client([]byte(fmt.Sprintf("GET /bot/ping?id=dvr-5566&seq=%d HTTP/1.1\r\nHost: update.dvr-vendor.test:8080\r\nUser-Agent: Wget\r\n\r\n", i))).
			Server([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")).Close()
	}

	// --- DVR: Mirai-like outbound telnet scanning ---------------------------
	for i := 0; i < 120; i++ {
		target := Host{MAC: homeGateway.MAC, IP: net.IPv4(203, 0, 113, byte(1+i%100)).To4()}
		if i >= 100 {
			target.IP = net.IPv4(198, 51, 100, byte(100+i-100)).To4()
		}
		port := uint16(23)
		if i%5 == 0 {
			port = 2323
		}
		ts := at(30*time.Minute + time.Duration(i)*500*time.Millisecond)
		c := b.TCP(homeDVR, target, uint16(40000+i), port)
		if i%10 == 0 {
			c.SynRst(ts)
		} else {
			c.SynOnly(ts)
		}
	}

	return &Scenario{
		Name:        "home-iot-v1",
		Description: "Synthetic household network: IP camera, smart plug, compromised DVR, smartphone. One hour, generated in code.",
		Start:       start,
		End:         start.Add(time.Hour),
		LocalNet:    "192.168.50.0/24",
		Devices: map[string]string{
			homeCamera.IP.String(): "ip_camera",
			homePlug.IP.String():   "smart_plug",
			homeDVR.IP.String():    "dvr_compromised",
			homePhone.IP.String():  "smartphone",
		},
		Labels:  homeLabels(),
		Builder: b,
	}
}

func homeLabels() []Label {
	cam, plug, dvr, phone := homeCamera.IP.String(), homePlug.IP.String(), homeDVR.IP.String(), homePhone.IP.String()
	return []Label{
		{ID: "L01", DeviceIP: cam, Kind: "weak_tls_version", Visibility: "observable", Description: "Camera offers only TLS 1.0 to its cloud endpoint."},
		{ID: "L02", DeviceIP: cam, Kind: "cleartext_credentials_http", Visibility: "observable", Description: "Camera sends HTTP Basic credentials over plain HTTP."},
		{ID: "L03", DeviceIP: cam, Kind: "cleartext_firmware_update", Visibility: "observable", Description: "Camera checks for firmware over plain HTTP."},
		{ID: "L04", DeviceIP: cam, Kind: "telnet_service_exposed", Visibility: "observable", Description: "Camera runs a Telnet login service reachable on the LAN."},
		{ID: "L05", DeviceIP: cam, Kind: "http_admin_interface", Visibility: "observable", Description: "Camera serves its admin login page over plain HTTP."},
		{ID: "L06", DeviceIP: plug, Kind: "cleartext_credentials_mqtt", Visibility: "observable", Description: "Smart plug sends MQTT username/password without TLS."},
		{ID: "L07", DeviceIP: dvr, Kind: "periodic_beacon", Malicious: true, Visibility: "observable", Description: "DVR contacts the same external host every 60 s (C2-like beacon)."},
		{ID: "L08", DeviceIP: dvr, Kind: "outbound_telnet_scan", Malicious: true, Visibility: "observable", Description: "DVR sends TCP SYNs to 120 external hosts on 23/2323 within 60 s (Mirai-like)."},
		{ID: "L09", DeviceIP: cam, Kind: "known_vulnerable_firmware", Visibility: "hidden", Description: "Camera firmware 5.4.1 is assumed vulnerable in this scenario; only the version string in a User-Agent is visible, the vulnerability itself is not."},
		{ID: "N01", DeviceIP: phone, Kind: "benign_modern_tls", Visibility: "observable", Description: "Negative control: phone uses TLS 1.2/1.3 to a web server; nothing should be flagged."},
	}
}

func ntpClientRequest() []byte {
	p := make([]byte, 48)
	p[0] = 0x23 // LI=0, VN=4, Mode=3 (client)
	return p
}
