package device

import (
	"testing"
	"time"
)

func profileWith(evidence ...[2]string) *DeviceProfile {
	p := &DeviceProfile{IP: "192.168.1.50"}
	now := time.Date(2026, 9, 26, 10, 0, 0, 0, time.UTC)
	for _, e := range evidence {
		p.AddIdentityEvidence(now, e[0], e[1], "observed", "test")
	}
	return p
}

func TestDescribeSelf(t *testing.T) {
	cases := []struct {
		name     string
		evidence [][2]string
		category string
		level    string
		notIoT   bool
	}{
		{"homekit outlet", [][2]string{{"mdns_service", "_hap._tcp.local"}, {"mdns_txt", "c#=1 ci=7 ff=1"}}, "Controller", "protocol", false},
		{"homekit category needs the HAP service", [][2]string{{"mdns_txt", "ci=7"}}, "", "", false},
		{"rtsp service", [][2]string{{"mdns_service", "_rtsp._tcp.local"}}, "Camera", "protocol", false},
		{"standard upnp camera", [][2]string{{"ssdp_device_type", "urn:schemas-upnp-org:device:DigitalSecurityCamera:1"}}, "Camera", "protocol", false},
		{"vendor upnp type with a generic word", [][2]string{{"ssdp_device_type", "urn:Example:device:sensor:1"}}, "Sensor", "protocol", false},
		{"vendor upnp type without a generic word", [][2]string{{"ssdp_device_type", "urn:Example:device:controllee:1"}}, "", "", false},
		{"known vendor upnp type", [][2]string{{"ssdp_device_type", "urn:Belkin:device:controllee:1"}}, "Controller", "protocol", false},
		{"generic word in host name", [][2]string{{"hostname", "Little Cam"}}, "Camera", "name", false},
		{"word must be a whole token", [][2]string{{"hostname", "camelot-01"}}, "", "", false},
		{"conflicting names give none", [][2]string{{"hostname", "cam-plug"}}, "", "", false},
		{"protocol wins over a conflicting name", [][2]string{{"mdns_service", "_rtsp._tcp.local"}, {"hostname", "smartplug"}}, "Camera", "protocol", false},
		{"android phone", [][2]string{{"hostname", "android-26fbc3d28e0130e6"}, {"mdns_service", "_rtsp._tcp.local"}}, "", "", true},
		{"windows pc", [][2]string{{"dhcp_vendor_class", "MSFT 5.0"}}, "", "", true},
		{"mac", [][2]string{{"mdns_txt", "model=MacBookPro11,5 osxvers=15"}}, "", "", true},
		{"printer", [][2]string{{"mdns_service", "_ipp._tcp.local"}, {"hostname", "HPE49BC0"}}, "", "", true},
		{"router", [][2]string{{"ssdp_device_type", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}}, "", "", true},
		// A camera with an embedded miniupnpd announces an IGD too.
		{"camera with embedded IGD", [][2]string{{"mdns_service", "_rtsp._tcp.local"}, {"ssdp_device_type", "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}}, "Camera", "protocol", false},
		{"nothing", [][2]string{{"hostname", "WN3"}}, "", "", false},
	}
	for _, c := range cases {
		s := describeSelf(profileWith(c.evidence...))
		if s.Category != c.category || s.Level != c.level || (s.NotIoT != "") != c.notIoT {
			t.Errorf("%s: got %+v", c.name, s)
		}
	}
}

func TestSelfDescriptionDrivesClassification(t *testing.T) {
	p := profileWith([2]string{"mdns_service", "_hap._tcp.local"}, [2]string{"mdns_txt", "ci=7"}, [2]string{"hostname", "SmartPlug-29D71D"})
	c := p.Classification
	if c.Category != "Controller" || c.ConfidenceLabel != "strong" || c.InferenceSource != InferenceSourceSelf {
		t.Fatalf("classification %+v, want Controller/strong from agreeing HomeKit category and name", c)
	}
	// A phone that talks to a hub vendor's cloud is still not a hub.
	phone := profileWith([2]string{"hostname", "android-537f89cca4c2aac1"})
	phone.Hosts = map[string]bool{"api.smartthings.com": true}
	recomputeDeviceIdentity(phone)
	if got := phone.Classification.NormalizedCategory(); got != "GenericIoT" {
		t.Fatalf("phone classified as %s", got)
	}
}

func TestDestinationOnlyCategoryIsLowConfidence(t *testing.T) {
	p := &DeviceProfile{IP: "192.168.1.60", Hosts: map[string]bool{"aps1-relay.tplinkcloud.com": true}}
	recomputeDeviceIdentity(p)
	if p.Classification.InferenceSource == InferenceSourceKnown && p.Classification.ConfidenceLabel != "low" {
		t.Fatalf("destination-only category labelled %s", p.Classification.ConfidenceLabel)
	}
}
