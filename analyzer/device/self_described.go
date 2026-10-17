package device

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Category inference from what the device says about itself.
//
// Destination names (the clouds a device talks to) were the main category
// signal and were wrong three times in four on the UNSW devices (C1): hubs,
// assistants and phones contact partner clouds, and one vendor cloud serves
// cameras and plugs alike. The device's own announcements are better
// evidence. Only protocol-defined vocabularies and generic words are used
// here, never product names, so the rules are not fitted to one dataset:
//
//   - protocol-defined types: the HomeKit accessory category (ci= in the
//     _hap._tcp TXT record, HomeKit Accessory Protocol "Accessory
//     Categories"), the UPnP device type in SSDP NT/USN (standard types and
//     a few vendor-defined ones, upnpVendorTypes), and mDNS service
//     types with a fixed meaning (_rtsp._tcp: video streaming; printing
//     services);
//   - generic words in names the device chose (DHCP host name, mDNS
//     instance and host names, DHCP vendor class): cam, plug, bulb, ...;
//   - markers of general-purpose computers (phones, laptops) and of
//     routers and printers, which get no IoT category at all.

// selfDescription is the result: Category is empty when the device does not
// describe itself; NotIoT is set for computers, routers and printers.
type selfDescription struct {
	Category string
	Level    string // "protocol" | "name"
	Agree    bool   // a protocol-defined type and a name word agree
	// Conflict: the device also announced a router/printer type; embedded
	// UPnP stacks (miniupnpd) announce InternetGatewayDevice by default, so
	// the IoT category is kept with lower confidence.
	Conflict string
	NotIoT   string // reason, when the device is not an IoT device
	Reasons  []string
}

// homeKitCategories maps HomeKit accessory category identifiers to Quarant
// categories. Identifiers without a clear counterpart are left out.
var homeKitCategories = map[int]string{
	2: "Hub",                                                                          // bridge
	3: "Appliance", 9: "Appliance", 19: "Appliance", 20: "Appliance", 21: "Appliance", // fan, thermostat, air purifier, heater, air conditioner
	22: "Appliance", 23: "Appliance", // humidifier, dehumidifier
	5: "Controller", 7: "Controller", 8: "Controller", 15: "Controller", // lightbulb, outlet, switch, programmable switch
	10: "Sensor",
	17: "Camera", 18: "Camera", // IP camera, video doorbell
}

// upnpStandardTypes maps standard UPnP device types (urn:schemas-upnp-org).
var upnpStandardTypes = map[string]string{
	"digitalsecuritycamera": "Camera",
	"binarylight":           "Controller",
	"dimmablelight":         "Controller",
	"hvac_system":           "Appliance",
}

// upnpVendorTypes maps device types that a vendor defines in its own UPnP
// namespace (urn:<vendor>:device:<type>), where the type word is the
// vendor's vocabulary rather than a generic word. These are protocol
// vocabularies, not product names: every WeMo plug announces "controllee"
// whatever its model. Belkin WeMo: controllee (plug/switch), lightswitch,
// insight (plug with metering), dimmer, bridge (WeMo Link). The sensor type
// is already a generic word.
var upnpVendorTypes = map[string]map[string]string{
	"belkin": {"controllee": "Controller", "lightswitch": "Controller", "insight": "Controller", "dimmer": "Controller", "bridge": "Hub"},
}

var upnpNotIoT = map[string]string{
	"internetgatewaydevice": "router (UPnP InternetGatewayDevice)",
	"wandevice":             "router (UPnP WANDevice)",
	"printer":               "printer (UPnP Printer)",
}

// nameWords are generic words that name a device class. A word counts only
// as a whole token of a name the device announced.
var nameWords = map[string]string{
	"cam": "Camera", "camera": "Camera", "ipcam": "Camera", "webcam": "Camera", "doorbell": "Camera", "nvr": "Camera", "dvr": "Camera",
	"plug": "Controller", "smartplug": "Controller", "outlet": "Controller", "switch": "Controller", "bulb": "Controller",
	"lamp": "Controller", "light": "Controller", "lightswitch": "Controller", "dimmer": "Controller", "relay": "Controller",
	"sensor": "Sensor", "smoke": "Sensor", "motion": "Sensor", "weather": "Sensor", "leak": "Sensor",
	"hub": "Hub", "bridge": "Hub",
	"echo": "VoiceAssistant", "alexa": "VoiceAssistant", "homepod": "VoiceAssistant",
	"thermostat": "Appliance", "fridge": "Appliance", "washer": "Appliance", "aircon": "Appliance",
	"watch": "Wearable", "fitbit": "Wearable",
}

var (
	computerHostRe = regexp.MustCompile(`(?i)(^android[-_]|iphone|ipad|macbook|-mbp$|^desktop-|^laptop-|-pc$|^win-)`)
	computerTXTRe  = regexp.MustCompile(`(?i)^model=(macbook|imac|macmini|macpro|iphone|ipad)`)
	upnpTypeRe     = regexp.MustCompile(`(?i)urn:([a-z0-9.-]+):device:([a-z0-9_-]+):\d+`)
	tokenRe        = regexp.MustCompile(`[a-z0-9]+`)
)

var printerServices = map[string]bool{"_ipp._tcp.local": true, "_ipps._tcp.local": true, "_printer._tcp.local": true, "_pdl-datastream._tcp.local": true}
var computerServices = map[string]bool{"_rfb._tcp.local": true, "_companion-link._tcp.local": true}

// describeSelf evaluates the device's own announcements.
func describeSelf(p *DeviceProfile) selfDescription {
	var s selfDescription
	if p == nil {
		return s
	}
	ev := p.IdentityEvidenceList()
	protocol := map[string][]string{} // category -> reasons
	names := map[string][]string{}
	// weakNotIoT: router/printer types, which embedded software can
	// announce on an IoT device; computer markers set s.NotIoT directly.
	weakNotIoT := ""
	hasHAP := false
	for _, e := range ev {
		if e.Attribute == "mdns_service" && strings.EqualFold(e.Value, "_hap._tcp.local") {
			hasHAP = true
		}
	}
	for _, e := range ev {
		v := strings.TrimSpace(e.Value)
		lv := strings.ToLower(v)
		switch e.Attribute {
		case "hostname":
			if computerHostRe.MatchString(v) {
				s.NotIoT = "general-purpose computer (host name " + v + ")"
			}
			addNameWords(names, lv, "host name "+v)
		case "mdns_instance":
			addNameWords(names, lv, "mDNS name "+v)
		case "dhcp_vendor_class":
			if strings.HasPrefix(lv, "msft") || strings.HasPrefix(lv, "android-dhcp") {
				s.NotIoT = "general-purpose computer (DHCP vendor class " + v + ")"
			}
			addNameWords(names, lv, "DHCP vendor class "+v)
		case "mdns_txt":
			if computerTXTRe.MatchString(v) {
				s.NotIoT = "general-purpose computer (mDNS " + v + ")"
			}
			if hasHAP {
				for _, kv := range strings.Fields(v) {
					if n, ok := strings.CutPrefix(kv, "ci="); ok {
						if id, err := strconv.Atoi(n); err == nil {
							if c := homeKitCategories[id]; c != "" {
								protocol[c] = append(protocol[c], "HomeKit accessory category ci="+n)
							}
						}
					}
				}
			}
		case "mdns_service":
			switch {
			case lv == "_rtsp._tcp.local":
				protocol["Camera"] = append(protocol["Camera"], "mDNS service _rtsp._tcp (video streaming)")
			case printerServices[lv]:
				weakNotIoT = "printer (mDNS " + v + ")"
			case computerServices[lv]:
				s.NotIoT = "general-purpose computer (mDNS " + v + ")"
			}
		case "ssdp_device_type":
			if m := upnpTypeRe.FindStringSubmatch(v); m != nil {
				domain, typ := strings.ToLower(m[1]), strings.ToLower(m[2])
				if domain == "schemas-upnp-org" {
					if c := upnpStandardTypes[typ]; c != "" {
						protocol[c] = append(protocol[c], "UPnP device type "+m[0])
					}
					if r := upnpNotIoT[typ]; r != "" {
						weakNotIoT = r
					}
				} else if c := upnpVendorTypes[domain][typ]; c != "" {
					protocol[c] = append(protocol[c], "UPnP device type "+m[0])
				} else {
					// Other vendor device types: only generic words count.
					addNameWords(protocol, typ, "UPnP device type "+m[0])
				}
			}
		case "ssdp_server", "ssdp_search_agent":
			if strings.Contains(lv, "windows") || strings.Contains(lv, "mac os x") {
				s.NotIoT = "general-purpose computer (SSDP " + v + ")"
			}
		}
	}
	if s.NotIoT != "" {
		return s
	}
	pc, pr := single(protocol)
	nc, nr := single(names)
	switch {
	case pc != "":
		s.Category, s.Level, s.Reasons = pc, "protocol", pr
		if nc == pc {
			s.Agree = true
			s.Reasons = append(s.Reasons, nr...)
		}
	case nc != "" && len(protocol) == 0:
		s.Category, s.Level, s.Reasons = nc, "name", nr
	}
	if weakNotIoT != "" {
		if s.Category == "" {
			s.NotIoT = weakNotIoT
		} else {
			s.Conflict = weakNotIoT
			s.Reasons = append(s.Reasons, "also announced: "+weakNotIoT)
		}
	}
	return s
}

// addNameWords records the categories of generic words found as whole
// tokens of a name.
func addNameWords(into map[string][]string, name, reason string) {
	for _, t := range tokenRe.FindAllString(strings.ToLower(name), -1) {
		if c := nameWords[t]; c != "" {
			into[c] = append(into[c], reason)
		}
	}
}

// single returns the category when exactly one is supported; conflicting
// self-descriptions give none.
func single(m map[string][]string) (string, []string) {
	if len(m) != 1 {
		return "", nil
	}
	for c, r := range m {
		sort.Strings(r)
		return c, dedupe(r)
	}
	return "", nil
}

func dedupe(in []string) []string {
	out := in[:0]
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}
