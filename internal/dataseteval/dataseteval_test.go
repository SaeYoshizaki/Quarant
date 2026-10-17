package dataseteval

import (
	"strings"
	"testing"
	"time"

	"quarant/analyzer/device"
)

const iot23New = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\tdet_label\n" +
	"1545403816.9\tC1\t192.168.1.195\t41040\t203.0.113.7\t6667\ttcp\t-\t-\t-\t-\tS0\t-\t-\t0\tS\t1\t60\t0\t0\t-\tMalicious\tC&C\n" +
	"1545403817.9\tC2\t192.168.1.195\t41041\t198.51.100.1\t443\ttcp\t-\t-\t-\t-\tSF\t-\t-\t0\tS\t1\t60\t0\t0\t-\tBenign\t-\n"

const iot23Old = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents   label   detailed-label\n" +
	"1526756261.8\tC3\t192.168.2.5\t40506\t203.0.113.9\t22\ttcp\t-\t-\t-\t-\tS0\t-\t-\t0\tS\t1\t60\t0\t0\t-   Malicious   PartOfAHorizontalPortScan\n"

func TestParseIoT23BothLayouts(t *testing.T) {
	flows, err := ParseIoT23Labels(strings.NewReader(iot23New))
	if err != nil || len(flows) != 2 || flows[0].Label != "Malicious" || flows[0].DetLabel != "C&C" || flows[0].RespP != 6667 {
		t.Fatalf("new layout: %+v err=%v", flows, err)
	}
	flows, err = ParseIoT23Labels(strings.NewReader(iot23Old))
	if err != nil || len(flows) != 1 || flows[0].Label != "Malicious" || flows[0].DetLabel != "PartOfAHorizontalPortScan" {
		t.Fatalf("old layout: %+v err=%v", flows, err)
	}
}

func TestEvaluateIoT23(t *testing.T) {
	flows, _ := ParseIoT23Labels(strings.NewReader(iot23New))
	events := []Event{
		{Type: "PERSISTENT_CONNECTION_ATTEMPTS", DeviceKey: "192.168.1.195", DstIP: "203.0.113.7", DstPort: 6667},
		{Type: "PERIODIC_COMMUNICATION_OBSERVED", DeviceKey: "192.168.1.195", DstIP: "198.51.100.1", DstPort: 443},
	}
	rep := EvaluateIoT23("t", flows, events, "")
	if rep.Host != "192.168.1.195" || len(rep.Classes) != 1 || rep.Classes[0].Outcome != "detected" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if len(rep.BehaviourOutsideLabels) != 1 || !strings.Contains(rep.BehaviourOutsideLabels[0], "198.51.100.1") {
		t.Fatalf("expected the periodic finding toward a benign destination to be listed: %v", rep.BehaviourOutsideLabels)
	}
}

func TestParseUNSWDevices(t *testing.T) {
	devs, err := ParseUNSWDevices(strings.NewReader("List of Devices\t\tMAC ADDRESS\n\nSmart Things \t\td0:52:a8:00:67:5e \tWired\nAndroid Phone\t40:f3:8:ff:1e:da\tWireless\n"))
	if err != nil || len(devs) != 2 || devs[0].Name != "Smart Things" || devs[1].MAC != "40:f3:08:ff:1e:da" || devs[1].Connection != "Wireless" {
		t.Fatalf("unexpected: %+v err=%v", devs, err)
	}
}

func TestEvaluateUNSWAttacks(t *testing.T) {
	ws, _ := parseUNSWAnnotations(strings.NewReader("1000,1600,Arpfeatures,ArpSpoof1L2D\n5000,5600,localIcmp,Localfeatures,TcpSynDevice10L2D\n9000,9600,Arpfeatures,ArpSpoof100L2D\n"), "aa:bb:cc:dd:ee:ff")
	inv := []device.InventorySnapshot{{FirstSeen: time.Unix(0, 0).UTC().Format(time.RFC3339), LastSeen: time.Unix(20000, 0).UTC().Format(time.RFC3339)}}
	events := []Event{
		{TS: time.Unix(1100, 0), Type: "IP_MAC_BINDING_CHANGED"},
		{TS: time.Unix(15000, 0), Type: "IP_MAC_BINDING_CHANGED"},
	}
	rep := EvaluateUNSWAttacks(ws, inv, events, 2*time.Minute)
	var arp, syn *UNSWAttackFamilyResult
	for i := range rep.Families {
		switch rep.Families[i].Family {
		case "ArpSpoof":
			arp = &rep.Families[i]
		case "TcpSynDevice":
			syn = &rep.Families[i]
		}
	}
	if arp == nil || arp.Windows != 2 || arp.Detected != 1 || syn == nil || syn.Outcome != "no_detector" {
		t.Fatalf("unexpected families: %+v", rep.Families)
	}
	if rep.EventsOutsideWindows["IP_MAC_BINDING_CHANGED"] != 1 {
		t.Fatalf("expected one event outside windows: %+v", rep.EventsOutsideWindows)
	}
}
