// Package synth builds synthetic, fully reproducible PCAP traffic for tests,
// demos and regression evaluation. Nothing here is captured from a real
// network: addresses use RFC 5737 / RFC 1918 ranges and every payload is
// generated in code, so the output can be committed to git safely.
package synth

import (
	"encoding/binary"
	"io"
	"net"
	"sort"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// Packet is one serialized Ethernet frame with its capture timestamp.
type Packet struct {
	Time time.Time
	Data []byte
}

// Builder accumulates packets. Methods never fail on valid input; a
// serialization error indicates a programming error and panics.
type Builder struct {
	packets []Packet
	ipID    uint16
}

func (b *Builder) Packets() []Packet {
	out := append([]Packet(nil), b.packets...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

// WritePCAP writes all packets, sorted by time, as a classic pcap stream.
func (b *Builder) WritePCAP(w io.Writer) error {
	pw := pcapgo.NewWriter(w)
	if err := pw.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return err
	}
	for _, p := range b.Packets() {
		if err := pw.WritePacket(gopacket.CaptureInfo{
			Timestamp:     p.Time,
			CaptureLength: len(p.Data),
			Length:        len(p.Data),
		}, p.Data); err != nil {
			return err
		}
	}
	return nil
}

// Host is an endpoint on the synthetic network.
type Host struct {
	MAC net.HardwareAddr
	IP  net.IP
}

func NewHost(mac, ip string) Host {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		panic(err)
	}
	return Host{MAC: hw, IP: net.ParseIP(ip).To4()}
}

func (b *Builder) add(ts time.Time, ls ...gopacket.SerializableLayer) {
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		panic(err)
	}
	data := append([]byte(nil), buf.Bytes()...)
	b.packets = append(b.packets, Packet{Time: ts, Data: data})
}

func (b *Builder) ipv4(src, dst net.IP, proto layers.IPProtocol) *layers.IPv4 {
	b.ipID++
	return &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Id: b.ipID, Protocol: proto, SrcIP: src, DstIP: dst}
}

func eth(src, dst net.HardwareAddr) *layers.Ethernet {
	return &layers.Ethernet{SrcMAC: src, DstMAC: dst, EthernetType: layers.EthernetTypeIPv4}
}

// UDP emits one UDP datagram.
func (b *Builder) UDP(ts time.Time, src, dst Host, sport, dport uint16, payload []byte) {
	ip := b.ipv4(src.IP, dst.IP, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(sport), DstPort: layers.UDPPort(dport)}
	_ = udp.SetNetworkLayerForChecksum(ip)
	b.add(ts, eth(src.MAC, dst.MAC), ip, udp, gopacket.Payload(payload))
}

// TCPConn models one TCP connection so that sequence numbers stay consistent.
type TCPConn struct {
	b                 *Builder
	client, server    Host
	cport, sport      uint16
	cseq, sseq        uint32
	clientMAC, srvMAC net.HardwareAddr
	lastTime          time.Time
	step              time.Duration
}

// TCP starts a connection. clientMAC/serverMAC are the link-layer addresses
// seen on the wire (for off-LAN servers this is the gateway MAC).
func (b *Builder) TCP(client, server Host, cport, sport uint16) *TCPConn {
	return &TCPConn{
		b: b, client: client, server: server, cport: cport, sport: sport,
		cseq: 1000 + uint32(cport), sseq: 5000 + uint32(sport),
		clientMAC: client.MAC, srvMAC: server.MAC, step: 2 * time.Millisecond,
	}
}

func (c *TCPConn) seg(ts time.Time, fromClient bool, flags func(*layers.TCP), payload []byte) {
	src, dst := c.client, c.server
	sp, dp := c.cport, c.sport
	seq, ack := c.cseq, c.sseq
	smac, dmac := c.clientMAC, c.srvMAC
	if !fromClient {
		src, dst = c.server, c.client
		sp, dp = c.sport, c.cport
		seq, ack = c.sseq, c.cseq
		smac, dmac = c.srvMAC, c.clientMAC
	}
	ip := c.b.ipv4(src.IP, dst.IP, layers.IPProtocolTCP)
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sp), DstPort: layers.TCPPort(dp), Seq: seq, Ack: ack, Window: 64240}
	flags(tcp)
	_ = tcp.SetNetworkLayerForChecksum(ip)
	c.b.add(ts, eth(smac, dmac), ip, tcp, gopacket.Payload(payload))

	adv := uint32(len(payload))
	if tcp.SYN || tcp.FIN {
		adv++
	}
	if fromClient {
		c.cseq += adv
	} else {
		c.sseq += adv
	}
	c.lastTime = ts
}

func (c *TCPConn) next() time.Time {
	return c.lastTime.Add(c.step)
}

// Handshake emits SYN, SYN/ACK, ACK starting at ts.
func (c *TCPConn) Handshake(ts time.Time) *TCPConn {
	c.seg(ts, true, func(t *layers.TCP) { t.SYN = true; t.Ack = 0 }, nil)
	c.seg(c.next(), false, func(t *layers.TCP) { t.SYN = true; t.ACK = true }, nil)
	c.seg(c.next(), true, func(t *layers.TCP) { t.ACK = true }, nil)
	return c
}

// SynOnly emits a single SYN that is never answered (scan / failed connect).
func (c *TCPConn) SynOnly(ts time.Time) {
	c.seg(ts, true, func(t *layers.TCP) { t.SYN = true; t.Ack = 0 }, nil)
}

// SynRst emits a SYN answered by RST/ACK (closed port).
func (c *TCPConn) SynRst(ts time.Time) {
	c.seg(ts, true, func(t *layers.TCP) { t.SYN = true; t.Ack = 0 }, nil)
	c.seg(c.next(), false, func(t *layers.TCP) { t.RST = true; t.ACK = true }, nil)
}

// Client sends data from the client, followed by an ACK from the server.
func (c *TCPConn) Client(payload []byte) *TCPConn {
	c.seg(c.next(), true, func(t *layers.TCP) { t.ACK = true; t.PSH = true }, payload)
	c.seg(c.next(), false, func(t *layers.TCP) { t.ACK = true }, nil)
	return c
}

// Server sends data from the server, followed by an ACK from the client.
func (c *TCPConn) Server(payload []byte) *TCPConn {
	c.seg(c.next(), false, func(t *layers.TCP) { t.ACK = true; t.PSH = true }, payload)
	c.seg(c.next(), true, func(t *layers.TCP) { t.ACK = true }, nil)
	return c
}

// Close emits FIN/ACK from both sides.
func (c *TCPConn) Close() {
	c.seg(c.next(), true, func(t *layers.TCP) { t.FIN = true; t.ACK = true }, nil)
	c.seg(c.next(), false, func(t *layers.TCP) { t.FIN = true; t.ACK = true }, nil)
	c.seg(c.next(), true, func(t *layers.TCP) { t.ACK = true }, nil)
}

// ---- application payload helpers -------------------------------------------

// DNSQuery returns a DNS query message for name (type A).
func DNSQuery(id uint16, name string) []byte {
	return serializeDNS(&layers.DNS{
		ID: id, RD: true, OpCode: layers.DNSOpCodeQuery,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
	})
}

// DNSResponse returns an A-record answer for name.
func DNSResponse(id uint16, name string, addr net.IP) []byte {
	return serializeDNS(&layers.DNS{
		ID: id, QR: true, RD: true, RA: true, OpCode: layers.DNSOpCodeQuery, ResponseCode: layers.DNSResponseCodeNoErr,
		Questions: []layers.DNSQuestion{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN}},
		Answers:   []layers.DNSResourceRecord{{Name: []byte(name), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 300, IP: addr.To4()}},
	})
}

// MDNSAnnounce returns an unsolicited mDNS response advertising a service
// instance with a PTR and a TXT record.
func MDNSAnnounce(service, instance string, txt []string) []byte {
	txts := make([][]byte, 0, len(txt))
	for _, t := range txt {
		txts = append(txts, []byte(t))
	}
	return serializeDNS(&layers.DNS{
		QR: true, AA: true, OpCode: layers.DNSOpCodeQuery,
		Answers: []layers.DNSResourceRecord{
			{Name: []byte(service), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 4500, PTR: []byte(instance + "." + service)},
			{Name: []byte(instance + "." + service), Type: layers.DNSTypeTXT, Class: layers.DNSClassIN, TTL: 4500, TXTs: txts},
		},
	})
}

func serializeDNS(d *layers.DNS) []byte {
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// DHCPOptions describes the client-controlled fields of a DHCP request.
type DHCPOptions struct {
	MsgType      layers.DHCPMsgType
	Hostname     string
	VendorClass  string
	ParamRequest []byte
	RequestedIP  net.IP
	Xid          uint32
}

// DHCPClientMessage returns a BOOTREQUEST payload (DISCOVER/REQUEST).
func DHCPClientMessage(mac net.HardwareAddr, o DHCPOptions) []byte {
	d := &layers.DHCPv4{
		Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6,
		Xid: o.Xid, ClientHWAddr: mac, ClientIP: net.IPv4zero, YourClientIP: net.IPv4zero,
		NextServerIP: net.IPv4zero, RelayAgentIP: net.IPv4zero,
	}
	d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(o.MsgType)}))
	if o.Hostname != "" {
		d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptHostname, []byte(o.Hostname)))
	}
	if o.VendorClass != "" {
		d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptClassID, []byte(o.VendorClass)))
	}
	if len(o.ParamRequest) > 0 {
		d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptParamsRequest, o.ParamRequest))
	}
	if o.RequestedIP != nil {
		d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptRequestIP, o.RequestedIP.To4()))
	}
	d.Options = append(d.Options, layers.NewDHCPOption(layers.DHCPOptEnd, nil))
	buf := gopacket.NewSerializeBuffer()
	if err := d.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		panic(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

// MQTTConnect returns an MQTT 3.1.1 CONNECT packet with optional credentials.
func MQTTConnect(clientID, username, password string) []byte {
	var body []byte
	body = append(body, mqttString("MQTT")...)
	body = append(body, 4) // protocol level 3.1.1
	flags := byte(0x02)    // clean session
	if username != "" {
		flags |= 0x80
	}
	if password != "" {
		flags |= 0x40
	}
	body = append(body, flags, 0x00, 0x3c)
	body = append(body, mqttString(clientID)...)
	if username != "" {
		body = append(body, mqttString(username)...)
	}
	if password != "" {
		body = append(body, mqttString(password)...)
	}
	return append([]byte{0x10, byte(len(body))}, body...)
}

func mqttString(s string) []byte {
	out := make([]byte, 2, 2+len(s))
	binary.BigEndian.PutUint16(out, uint16(len(s)))
	return append(out, s...)
}
