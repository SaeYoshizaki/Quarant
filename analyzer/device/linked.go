package device

import (
	"net"
	"sort"
	"strings"
	"time"
)

// Self-descriptions belong to the interface (MAC), not to an address.
//
// Profiles are kept per IP, so one device appears as several profiles: its
// IPv4 address, its IPv6 link-local address, a 169.254.x address while DHCP
// is pending. A device announces itself (DHCP, mDNS, SSDP) from only some of
// them, and only now and then (mDNS at boot, DHCP at lease renewal). On the
// UNSW traces this split one camera's _rtsp._tcp announcement from its IPv4
// profile and left it uncategorised on most days (C2). Profiles bound to the
// same MAC therefore share their self-descriptions through a linkedIdentity.
//
// The shared record can also be saved and loaded (identity state), so that a
// monitor that is restarted, or a capture analysed day by day, keeps what a
// device said about itself earlier. Shared and earlier entries are marked in
// IdentityEvidence.Via so that every category reason stays traceable.
//
// One MAC can stand for several hosts behind a bridge or a Wi-Fi repeater
// doing MAC translation. Sharing stops for a MAC once its IPv4 address
// alternates (A, then B, then A again): a one-way change is DHCP
// renumbering, alternation means two hosts.

// sharedIdentityAttributes are the self-describing attributes shared
// between profiles with the same MAC.
var sharedIdentityAttributes = map[string]bool{
	"hostname": true, "mdns_instance": true, "mdns_service": true, "mdns_txt": true,
	"dhcp_vendor_class": true, "dhcp_param_request_list": true,
	"ssdp_device_type": true, "ssdp_server": true, "ssdp_search_agent": true,
}

// Values of IdentityEvidence.Via.
const (
	ViaSameMAC        = "same_mac"        // announced from another address of the same MAC in this capture
	ViaEarlierCapture = "earlier_capture" // loaded from the identity state of an earlier capture
)

type linkedIdentity struct {
	mac       string
	hints     map[string]*identityHint
	members   map[*DeviceProfile]bool
	seenIPv4  map[string]bool
	lastIPv4  string
	ambiguous bool
}

func newLinkedIdentity(mac string) *linkedIdentity {
	return &linkedIdentity{
		mac:      mac,
		hints:    map[string]*identityHint{},
		members:  map[*DeviceProfile]bool{},
		seenIPv4: map[string]bool{},
	}
}

// merge adds one hint and reports whether it was new; fromState marks
// hints loaded from an earlier capture until they are seen again.
func (l *linkedIdentity) merge(key string, h *identityHint, count int, fromState bool) bool {
	if cur, ok := l.hints[key]; ok {
		cur.evidence.Count += count
		if h.firstSeen.Before(cur.firstSeen) {
			cur.firstSeen = h.firstSeen
		}
		if h.lastSeen.After(cur.lastSeen) {
			cur.lastSeen = h.lastSeen
		}
		if !fromState && cur.fromState {
			cur.fromState = false
			return true
		}
		return false
	}
	if len(l.hints) >= maxIdentityEvidence {
		return false
	}
	e := h.evidence
	e.Count = count
	l.hints[key] = &identityHint{evidence: e, firstSeen: h.firstSeen, lastSeen: h.lastSeen, fromState: fromState}
	return true
}

func (l *linkedIdentity) recomputeMembers() {
	for m := range l.members {
		recomputeDeviceIdentity(m)
	}
}

// observeIPv4 tracks the MAC's IPv4 addresses and reports whether the MAC
// just became ambiguous.
func (l *linkedIdentity) observeIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil || parsed.IsLinkLocalUnicast() || ip == l.lastIPv4 {
		return false
	}
	alternated := l.seenIPv4[ip]
	l.seenIPv4[ip] = true
	l.lastIPv4 = ip
	if alternated && !l.ambiguous {
		l.ambiguous = true
		return true
	}
	return false
}

// LinkMAC binds the profile to the shared identity of mac. It is cheap when
// the binding is unchanged, since it runs for every packet with a local
// source.
func (s *Store) LinkMAC(p *DeviceProfile, mac string) {
	mac = strings.ToLower(strings.TrimSpace(mac))
	if s == nil || p == nil || mac == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	l := p.linked
	if l == nil || l.mac != mac {
		if l != nil {
			delete(l.members, p)
		}
		if s.macs == nil {
			s.macs = map[string]*linkedIdentity{}
		}
		l = s.macs[mac]
		if l == nil {
			l = newLinkedIdentity(mac)
			s.macs[mac] = l
		}
		l.members[p] = true
		p.linked = l
		for key, h := range p.IdentityHints {
			if sharedIdentityAttributes[h.evidence.Attribute] {
				l.merge(key, h, h.evidence.Count, false)
			}
		}
		l.observeIPv4(p.IP)
		l.recomputeMembers()
		return
	}
	if l.observeIPv4(p.IP) {
		l.recomputeMembers()
	}
}

// shareIdentityHint passes a newly recorded self-description to the other
// profiles of the same MAC.
func (p *DeviceProfile) shareIdentityHint(key string, h *identityHint) {
	l := p.linked
	if l == nil || !sharedIdentityAttributes[h.evidence.Attribute] {
		return
	}
	single := &identityHint{evidence: h.evidence, firstSeen: h.lastSeen, lastSeen: h.lastSeen}
	if !l.merge(key, single, 1, false) || l.ambiguous {
		return
	}
	for m := range l.members {
		if m != p {
			recomputeDeviceIdentity(m)
		}
	}
}

// linkedEvidence returns the shared hints this profile did not record
// itself, marked with Via.
func (p *DeviceProfile) linkedEvidence() []IdentityEvidence {
	l := p.linked
	if l == nil || l.ambiguous {
		return nil
	}
	var out []IdentityEvidence
	for key, h := range l.hints {
		if _, own := p.IdentityHints[key]; own {
			continue
		}
		e := h.evidence
		e.FirstSeen = formatSnapshotTime(h.firstSeen)
		e.LastSeen = formatSnapshotTime(h.lastSeen)
		e.Via = ViaSameMAC
		if h.fromState {
			e.Via = ViaEarlierCapture
		}
		out = append(out, e)
	}
	return out
}

// IdentityState is the saved form of the per-MAC self-descriptions.
type IdentityState struct {
	Version int                           `json:"version"`
	Devices map[string][]IdentityEvidence `json:"devices"`
}

const identityStateVersion = 1

// ExportIdentityState returns the self-descriptions of every MAC whose
// sharing is still unambiguous.
func (s *Store) ExportIdentityState() IdentityState {
	state := IdentityState{Version: identityStateVersion, Devices: map[string][]IdentityEvidence{}}
	if s == nil {
		return state
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for mac, l := range s.macs {
		if l.ambiguous || len(l.hints) == 0 {
			continue
		}
		list := make([]IdentityEvidence, 0, len(l.hints))
		for _, h := range l.hints {
			e := h.evidence
			e.FirstSeen = formatSnapshotTime(h.firstSeen)
			e.LastSeen = formatSnapshotTime(h.lastSeen)
			e.Via = ""
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.Attribute != b.Attribute {
				return a.Attribute < b.Attribute
			}
			if a.Source != b.Source {
				return a.Source < b.Source
			}
			return a.Value < b.Value
		})
		state.Devices[mac] = list
	}
	return state
}

// ImportIdentityState loads self-descriptions saved from earlier captures.
// It must be called before the first packet.
func (s *Store) ImportIdentityState(state IdentityState) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.macs == nil {
		s.macs = map[string]*linkedIdentity{}
	}
	for mac, list := range state.Devices {
		mac = strings.ToLower(strings.TrimSpace(mac))
		if mac == "" {
			continue
		}
		l := s.macs[mac]
		if l == nil {
			l = newLinkedIdentity(mac)
			s.macs[mac] = l
		}
		for _, e := range list {
			if !sharedIdentityAttributes[e.Attribute] || strings.TrimSpace(e.Value) == "" {
				continue
			}
			first, _ := time.Parse(time.RFC3339, e.FirstSeen)
			last, _ := time.Parse(time.RFC3339, e.LastSeen)
			e.Via = ""
			h := &identityHint{evidence: e, firstSeen: first, lastSeen: last}
			count := e.Count
			if count < 1 {
				count = 1
			}
			l.merge(e.Attribute+"|"+e.Source+"|"+e.Value, h, count, true)
		}
	}
}
