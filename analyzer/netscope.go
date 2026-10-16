package analyzer

import (
	"fmt"
	"net"
	"strings"
)

// LocalNetworks defines which addresses belong to the monitored network.
// Only hosts inside these ranges are tracked as devices; everything else is a
// remote peer. Treating internet servers as "devices" produced false
// new-device notifications and polluted the inventory.
type LocalNetworks struct {
	nets []*net.IPNet
}

// DefaultLocalNetworkCIDRs covers private, link-local and unique-local ranges
// used by home networks.
var DefaultLocalNetworkCIDRs = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

func DefaultLocalNetworks() LocalNetworks {
	ln, err := ParseLocalNetworks(DefaultLocalNetworkCIDRs)
	if err != nil {
		panic(err)
	}
	return ln
}

// ParseLocalNetworks parses CIDR strings (bare addresses are treated as /32 or
// /128). An empty list yields the defaults.
func ParseLocalNetworks(cidrs []string) (LocalNetworks, error) {
	var out LocalNetworks
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "/") {
			if ip := net.ParseIP(raw); ip != nil && ip.To4() != nil {
				raw += "/32"
			} else {
				raw += "/128"
			}
		}
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return LocalNetworks{}, fmt.Errorf("invalid local network %q: %w", raw, err)
		}
		out.nets = append(out.nets, n)
	}
	if len(out.nets) == 0 {
		return DefaultLocalNetworks(), nil
	}
	return out, nil
}

// Contains reports whether ip is a unicast address inside a local range.
// Multicast and broadcast destinations are never devices.
func (l LocalNetworks) Contains(ipStr string) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	nets := l.nets
	if len(nets) == 0 {
		nets = DefaultLocalNetworks().nets
	}
	for _, n := range nets {
		if n.Contains(ip) {
			// The subnet broadcast address is not a device.
			if v4 := ip.To4(); v4 != nil && isSubnetBroadcast(v4, n) {
				return false
			}
			return true
		}
	}
	return false
}

func isSubnetBroadcast(ip net.IP, n *net.IPNet) bool {
	mask := n.Mask
	if len(mask) == net.IPv6len {
		mask = mask[12:]
	}
	if len(mask) != net.IPv4len {
		return false
	}
	ones, _ := net.IPMask(mask).Size()
	if ones >= 31 {
		return false
	}
	for i := 0; i < net.IPv4len; i++ {
		if ip[i]|mask[i] != 0xff {
			return false
		}
	}
	return true
}
