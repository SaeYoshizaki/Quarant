package reportapi

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

func itoaUint16(value uint16) string {
	return strconv.FormatUint(uint64(value), 10)
}

func earlierTime(a, b string) bool {
	at, aok := parseRFC3339(a)
	bt, bok := parseRFC3339(b)
	if !aok {
		return false
	}
	if !bok {
		return true
	}
	return at.Before(bt)
}

func laterTime(a, b string) bool {
	at, aok := parseRFC3339(a)
	bt, bok := parseRFC3339(b)
	if !aok {
		return false
	}
	if !bok {
		return true
	}
	return at.After(bt)
}

func parseRFC3339(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return t, true
	}
	t, err = time.Parse(time.RFC3339, value)
	if err == nil {
		return t, true
	}
	return time.Time{}, false
}

func observeTimestampBounds(device *InventoryDevice, ts time.Time) {
	if device == nil || ts.IsZero() {
		return
	}
	value := ts.UTC().Format(time.RFC3339)
	if device.FirstSeen == "" || earlierTime(value, device.FirstSeen) {
		device.FirstSeen = value
	}
	if device.LastSeen == "" || laterTime(value, device.LastSeen) {
		device.LastSeen = value
	}
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		set[value] = true
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func uniqueSortedPorts(values []uint16) []uint16 {
	set := map[uint16]bool{}
	for _, value := range values {
		if value == 0 {
			continue
		}
		set[value] = true
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]uint16, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func cloneStringIntMap(src map[string]int) map[string]int {
	if len(src) == 0 {
		return map[string]int{}
	}
	dst := make(map[string]int, len(src))
	for key, value := range src {
		dst[key] = value
	}
	return dst
}

func sortInventoryDevices(devices []InventoryDevice) {
	sort.SliceStable(devices, func(i, j int) bool {
		if devices[i].IP == devices[j].IP {
			return devices[i].LastSeen > devices[j].LastSeen
		}
		return devices[i].IP < devices[j].IP
	})
}
