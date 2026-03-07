package device

import (
	"fmt"
	"strings"

	"quarant/analyzer/rules"
)

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}

func EnrichFromTLS(d *DeviceProfile, info rules.TLSClientHelloInfo) {
	if d.SNIValues == nil {
		d.SNIValues = map[string]bool{}
	}

	if info.SNI != "" {
		d.SNIValues[info.SNI] = true
		d.Evidence = appendUnique(d.Evidence, "SNI="+info.SNI)
	}

	ja3 := rules.BuildJA3Hash(info)
	if ja3 != "" {
		d.JA3 = ja3
		d.Evidence = appendUnique(d.Evidence, "JA3="+ja3)
	}

	inferFromTLS(d, info)
}

func inferFromTLS(d *DeviceProfile, info rules.TLSClientHelloInfo) {
	sni := strings.ToLower(info.SNI)

	if strings.Contains(sni, "hikvision") {
		d.Vendor = "Hikvision"
		d.DeviceType = "IP Camera"
		d.Confidence += 0.4
	}
	if strings.Contains(sni, "tplink") || strings.Contains(sni, "tapo") {
		d.Vendor = "TP-Link"
		d.DeviceType = "IP Camera"
		d.Confidence += 0.4
	}

	_ = fmt.Sprintf
}
