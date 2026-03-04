package rules

import "encoding/binary"

type TLSClientHelloInfo struct {
	RecordVersion uint16
	ClientVersion uint16
	SNI           string
}

func extractSNI(exts []byte) string {
	for j := 0; j+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[j : j+2])
		l := int(binary.BigEndian.Uint16(exts[j+2 : j+4]))
		j += 4

		if l < 0 || j+l > len(exts) {
			return ""
		}

		body := exts[j : j+l]
		j += l

		if typ != 0 { // server_name extension
			continue
		}

		if len(body) < 2 {
			return ""
		}

		listLen := int(binary.BigEndian.Uint16(body[0:2]))
		if listLen < 0 || 2+listLen > len(body) {
			return ""
		}

		k := 2
		for k+3 <= 2+listLen {
			nameType := body[k]
			k++
			nameLen := int(binary.BigEndian.Uint16(body[k : k+2]))
			k += 2

			if nameLen < 0 || k+nameLen > len(body) {
				return ""
			}

			if nameType == 0 { // host_name
				return string(body[k : k+nameLen])
			}

			k += nameLen
		}
		return ""
	}
	return ""
}

func DetectTLSClientHello(data []byte) (TLSClientHelloInfo, bool) {
	var info TLSClientHelloInfo

	for off := 0; off+5 <= len(data); off++ {
		if data[off] != 22 {
			continue
		}
		recVer := binary.BigEndian.Uint16(data[off+1 : off+3])
		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))

		if recLen <= 0 || off+5+recLen > len(data) {
			continue
		}

		rec := data[off+5 : off+5+recLen]
		if len(rec) < 4 {
			continue
		}

		hsType := rec[0]
		if hsType != 1 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		ch := rec[4 : 4+hsLen]
		if len(ch) < 2+32+1 {
			continue
		}

		info.RecordVersion = recVer
		info.ClientVersion = binary.BigEndian.Uint16(ch[0:2])

		i := 2 + 32
		sidLen := int(ch[i])
		i++
		if i+sidLen > len(ch) {
			continue
		}
		i += sidLen

		if i+2 > len(ch) {
			continue
		}
		csLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
		i += 2
		if csLen < 2 || i+csLen > len(ch) {
			continue
		}
		i += csLen

		if i >= len(ch) {
			return info, true
		}
		cmLen := int(ch[i])
		i++
		if i+cmLen > len(ch) {
			continue
		}
		i += cmLen

		if i == len(ch) {
			return info, true
		}
		if i+2 > len(ch) {
			continue
		}
		extLen := int(binary.BigEndian.Uint16(ch[i : i+2]))
		i += 2
		if extLen < 0 || i+extLen > len(ch) {
			continue
		}
		exts := ch[i : i+extLen]

		info.SNI = extractSNI(exts)
		return info, true
	}

	return info, false
}
