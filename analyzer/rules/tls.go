package rules

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

type TLSClientHelloInfo struct {
	RecordVersion uint16
	ClientVersion uint16
	SNI           string

	CipherSuites    []uint16
	Extensions      []uint16
	SupportedGroups []uint16
	ECPointFormats  []uint8
}

func isGREASE(v uint16) bool {
	return (v&0x0f0f) == 0x0a0a && ((v>>8)&0xff) == (v&0xff)
}

func joinUint16(vals []uint16) string {
	if len(vals) == 0 {
		return ""
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if isGREASE(v) {
			continue
		}
		out = append(out, strconv.Itoa(int(v)))
	}
	return strings.Join(out, "-")
}

func joinUint8(vals []uint8) string {
	if len(vals) == 0 {
		return ""
	}
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, strconv.Itoa(int(v)))
	}
	return strings.Join(out, "-")
}

func BuildJA3String(info TLSClientHelloInfo) string {
	return strings.Join([]string{
		strconv.Itoa(int(info.ClientVersion)),
		joinUint16(info.CipherSuites),
		joinUint16(info.Extensions),
		joinUint16(info.SupportedGroups),
		joinUint8(info.ECPointFormats),
	}, ",")
}

func BuildJA3Hash(info TLSClientHelloInfo) string {
	s := BuildJA3String(info)
	if s == "" {
		return ""
	}
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
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

		if typ != 0 {
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

			if nameType == 0 {
				return string(body[k : k+nameLen])
			}

			k += nameLen
		}
		return ""
	}
	return ""
}

func parseExtensions(exts []byte, info *TLSClientHelloInfo) {
	for j := 0; j+4 <= len(exts); {
		typ := binary.BigEndian.Uint16(exts[j : j+2])
		l := int(binary.BigEndian.Uint16(exts[j+2 : j+4]))
		j += 4

		if l < 0 || j+l > len(exts) {
			return
		}

		body := exts[j : j+l]
		j += l

		info.Extensions = append(info.Extensions, typ)

		switch typ {
		case 10:
			if len(body) < 2 {
				continue
			}
			n := int(binary.BigEndian.Uint16(body[:2]))
			if 2+n > len(body) {
				continue
			}
			for k := 2; k+2 <= 2+n; k += 2 {
				info.SupportedGroups = append(info.SupportedGroups, binary.BigEndian.Uint16(body[k:k+2]))
			}
		case 11:
			if len(body) < 1 {
				continue
			}
			n := int(body[0])
			if 1+n > len(body) {
				continue
			}
			info.ECPointFormats = append(info.ECPointFormats, body[1:1+n]...)
		}
	}
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
		if csLen < 2 || i+csLen > len(ch) || csLen%2 != 0 {
			continue
		}
		for k := i; k < i+csLen; k += 2 {
			info.CipherSuites = append(info.CipherSuites, binary.BigEndian.Uint16(ch[k:k+2]))
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
		parseExtensions(exts, &info)
		return info, true
	}

	return info, false
}