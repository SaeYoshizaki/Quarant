package rules

import (
	"crypto/md5"
	"crypto/x509"
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

type TLSCertificateInfo struct {
	Subject    string
	Issuer     string
	SANs       []string
	SelfSigned bool
}

type TLSServerInfo struct {
	ServerVersion  uint16
	SelectedCipher uint16

	Cert *TLSCertificateInfo
}

func DetectTLSServerHello(data []byte) (*TLSServerInfo, bool) {
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
		if hsType != 2 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		sh := rec[4 : 4+hsLen]
		if len(sh) < 2+32+1 {
			continue
		}

		info := &TLSServerInfo{
			ServerVersion: binary.BigEndian.Uint16(sh[0:2]),
			Cert:          nil,
		}

		i := 2 + 32

		sidLen := int(sh[i])
		i++
		if i+sidLen > len(sh) {
			continue
		}
		i += sidLen

		if i+2 > len(sh) {
			continue
		}
		info.SelectedCipher = binary.BigEndian.Uint16(sh[i : i+2])

		if info.ServerVersion == 0 {
			info.ServerVersion = recVer
		}

		if cert, ok := DetectTLSCertificate(data); ok {
			info.Cert = cert
		}

		return info, true
	}

	return nil, false
}

func DetectTLSCertificate(data []byte) (*TLSCertificateInfo, bool) {
	for off := 0; off+5 <= len(data); off++ {
		if data[off] != 22 {
			continue
		}

		recLen := int(binary.BigEndian.Uint16(data[off+3 : off+5]))
		if recLen <= 0 || off+5+recLen > len(data) {
			continue
		}

		rec := data[off+5 : off+5+recLen]
		if len(rec) < 4 {
			continue
		}

		hsType := rec[0]
		if hsType != 11 {
			continue
		}

		hsLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
		if hsLen <= 0 || 4+hsLen > len(rec) {
			continue
		}

		body := rec[4 : 4+hsLen]
		if len(body) < 3 {
			continue
		}

		certListLen := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
		if certListLen <= 0 || 3+certListLen > len(body) {
			continue
		}

		certs := body[3 : 3+certListLen]
		if len(certs) < 3 {
			continue
		}

		certLen := int(certs[0])<<16 | int(certs[1])<<8 | int(certs[2])
		if certLen <= 0 || 3+certLen > len(certs) {
			continue
		}

		certBytes := certs[3 : 3+certLen]

		parsed, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		info := &TLSCertificateInfo{
			Subject:    parsed.Subject.CommonName,
			Issuer:     parsed.Issuer.CommonName,
			SANs:       append([]string(nil), parsed.DNSNames...),
			SelfSigned: parsed.Subject.String() == parsed.Issuer.String(),
		}

		return info, true
	}

	return nil, false
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
