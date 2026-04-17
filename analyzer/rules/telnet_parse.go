package rules

import "strings"

type TelnetInfo struct {
	Plaintext         bool
	LoginPrompt       bool
	UsernamePrompt    bool
	PasswordPrompt    bool
	ClientSubmitted   bool
	SensitiveEvidence string
}

func ParseTelnet(clientData, serverData []byte) (*TelnetInfo, bool) {
	if len(clientData) == 0 && len(serverData) == 0 {
		return nil, false
	}

	serverText := strings.ToLower(string(stripTelnetCommands(serverData)))
	clientText := stripTelnetCommands(clientData)
	info := &TelnetInfo{
		Plaintext:       true,
		LoginPrompt:     strings.Contains(serverText, "login:"),
		UsernamePrompt:  strings.Contains(serverText, "username:"),
		PasswordPrompt:  strings.Contains(serverText, "password:"),
		ClientSubmitted: hasTelnetClientText(clientText),
	}

	if ev, ok := DetectSensitiveTextBody(clientText); ok {
		info.SensitiveEvidence = ev
	}

	return info, true
}

func stripTelnetCommands(data []byte) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); i++ {
		if data[i] != 0xff {
			out = append(out, data[i])
			continue
		}
		if i+1 >= len(data) {
			break
		}
		cmd := data[i+1]
		i++
		switch cmd {
		case 0xff:
			out = append(out, 0xff)
		case 0xfa:
			for i+1 < len(data) {
				i++
				if data[i] == 0xff && i+1 < len(data) && data[i+1] == 0xf0 {
					i++
					break
				}
			}
		case 0xfb, 0xfc, 0xfd, 0xfe:
			if i+1 < len(data) {
				i++
			}
		}
	}
	return out
}

func hasTelnetClientText(data []byte) bool {
	count := 0
	for _, b := range data {
		if b >= 0x21 && b <= 0x7e {
			count++
			if count >= 2 {
				return true
			}
			continue
		}
		if b == '\r' || b == '\n' || b == '\t' || b == ' ' {
			continue
		}
	}
	return false
}
