package rules

import "testing"

func TestI7TelnetPlaintextDetectsTelnet(t *testing.T) {
	info, ok := ParseTelnet([]byte{}, []byte("Welcome\r\nlogin: "))
	if !ok {
		t.Fatal("expected telnet stream to parse")
	}

	match, ok := (&I7TelnetPlaintextRule{}).Apply(&Context{Telnet: info})
	if !ok {
		t.Fatal("expected plaintext telnet to be detected")
	}
	if match.Message != "Plaintext Telnet detected" {
		t.Fatalf("unexpected message: %s", match.Message)
	}
}

func TestI7TelnetCredentialsDetectsPasswordExchange(t *testing.T) {
	info, ok := ParseTelnet([]byte("admin\r\nhunter2\r\n"), []byte("login: Password: "))
	if !ok {
		t.Fatal("expected telnet stream to parse")
	}

	match, ok := (&I7TelnetCredentialsRule{}).Apply(&Context{Telnet: info})
	if !ok {
		t.Fatal("expected telnet credential exchange to be detected")
	}
	if match.Evidence != "telnet_password=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7TelnetCredentialsDoesNotDetectPromptOnly(t *testing.T) {
	info, ok := ParseTelnet([]byte{}, []byte("login: Password: "))
	if !ok {
		t.Fatal("expected telnet stream to parse")
	}

	if _, ok := (&I7TelnetCredentialsRule{}).Apply(&Context{Telnet: info}); ok {
		t.Fatal("did not expect prompt-only telnet stream to trigger credentials")
	}
}

func TestI7TelnetPayloadSecretDetectsExplicitToken(t *testing.T) {
	info, ok := ParseTelnet([]byte("set token=AbCdEf1234567890ZYXWVutsrq\r\n"), []byte("$ "))
	if !ok {
		t.Fatal("expected telnet stream to parse")
	}

	match, ok := (&I7TelnetPayloadSecretRule{}).Apply(&Context{Telnet: info})
	if !ok {
		t.Fatal("expected explicit sensitive telnet payload to be detected")
	}
	if match.Evidence != "token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestParseTelnetStripsTelnetOptions(t *testing.T) {
	info, ok := ParseTelnet([]byte{0xff, 0xfd, 0x01, 'a', 'd', 'm', 'i', 'n', '\r', '\n'}, []byte("login: "))
	if !ok {
		t.Fatal("expected telnet stream to parse")
	}
	if !info.ClientSubmitted {
		t.Fatal("expected client text after telnet option negotiation")
	}
}
