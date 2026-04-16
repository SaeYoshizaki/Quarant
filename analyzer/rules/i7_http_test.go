package rules

import "testing"

func TestI7HTTPQueryExpandedKeys(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"refresh_token": {"abc"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected query leak to be detected")
	}
	if match.Evidence != "refresh_token=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPAuthExtendedHeader(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-api-key": "secret-value",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected header leak to be detected")
	}
	if match.Evidence != "X-Api-Key: ***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPBodyInfersFormWithoutContentType(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Body: []byte("ssid=mywifi&psk=supersecret"),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected inferred form body leak to be detected")
	}
	if match.Evidence != "ssid=***" && match.Evidence != "psk=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPBodyDetectsMultipartSecrets(t *testing.T) {
	body := []byte("--boundary\r\nContent-Disposition: form-data; name=\"mqtt_pass\"\r\n\r\nhunter2\r\n--boundary--\r\n")
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "multipart/form-data",
			Body:        body,
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected multipart body leak to be detected")
	}
	if match.Evidence != "mqtt_pass=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPBodyDetectsXMLSecrets(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "application/xml",
			Body:        []byte("<config><serial>123456</serial></config>"),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected xml body leak to be detected")
	}
	if match.Evidence != "serial=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}
