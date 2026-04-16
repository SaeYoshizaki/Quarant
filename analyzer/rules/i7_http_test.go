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

func TestI7HTTPQuerySessionRequiresSensitiveValueShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"session": {"abc"},
			},
		},
	}

	if _, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx); ok {
		t.Fatal("did not expect short session value to be detected")
	}
}

func TestI7HTTPQuerySessionDetectsJWTValue(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"session": {"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected jwt-like session to be detected")
	}
	if match.Evidence != "session=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}

func TestI7HTTPQueryDeviceIDNeedsIdentifierShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"device_id": {"abc"},
			},
		},
	}

	if _, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx); ok {
		t.Fatal("did not expect weak device_id value to be detected")
	}
}

func TestI7HTTPQueryDeviceIDDetectsIdentifierShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Query: map[string][]string{
				"device_id": {"dev-12345678"},
			},
		},
	}

	match, ok := (&I7HTTPTokenLeakRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected device identifier to be detected")
	}
	if match.Evidence != "device_id=***" {
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

func TestI7HTTPAuthDetectsCustomTokenHeaderByValueShape(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Headers: map[string]string{
				"x-device-token": "AbCdEf1234567890ZYXWVutsrq",
			},
		},
	}

	match, ok := (&I7HTTPAuthRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected custom token header to be detected")
	}
	if match.Evidence != "x-device-token=***" {
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

func TestI7HTTPBodySSIDAloneDoesNotTrigger(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			Body: []byte("ssid=guest"),
		},
	}

	if _, ok := (&I7HTTPBodySecretRule{}).Apply(ctx); ok {
		t.Fatal("did not expect standalone ssid to be detected")
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
			Body:        []byte("<config><serial>SN12345678</serial></config>"),
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

func TestI7HTTPBodyDetectsBase64LikeSession(t *testing.T) {
	ctx := &Context{
		HTTP: &HTTPInfo{
			ContentType: "application/json",
			Body:        []byte(`{"session":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo9"}`),
		},
	}

	match, ok := (&I7HTTPBodySecretRule{}).Apply(ctx)
	if !ok {
		t.Fatal("expected base64-like session to be detected")
	}
	if match.Evidence != "session=***" {
		t.Fatalf("unexpected evidence: %s", match.Evidence)
	}
}
