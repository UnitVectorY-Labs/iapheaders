package main

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDecodeJWTPayload(t *testing.T) {
	payload := `{"email":"user@example.com","sub":"123","identity_source":"GOOGLE","nested":{"x":1}}`
	token := "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
	pretty, email, sub, source, err := decodeJWTPayload(token)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"email\": \"user@example.com\",\n  \"sub\": \"123\",\n  \"identity_source\": \"GOOGLE\",\n  \"nested\": {\n    \"x\": 1\n  }\n}"
	if pretty != want || email != "user@example.com" || sub != "123" || source != "GOOGLE" {
		t.Fatalf("got payload %q, email %q, sub %q, source %q", pretty, email, sub, source)
	}
}

func TestDecodeJWTPayloadRejectsInvalidJSON(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"duplicate claim", `{"email":"one","email":"two"}`},
		{"nested duplicate", `{"nested":{"x":1,"x":2}}`},
		{"invalid UTF-8", "{\"email\":\"\xff\"}"},
		{"malformed JSON", `{"email":`},
		{"multiple values", `{} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := "header." + base64.RawURLEncoding.EncodeToString([]byte(tc.payload)) + ".signature"
			pretty, email, sub, source, err := decodeJWTPayload(token)
			if err == nil || !strings.Contains(err.Error(), "failed to unmarshal JSON") {
				t.Fatalf("expected JSON error, got %v", err)
			}
			if pretty != "" || email != "" || sub != "" || source != "" {
				t.Fatal("invalid payload returned data")
			}
		})
	}
}
