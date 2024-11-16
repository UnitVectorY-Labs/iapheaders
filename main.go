package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const jwksIap = "https://www.gstatic.com/iap/verify/public_key-jwk"

// HeaderData holds the necessary header information and statuses
type HeaderData struct {
	UserEmail          string
	UserEmailStatus    string
	UserID             string
	UserIDStatus       string
	JWTAssertion       string
	JWTAssertionStatus string
	JWTPayload         string
	JWTPayloadStatus   string
	OverallStatus      string
	StatusMessage      string
}

func main() {
	port := getEnv("PORT", "8080")

	tpl := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"statusIndicator": statusIndicator,
	}).ParseFiles("templates/index.html"))

	http.HandleFunc("/", homeHandler(tpl))

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}

// getEnv retrieves environment variables with a fallback default
func getEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

// statusIndicator returns an emoji based on the status string
func statusIndicator(status string) string {
	switch status {
	case "good":
		return "🟢"
	case "warning":
		return "🟡"
	case "error":
		return "🔴"
	default:
		return ""
	}
}

// homeHandler generates the HTTP handler with the provided template
func homeHandler(tpl *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		data := HeaderData{
			UserEmail:    r.Header.Get("x-goog-authenticated-user-email"),
			UserID:       r.Header.Get("x-goog-authenticated-user-id"),
			JWTAssertion: r.Header.Get("x-goog-iap-jwt-assertion"),
		}

		// Set statuses based on presence of headers
		data.UserEmailStatus = statusFromBool(data.UserEmail != "")
		data.UserIDStatus = statusFromBool(data.UserID != "")
		data.JWTAssertionStatus = statusFromBool(data.JWTAssertion != "")

		if data.JWTAssertion != "" {
			payload, err := decodeJWTPayload(data.JWTAssertion)
			if err != nil {
				data.JWTPayloadStatus = "warning"
				data.StatusMessage = appendMessage(data.StatusMessage, fmt.Sprintf("JWT Decode Error: %v", err))
			} else {
				data.JWTPayload = payload
				data.JWTPayloadStatus = "good"
			}

			if _, err := validateIAPJWT(data.JWTAssertion); err != nil {
				data.JWTAssertionStatus = "warning"
				data.StatusMessage = appendMessage(data.StatusMessage, fmt.Sprintf("JWT Validation Error: %v", err))
			}
		} else {
			data.JWTAssertionStatus = "error"
		}

		// Determine overall status
		data.OverallStatus, data.StatusMessage = determineOverallStatus(data)

		// Render template
		if err := tpl.Execute(w, data); err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}
	}
}

// statusFromBool returns "good" if true, else "error"
func statusFromBool(ok bool) string {
	if ok {
		return "good"
	}
	return "error"
}

// appendMessage appends a new message to the existing status message
func appendMessage(existing, newMsg string) string {
	if existing != "" {
		return existing + "\n" + newMsg
	}
	return newMsg
}

// determineOverallStatus computes the overall status and message based on individual statuses
func determineOverallStatus(data HeaderData) (string, string) {
	if data.UserEmailStatus == "good" && data.UserIDStatus == "good" &&
		data.JWTAssertionStatus == "good" && data.JWTPayloadStatus == "good" {
		if data.StatusMessage == "" {
			data.StatusMessage = "All headers are valid and JWT is verified."
		}
		return "good", data.StatusMessage
	}

	if data.UserEmailStatus == "error" && data.UserIDStatus == "error" &&
		data.JWTAssertionStatus == "error" {
		return "error", "IAP appears to be disabled - no IAP headers detected."
	}

	if data.StatusMessage == "" {
		data.StatusMessage = "Some headers are missing or invalid."
	}
	return "warning", data.StatusMessage
}

// validateIAPJWT validates the JWT using the IAP JWKS
func validateIAPJWT(token string) (jwt.Token, error) {
	keySet, err := jwk.Fetch(context.Background(), jwksIap)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return jwt.ParseString(token, jwt.WithKeySet(keySet))
}

// decodeJWTPayload decodes and pretty-prints the JWT payload
func decodeJWTPayload(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode payload: %w", err)
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, payload, "", "  "); err != nil {
		return "", fmt.Errorf("failed to pretty print JSON: %w", err)
	}

	return prettyJSON.String(), nil
}
