package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"text/template"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Version is the application version, injected at build time via ldflags
var Version = "dev"

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

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
	OverallStatus      string
	StatusMessage      string
}

func main() {
	// Set the build version from the build info if not set by the build system
	if Version == "dev" || Version == "" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
				Version = bi.Main.Version
			}
		}
	}

	port := getEnv("PORT", "8080")

	log.Printf("Starting iapheaders version %s", Version)

	tpl := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"statusIndicator": statusIndicator,
		"version":         func() string { return Version },
	}).ParseFS(templatesFS, "templates/index.html"))

	hideSignatureStr := getEnv("HIDE_SIGNATURE", "false")
	hideSignature := (hideSignatureStr == "true")

	// Serve static files from the embedded "static" directory
	staticContent, err := fs.Sub(staticFS, "static")
	if err != nil {
		log.Fatalf("Failed to create static sub-filesystem: %v", err)
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticContent))))

	// Handle the home page
	http.HandleFunc("/", homeHandler(tpl, hideSignature))

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
func homeHandler(tpl *template.Template, hideSignature bool) http.HandlerFunc {
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

		verifiedUserEmail := false
		verifiedUserId := false

		if data.JWTAssertion != "" {
			payload, email, sub, identitySource, err := decodeJWTPayload(data.JWTAssertion)
			if err != nil {
				data.StatusMessage = appendMessage(data.StatusMessage, fmt.Sprintf("JWT Decode Error: %v", err))
			} else {
				data.JWTPayload = payload
			}

			if _, err := validateIAPJWT(data.JWTAssertion); err != nil {
				data.JWTAssertionStatus = "warning"
				data.StatusMessage = appendMessage(data.StatusMessage, fmt.Sprintf("JWT Validation Error: %v", err))
			}

			if data.JWTAssertionStatus == "good" {
				if identitySource == "GOOGLE" {
					if ("accounts.google.com:" + email) == data.UserEmail {
						verifiedUserEmail = true
					}
				} else if identitySource == "GCIP" {
					if email == data.UserEmail {
						verifiedUserEmail = true
					}
				}

				if sub == data.UserID {
					verifiedUserId = true
				}
			}

			if hideSignature {
				parts := strings.Split(data.JWTAssertion, ".")
				if len(parts) == 3 {
					data.JWTAssertion = parts[0] + "." + parts[1] + ".SIGNATURE_REMOVED_BY_IAPHEADERS"
				}
			}
		} else {
			data.JWTAssertionStatus = "error"
		}

		// Without a JWT, the other headers cannot be verified
		if data.UserEmailStatus == "good" && !verifiedUserEmail {
			data.UserEmailStatus = "warning"
		}
		if data.UserIDStatus == "good" && !verifiedUserId {
			data.UserIDStatus = "warning"
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
		data.JWTAssertionStatus == "good" {
		if data.StatusMessage == "" {
			data.StatusMessage = "All IAP headers are present and the JWT is verified."
		}
		return "good", data.StatusMessage
	}

	if data.UserEmailStatus == "error" && data.UserIDStatus == "error" &&
		data.JWTAssertionStatus == "error" {
		return "error", "IAP appears to be disabled - no IAP headers were detected."
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
func decodeJWTPayload(token string) (string, string, string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", "", "", "", fmt.Errorf("invalid JWT format")
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", "", "", fmt.Errorf("failed to decode payload: %w", err)
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, payload, "", "  "); err != nil {
		return "", "", "", "", fmt.Errorf("failed to pretty-print JSON: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", "", "", fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	email, _ := claims["email"].(string)
	sub, _ := claims["sub"].(string)
	identitySource, _ := claims["identity_source"].(string)

	return prettyJSON.String(), email, sub, identitySource, nil
}
