package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type HeaderData struct {
	Status       string
	UserEmail    string
	UserID       string
	JWTAssertion string
	JWTPayload   string
}

func main() {
	// Read in PORT envirionment variable and default to 8080
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Load the HTML template
	tpl := template.Must(template.ParseFiles("templates/index.html"))

	// Set up HTTP handlers
	http.HandleFunc("/", getHomeHandler(tpl))

	// Start the server
	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Could not start server: %v", err)
	}
}

// serveHome renders the main HTML page
func getHomeHandler(tpl *template.Template) http.HandlerFunc {
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

		// Check if IAP appears to be completely disabled
		if data.UserEmail == "" && data.UserID == "" && data.JWTAssertion == "" {
			data.Status = "IAP appears to be disabled - no IAP headers detected"
			tpl.Execute(w, data)
			return
		}

		// Only validate JWT if it exists
		if data.JWTAssertion != "" {
			token, err := validateIAPJWT(data.JWTAssertion)
			if err != nil {
				data.Status = fmt.Sprintf("JWT Validation Error: %v", err)
			} else {
				claimsJSON, err := json.MarshalIndent(token, "", "  ")
				if err != nil {
					data.Status = "Error decoding JWT payload"
				} else {
					data.JWTPayload = string(claimsJSON)
					data.Status = "JWT signature validated successfully"
				}
			}
		}

		// Always show the template with whatever data we have
		err := tpl.Execute(w, data)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}
	}
}

func validateIAPJWT(jwtToken string) (jwt.Token, error) {
	keySet, err := jwk.Fetch(context.Background(), "https://www.gstatic.com/iap/verify/public_key-jwk")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %v", err)
	}

	token, err := jwt.ParseString(jwtToken, jwt.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("failed to validate JWT: %v", err)
	}

	return token, nil
}
