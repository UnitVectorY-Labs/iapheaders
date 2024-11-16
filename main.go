package main

import (
	"log"
	"net/http"
	"os"
	"text/template"
)

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

		err := tpl.Execute(w, nil)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Printf("Template execution error: %v", err)
		}
	}
}
