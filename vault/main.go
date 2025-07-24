package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ebachlitzanakis/vault/internal/crypto"
	"github.com/ebachlitzanakis/vault/internal/handlers"
	"github.com/ebachlitzanakis/vault/internal/server"
	"github.com/ebachlitzanakis/vault/internal/storage"
)

// Constants for configuration
const (
	dataFilePath = "data.json"
	port         = 8080
)

// IMPORTANT: In a real application, NEVER hardcode the encryption key like this.
// It should be securely managed, e.g., derived from a master password,
// stored in an environment variable, or retrieved from a secure key management system.
var encryptionKey = []byte("thisisasecretkeyforaes256encryp!") // 32 bytes for AES-256

// init ensures the data file exists and loads initial data
func main() {
	// Initialize the data file
	if _, err := os.Stat(dataFilePath); os.IsNotExist(err) {
		log.Printf("Creating empty data file: %s", dataFilePath)
		err := os.WriteFile(dataFilePath, []byte("[]"), 0644)
		if err != nil {
			log.Fatalf("Failed to create data file: %v", err)
		}
	}

	// Initialize components
	encryptor, err := crypto.NewEncryptor(encryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize encryptor: %v", err)
	}

	// Initialize storage
	store := storage.NewStorage(dataFilePath, encryptor)

	// Initialize handlers
	passwordHandler := handlers.NewPasswordHandler(store)

	// Initialize and start server
	srv := server.NewServer(port, passwordHandler)
	log.Fatal(srv.Start())
}

func main() {
	// Serve static files (index.html, etc.)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
			return
		}
		// Serve other static assets if any, though not strictly needed for this example
		http.ServeFile(w, r, r.URL.Path[1:])
	})

	// API endpoints
	http.HandleFunc("/passwords", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getPasswordsHandler(w, r)
		case http.MethodPost:
			addPasswordHandler(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/passwords/", deletePasswordHandler) // For DELETE requests with ID

	port := 8080
	log.Printf("Server starting on :%d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}
