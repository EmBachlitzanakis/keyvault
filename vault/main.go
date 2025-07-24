package main

import (
	"log"
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
