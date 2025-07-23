package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid" // For generating unique IDs
)

// PasswordEntry represents a single entry in the vault
type PasswordEntry struct {
	ID       string `json:"id"`
	Website  string `json:"website"`
	Username string `json:"username"`
	Password string `json:"password"` // This will be encrypted in the JSON file
}

// Global variables for data and encryption key
var (
	dataFilePath = "data.json"
	// IMPORTANT: In a real application, NEVER hardcode the encryption key like this.
	// It should be securely managed, e.g., derived from a master password,
	// stored in an environment variable, or retrieved from a secure key management system.
	// Changed to be exactly 32 bytes (AES-256)
	encryptionKey = []byte("thisisasecretkeyforaes256encryp!") // 32 bytes for AES-256
	dataMutex     sync.Mutex                                   // Mutex to protect data access
)

// init ensures the data file exists and loads initial data
func init() {
	// Check if the encryption key is 32 bytes (AES-256)
	if len(encryptionKey) != 32 {
		log.Fatalf("Encryption key must be 32 bytes for AES-256. Current length: %d", len(encryptionKey))
	}

	// Ensure the data file exists
	if _, err := os.Stat(dataFilePath); os.IsNotExist(err) {
		log.Printf("Creating empty data file: %s", dataFilePath)
		err := ioutil.WriteFile(dataFilePath, []byte("[]"), 0644)
		if err != nil {
			log.Fatalf("Failed to create data file: %v", err)
		}
	}
}

// encrypt encrypts plaintext using AES-GCM
func encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("could not create new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("could not create new GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("could not read nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt decrypts ciphertext using AES-GCM
func decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("could not decode base64: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("could not create new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create new GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt: %w", err)
	}
	return plaintext, nil
}

// loadEntries loads password entries from the JSON file
func loadEntries() ([]PasswordEntry, error) {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	fileBytes, err := ioutil.ReadFile(dataFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read data file: %w", err)
	}

	var entries []PasswordEntry
	if len(fileBytes) == 0 {
		return entries, nil // Return empty slice if file is empty
	}

	err = json.Unmarshal(fileBytes, &entries)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Decrypt passwords for loaded entries
	for i := range entries {
		if entries[i].Password != "" {
			decryptedBytes, err := decrypt(entries[i].Password)
			if err != nil {
				log.Printf("Warning: Failed to decrypt password for entry ID %s: %v", entries[i].ID, err)
				entries[i].Password = "[Decryption Error]" // Indicate error
				continue
			}
			entries[i].Password = string(decryptedBytes)
		}
	}

	return entries, nil
}

// saveEntries saves password entries to the JSON file (passwords are encrypted before saving)
func saveEntries(entries []PasswordEntry) error {
	dataMutex.Lock()
	defer dataMutex.Unlock()

	// Create a copy to encrypt passwords before saving
	entriesToSave := make([]PasswordEntry, len(entries))
	copy(entriesToSave, entries)

	for i := range entriesToSave {
		if entriesToSave[i].Password != "" {
			encrypted, err := encrypt([]byte(entriesToSave[i].Password))
			if err != nil {
				return fmt.Errorf("failed to encrypt password for entry ID %s: %w", entriesToSave[i].ID, err)
			}
			entriesToSave[i].Password = encrypted
		}
	}

	fileBytes, err := json.MarshalIndent(entriesToSave, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	err = ioutil.WriteFile(dataFilePath, fileBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}
	return nil
}

// getPasswordsHandler handles GET requests to retrieve all password entries
func getPasswordsHandler(w http.ResponseWriter, r *http.Request) {
	entries, err := loadEntries()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading entries: %v", err), http.StatusInternalServerError)
		return
	}

	// Render the table rows using HTMX fragments
	w.Header().Set("Content-Type", "text/html")
	for _, entry := range entries {
		fmt.Fprintf(w, `
			<tr id="entry-%s" class="border-b border-gray-700 hover:bg-gray-700">
				<td class="px-4 py-2">%s</td>
				<td class="px-4 py-2">%s</td>
				<td class="px-4 py-2 flex items-center">
					<span id="password-%s" class="mr-2">%s</span>
					<button onclick="copyToClipboard('password-%s')" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-1 px-2 rounded-md text-sm">Copy</button>
				</td>
				<td class="px-4 py-2">
					<button hx-delete="/passwords/%s" hx-target="#entry-%s" hx-swap="outerHTML" class="bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-2 rounded-md text-sm">Delete</button>
				</td>
			</tr>
		`, entry.ID, entry.Website, entry.Username, entry.ID, entry.Password, entry.ID, entry.ID, entry.ID)
	}
}

// addPasswordHandler handles POST requests to add a new password entry
func addPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	website := r.FormValue("website")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if website == "" || username == "" || password == "" {
		http.Error(w, "All fields (website, username, password) are required.", http.StatusBadRequest)
		return
	}

	newEntry := PasswordEntry{
		ID:       uuid.New().String(),
		Website:  website,
		Username: username,
		Password: password, // This will be encrypted by saveEntries
	}

	entries, err := loadEntries()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading entries: %v", err), http.StatusInternalServerError)
		return
	}

	entries = append(entries, newEntry)

	err = saveEntries(entries)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving entries: %v", err), http.StatusInternalServerError)
		return
	}

	// Respond with the new row for HTMX to swap in
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<tr id="entry-%s" class="border-b border-gray-700 hover:bg-gray-700">
			<td class="px-4 py-2">%s</td>
			<td class="px-4 py-2">%s</td>
			<td class="px-4 py-2 flex items-center">
				<span id="password-%s" class="mr-2">%s</span>
				<button onclick="copyToClipboard('password-%s')" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-1 px-2 rounded-md text-sm">Copy</button>
			</td>
			<td class="px-4 py-2">
				<button hx-delete="/passwords/%s" hx-target="#entry-%s" hx-swap="outerHTML" class="bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-2 rounded-md text-sm">Delete</button>
			</td>
		</tr>
	`, newEntry.ID, newEntry.Website, newEntry.Username, newEntry.ID, newEntry.Password, newEntry.ID, newEntry.ID, newEntry.ID)
}

// deletePasswordHandler handles DELETE requests to remove a password entry
func deletePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := filepath.Base(r.URL.Path) // Extract ID from URL path

	entries, err := loadEntries()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading entries: %v", err), http.StatusInternalServerError)
		return
	}

	found := false
	updatedEntries := []PasswordEntry{}
	for _, entry := range entries {
		if entry.ID == id {
			found = true
			continue // Skip this entry to delete it
		}
		updatedEntries = append(updatedEntries, entry)
	}

	if !found {
		http.Error(w, "Entry not found", http.StatusNotFound)
		return
	}

	err = saveEntries(updatedEntries)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving entries: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK) // HTMX expects a 200 OK for successful deletion
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
