package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"sync"

	"github.com/ebachlitzanakis/vault/internal/crypto"
	"github.com/ebachlitzanakis/vault/internal/models"
)

type Storage struct {
	filePath  string
	encryptor *crypto.Encryptor
	mutex     sync.Mutex
}

func NewStorage(filePath string, encryptor *crypto.Encryptor) *Storage {
	return &Storage{
		filePath:  filePath,
		encryptor: encryptor,
	}
}

// LoadEntries loads password entries from the JSON file
func (s *Storage) LoadEntries() ([]models.PasswordEntry, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	fileBytes, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read data file: %w", err)
	}

	var entries []models.PasswordEntry
	if len(fileBytes) == 0 {
		return entries, nil
	}

	err = json.Unmarshal(fileBytes, &entries)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	// Decrypt passwords for loaded entries
	for i := range entries {
		if entries[i].Password != "" {
			decryptedBytes, err := s.encryptor.Decrypt(entries[i].Password)
			if err != nil {
				log.Printf("Warning: Failed to decrypt password for entry ID %s: %v", entries[i].ID, err)
				entries[i].Password = "[Decryption Error]"
				continue
			}
			entries[i].Password = string(decryptedBytes)
		}
	}

	return entries, nil
}

// SaveEntries saves password entries to the JSON file (passwords are encrypted before saving)
func (s *Storage) SaveEntries(entries []models.PasswordEntry) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Create a copy to encrypt passwords before saving
	entriesToSave := make([]models.PasswordEntry, len(entries))
	copy(entriesToSave, entries)

	for i := range entriesToSave {
		if entriesToSave[i].Password != "" {
			encrypted, err := s.encryptor.Encrypt([]byte(entriesToSave[i].Password))
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

	err = ioutil.WriteFile(s.filePath, fileBytes, 0644)
	if err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}
	return nil
}
