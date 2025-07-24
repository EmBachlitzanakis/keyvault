package models

// PasswordEntry represents a single entry in the vault
type PasswordEntry struct {
	ID       string `json:"id"`
	Website  string `json:"website"`
	Username string `json:"username"`
	Password string `json:"password"` // This will be encrypted in the JSON file
}
