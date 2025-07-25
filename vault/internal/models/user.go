package models

// User represents a user in the system
type User struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Password   string `json:"password"` // This should be stored as a hash, not plaintext
	IsLoggedIn bool   `json:"isLoggedIn"`
}
