package handlers

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/ebachlitzanakis/vault/internal/models"
	"github.com/ebachlitzanakis/vault/internal/storage"
	"github.com/google/uuid"
)

type PasswordHandler struct {
	storage *storage.Storage
}

func NewPasswordHandler(storage *storage.Storage) *PasswordHandler {
	return &PasswordHandler{storage: storage}
}

// GetPasswords handles GET requests to retrieve all password entries
func (h *PasswordHandler) GetPasswords(w http.ResponseWriter, r *http.Request) {
	entries, err := h.storage.LoadEntries()
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

// AddPassword handles POST requests to add a new password entry
func (h *PasswordHandler) AddPassword(w http.ResponseWriter, r *http.Request) {
	website := r.FormValue("website")
	username := r.FormValue("username")
	password := r.FormValue("password")

	if website == "" || username == "" || password == "" {
		http.Error(w, "All fields (website, username, password) are required.", http.StatusBadRequest)
		return
	}

	newEntry := models.PasswordEntry{
		ID:       uuid.New().String(),
		Website:  website,
		Username: username,
		Password: password,
	}

	entries, err := h.storage.LoadEntries()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading entries: %v", err), http.StatusInternalServerError)
		return
	}

	entries = append(entries, newEntry)

	err = h.storage.SaveEntries(entries)
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

// DeletePassword handles DELETE requests to remove a password entry
func (h *PasswordHandler) DeletePassword(w http.ResponseWriter, r *http.Request) {
	id := filepath.Base(r.URL.Path)

	entries, err := h.storage.LoadEntries()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error loading entries: %v", err), http.StatusInternalServerError)
		return
	}

	found := false
	updatedEntries := []models.PasswordEntry{}
	for _, entry := range entries {
		if entry.ID == id {
			found = true
			continue
		}
		updatedEntries = append(updatedEntries, entry)
	}

	if !found {
		http.Error(w, "Entry not found", http.StatusNotFound)
		return
	}

	err = h.storage.SaveEntries(updatedEntries)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error saving entries: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}
