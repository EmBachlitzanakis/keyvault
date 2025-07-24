package server

import (
	"fmt"
	"log"
	"net/http"

	"github.com/ebachlitzanakis/vault/internal/handlers"
)

type Server struct {
	port           int
	passwordRouter *handlers.PasswordHandler
}

func NewServer(port int, passwordRouter *handlers.PasswordHandler) *Server {
	return &Server{
		port:           port,
		passwordRouter: passwordRouter,
	}
}

func (s *Server) setupRoutes() {
	// Serve static files (index.html, etc.)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "index.html")
			return
		}
		http.ServeFile(w, r, r.URL.Path[1:])
	})

	// API endpoints
	http.HandleFunc("/passwords", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			s.passwordRouter.GetPasswords(w, r)
		case http.MethodPost:
			s.passwordRouter.AddPassword(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})

	http.HandleFunc("/passwords/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			s.passwordRouter.DeletePassword(w, r)
			return
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
}

func (s *Server) Start() error {
	s.setupRoutes()
	log.Printf("Server starting on :%d", s.port)
	return http.ListenAndServe(fmt.Sprintf(":%d", s.port), nil)
}
