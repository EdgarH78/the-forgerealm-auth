package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type TokenDatabase interface {
	SaveTokenLogin(ctx context.Context, token string, expiresAt time.Time) error
	CheckTokenLogin(ctx context.Context, token string) (bool, string, error)
}

type TokenLogin struct {
	db TokenDatabase
}

func NewTokenLogin(db TokenDatabase) *TokenLogin {
	return &TokenLogin{db: db}
}

// POST /auth/token/start
// Body: { client_name: string } (optional)
// Response: { token: string }
func (t *TokenLogin) StartTokenLogin(w http.ResponseWriter, r *http.Request) {
	token := uuid.New().String()
	expiry := time.Now().Add(10 * time.Minute)

	err := t.db.SaveTokenLogin(r.Context(), token, expiry)
	if err != nil {
		http.Error(w, "Failed to create login token", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"token": token}); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// TokenStatusResponse represents the token status response
type TokenStatusResponse struct {
	Fulfilled bool   `json:"fulfilled"`
	Token     string `json:"token,omitempty"`
}

// GET /auth/token/status?token=...
// Response: { fulfilled: bool, token?: string }
func (t *TokenLogin) CheckTokenStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	fulfilled, userID, err := t.db.CheckTokenLogin(r.Context(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusNotFound)
		return
	}

	response := TokenStatusResponse{
		Fulfilled: fulfilled,
	}

	// If token is fulfilled, generate and return JWT token
	if fulfilled && userID != "" {
		jwtToken, err := generateJWT(userID, "apprentice") // Default tier, can be enhanced later
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}
		response.Token = jwtToken
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
