package auth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"forgerealm-auth/db"

	"github.com/google/uuid"
)

type TokenDatabase interface {
	SaveTokenLogin(ctx context.Context, token string, expiresAt time.Time) error
	CheckTokenLogin(ctx context.Context, token string) (bool, string, error)
	StoreRefreshToken(ctx context.Context, userID string, token string) error
	GetPatreonIDFromUserID(ctx context.Context, userID string) (string, error)
	GetUserAccount(ctx context.Context, patreonID string) (db.UserAccount, error)
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
	Fulfilled    bool   `json:"fulfilled"`
	Token        string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
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

	// If token is fulfilled, issue tokens with the current tier and status.
	// Closed accounts get none (ED77).
	if fulfilled && userID != "" {
		patreonID, err := t.db.GetPatreonIDFromUserID(r.Context(), userID)
		if err != nil {
			http.Error(w, "Failed to get user information", http.StatusInternalServerError)
			return
		}
		account, err := t.db.GetUserAccount(r.Context(), patreonID)
		if err != nil {
			log.Printf("ERROR: Failed to load account for user %s: %v", userID, err)
			http.Error(w, "Failed to get user information", http.StatusInternalServerError)
			return
		}
		if account.Closed {
			http.Error(w, "Account closed", http.StatusForbidden)
			return
		}
		jwtToken, refreshToken, err := issueTokens(r.Context(), t.db, account)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		response.Token = jwtToken
		response.RefreshToken = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
