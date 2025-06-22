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
	CheckTokenLogin(ctx context.Context, token string) (bool, error)
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

	err := t.db.SaveTokenLogin(context.Background(), token, expiry)
	if err != nil {
		http.Error(w, "Failed to create login token", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

// GET /auth/token/status?token=...
// Response: { fulfilled: bool }
func (t *TokenLogin) CheckTokenStatus(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	fulfilled, err := t.db.CheckTokenLogin(context.Background(), token)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"fulfilled": fulfilled})
}
