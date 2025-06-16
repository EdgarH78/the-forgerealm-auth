package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"forgerealm-auth/db"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
)

var (
	patreonOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("PATREON_CLIENT_ID"),
		ClientSecret: os.Getenv("PATREON_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("PATREON_REDIRECT_URL"),
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.patreon.com/oauth2/authorize",
			TokenURL: "https://www.patreon.com/api/oauth2/token",
		},
		Scopes: []string{"identity", "identity[email]"},
	}
)

// HandlePatreonLogin initiates the Patreon OAuth2 flow
func HandlePatreonLogin(w http.ResponseWriter, r *http.Request) {
	url := patreonOAuthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandlePatreonCallback processes the OAuth2 callback from Patreon
func HandlePatreonCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := patreonOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get user info from Patreon
	client := patreonOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields[user]=email")
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Data struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Email string `json:"email"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		http.Error(w, "Failed to decode user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Save user to database
	tokenExpiresAt := pgtype.Timestamp{
		Time:  time.Now().Add(token.Expiry.Sub(time.Now())),
		Valid: true,
	}

	err = db.SaveUser(
		context.Background(),
		result.Data.ID,
		result.Data.Email,
		token.AccessToken,
		token.RefreshToken,
		tokenExpiresAt,
	)
	if err != nil {
		http.Error(w, "Failed to save user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to success page or return success response
	w.Write([]byte("Successfully authenticated with Patreon!"))
}
