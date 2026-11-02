package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"forgerealm-auth/db"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
)

// PatreonUserAttributes represents user attributes from Patreon API
type PatreonUserAttributes struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// PatreonMembershipData represents membership data from Patreon API
type PatreonMembershipData struct {
	ID string `json:"id"`
}

// PatreonMemberships represents memberships relationship from Patreon API
type PatreonMemberships struct {
	Data []PatreonMembershipData `json:"data"`
}

// PatreonUserRelationships represents user relationships from Patreon API
type PatreonUserRelationships struct {
	Memberships PatreonMemberships `json:"memberships"`
}

// PatreonUserData represents user data from Patreon API
type PatreonUserData struct {
	ID            string                   `json:"id"`
	Attributes    PatreonUserAttributes    `json:"attributes"`
	Relationships PatreonUserRelationships `json:"relationships"`
}

// PatreonIncludedAttributes represents included attributes from Patreon API
type PatreonIncludedAttributes struct {
	PatronStatus string `json:"patron_status"`
	Title        string `json:"title"`
}

// CampaignData represents campaign data in relationships
type CampaignData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// CampaignRelationship represents campaign relationship
type CampaignRelationship struct {
	Data CampaignData `json:"data"`
}

// TierData represents tier data in relationships
type TierData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// CurrentlyEntitledTiersRelationship represents currently entitled tiers relationship
type CurrentlyEntitledTiersRelationship struct {
	Data []TierData `json:"data"`
}

// PatreonIncludedRelationships represents relationships in included data
type PatreonIncludedRelationships struct {
	Campaign               CampaignRelationship               `json:"campaign"`
	CurrentlyEntitledTiers CurrentlyEntitledTiersRelationship `json:"currently_entitled_tiers"`
}

// PatreonIncluded represents included data from Patreon API
type PatreonIncluded struct {
	Type          string                       `json:"type"`
	ID            string                       `json:"id"`
	Attributes    PatreonIncludedAttributes    `json:"attributes"`
	Relationships PatreonIncludedRelationships `json:"relationships"`
}

// PatreonIdentityResponse represents the Patreon identity API response
type PatreonIdentityResponse struct {
	Data     PatreonUserData   `json:"data"`
	Included []PatreonIncluded `json:"included"`
}

// RefreshTokenRequest represents the request body for token refresh
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// AuthResponse represents the authentication response
type AuthResponse struct {
	Status       string `json:"status"`
	Message      string `json:"message"`
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthStatusResponse represents the authentication status response
type AuthStatusResponse struct {
	Status string      `json:"status"`
	UserID interface{} `json:"user_id,omitempty"`
	Tier   interface{} `json:"tier,omitempty"`
}

type ExternalAuth interface {
	HandleLogin(http.ResponseWriter, *http.Request)
	HandleCallback(http.ResponseWriter, *http.Request)
	HandleWebhook(http.ResponseWriter, *http.Request)
}

type PatreonAuthDb interface {
	SaveUser(ctx context.Context, patreonID, email, givenName, surName, tierID, patronStatus, accessToken, refreshToken string, tokenExpiry pgtype.Timestamp) error
	RecordWebhook(ctx context.Context, rec db.WebhookRecord) error
	RotateRefreshToken(ctx context.Context, token string) (string, error)
	StoreRefreshToken(ctx context.Context, patreonID, token string) error
	GetUserAccount(ctx context.Context, patreonID string) (db.UserAccount, error)
	FulfillTokenLogin(ctx context.Context, token string, userID string) error
}

// OAuth2Config interface defines the OAuth2 methods we use
type OAuth2Config interface {
	AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string
	Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error)
	Client(ctx context.Context, t *oauth2.Token) *http.Client
}

type PatreonAuth struct {
	patreonOAuthConfig OAuth2Config
	db                 PatreonAuthDb
}

func NewPatreonAuth(db PatreonAuthDb, patreonOAuthConfig OAuth2Config) *PatreonAuth {
	return &PatreonAuth{
		patreonOAuthConfig: patreonOAuthConfig,
		db:                 db,
	}
}

// HandlePatreonLogin initiates the Patreon OAuth2 flow
//
// Query params:
//   - token: UUID for token-based (polling) login flow
//   - app:   client app identifier (e.g. "atlasforge") — triggers redirect-based flow
func (a *PatreonAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	app := r.URL.Query().Get("app")

	state := "state"
	if token != "" {
		state = token
	}
	// Encode app into state so HandleCallback knows where to redirect
	if app != "" {
		state = "app:" + app + ":" + state
	}

	url := a.patreonOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	log.Printf("DEBUG: Redirecting to Patreon OAuth URL: %s", url)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandlePatreonCallback processes the OAuth2 callback from Patreon
func (a *PatreonAuth) HandleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		log.Printf("ERROR: OAuth callback missing code parameter")
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := a.patreonOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("ERROR: Failed to exchange OAuth token: %v", err)
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := a.patreonOAuthConfig.Client(context.Background(), token)

	// Call identity with the relationships/fields you actually need
	resp, err := client.Get(
		"https://www.patreon.com/api/oauth2/v2/identity" +
			"?include=memberships,memberships.campaign,memberships.currently_entitled_tiers" +
			"&fields[user]=email,first_name,last_name" +
			"&fields[member]=patron_status" +
			"&fields[tier]=title")
	if err != nil {
		log.Printf("ERROR: Failed to get user info from Patreon API: %v", err)
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("ERROR: Patreon identity returned %d: %s", resp.StatusCode, string(b))
		http.Error(w, "Patreon identity error", http.StatusBadGateway)
		return
	}

	body, _ := io.ReadAll(resp.Body)
	log.Printf("DEBUG: Raw Patreon user JSON: %s", string(body))

	var result PatreonIdentityResponse

	if err := json.Unmarshal(body, &result); err != nil {
		log.Printf("ERROR: Failed to parse identity JSON: %v", err)
		http.Error(w, "Failed to parse identity info", http.StatusInternalServerError)
		return
	}

	userID := result.Data.ID
	email := result.Data.Attributes.Email
	firstName := result.Data.Attributes.FirstName
	lastName := result.Data.Attributes.LastName

	// Check if user is an active patron of YOUR specific campaign
	const forgeRealmCampaignID = "14358641"

	isActivePatron := false
	var activeMembershipID string

	// First, let's log all memberships to see the campaign data structure
	log.Printf("DEBUG: All memberships: %+v", result.Included)

	// Index included by (type,id) for quick lookup
	typeKey := func(t, id string) string { return t + ":" + id }
	inc := make(map[string]PatreonIncluded)
	for _, x := range result.Included {
		inc[typeKey(x.Type, x.ID)] = x
	}

	// Walk the membership references on the user and find the one for YOUR campaign.
	// Lapsed patrons are admitted so the access gate can let them use credits
	// they still have (ED78); tier is non_patron unless a tier is entitled.
	tierTitle := nonPatronTier
	var patronStatus string

	memRefs := result.Data.Relationships.Memberships.Data // []Ref{ {id,type:"member"} ... }
	for _, ref := range memRefs {
		m, ok := inc[typeKey("member", ref.ID)]
		if !ok {
			continue // this means you didn't ask for include=memberships
		}

		// Find the campaign of this membership
		campRef := m.Relationships.Campaign.Data
		if campRef.ID != forgeRealmCampaignID {
			continue
		}

		// "active_patron" | "declined_patron" | "former_patron" | null (never paid)
		status := m.Attributes.PatronStatus
		if !admittedPatronStatuses[status] {
			continue
		}

		// Pull tier title if present (first entitled tier)
		if len(m.Relationships.CurrentlyEntitledTiers.Data) > 0 {
			tierRef := m.Relationships.CurrentlyEntitledTiers.Data[0] // pick the first
			if t, ok := inc[typeKey("tier", tierRef.ID)]; ok {
				if t.Attributes.Title != "" {
					tierTitle = strings.ToLower(t.Attributes.Title) // e.g., "apprentice"
				}
			}
		}

		isActivePatron = true
		activeMembershipID = m.ID
		patronStatus = status
		break
	}

	if !isActivePatron {
		log.Printf("INFO: User %s is not a patron of campaign %s", userID, forgeRealmCampaignID)
		http.Error(w, "You must be a patron to access this feature.", http.StatusForbidden)
		return
	}

	log.Printf("INFO: User %s is a patron (membership %s, status %s) of campaign %s, tier=%s",
		userID, activeMembershipID, patronStatus, forgeRealmCampaignID, tierTitle,
	)

	tokenExpiresAt := defaultExpiry(24)
	err = a.db.SaveUser(
		context.Background(),
		userID,
		email,
		firstName,
		lastName,
		tierTitle,
		patronStatus,
		token.AccessToken,
		token.RefreshToken,
		tokenExpiresAt,
	)
	if err != nil {
		log.Printf("ERROR: Failed to save user to database (Patreon ID: %s): %v", userID, err)
		http.Error(w, "Failed to save user: "+err.Error(), http.StatusInternalServerError)
		return
	}

	account, err := a.db.GetUserAccount(r.Context(), userID)
	if err != nil {
		log.Printf("ERROR: Failed to load account for Patreon ID %s: %v", userID, err)
		http.Error(w, "Failed to resolve user ID", http.StatusInternalServerError)
		return
	}
	if account.Closed {
		log.Printf("INFO: Refused login to closed account (Patreon ID: %s)", userID)
		http.Error(w, "This account is closed.", http.StatusForbidden)
		return
	}
	// Parse state parameter — may contain app prefix: "app:<name>:<inner_state>"
	rawState := r.URL.Query().Get("state")
	var appName string
	loginToken := rawState

	if strings.HasPrefix(rawState, "app:") {
		parts := strings.SplitN(rawState, ":", 3)
		if len(parts) == 3 {
			appName = parts[1]
			loginToken = parts[2]
		}
	}

	if loginToken == "" {
		log.Println("No login token (state param) returned in OAuth callback")
	} else if loginToken != "state" {
		err = a.db.FulfillTokenLogin(r.Context(), loginToken, userID)
		if err != nil {
			log.Printf("ERROR: Failed to fulfill token login (Patreon ID: %s): %v", userID, err)
			http.Error(w, "Failed to fulfill token login: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	jwtToken, refreshToken, err := issueTokens(r.Context(), a.db, account)
	if err != nil {
		log.Printf("ERROR: Failed to issue tokens (Patreon ID: %s): %v", userID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("INFO: Successfully authenticated Patreon user ID: %s", userID)

	// App-based login: redirect back to the app with tokens in query params
	if appName != "" {
		redirectURL := appRedirectURL(appName, jwtToken, refreshToken)
		if redirectURL != "" {
			log.Printf("INFO: Redirecting authenticated user to app: %s", appName)
			http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
			return
		}
		log.Printf("WARN: Unknown app '%s', falling back to JSON response", appName)
	}

	// Default: return JSON response (ScryForge / token-polling flow)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := AuthResponse{
		Status:       "ok",
		Message:      "authenticated",
		Token:        jwtToken,
		RefreshToken: refreshToken,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ERROR: Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// HandleRefresh exchanges a refresh token, once, for a token with the user's
// current tier and patron_status and a new refresh token. Closed accounts are
// refused (ED77, ED78).
func (a *PatreonAuth) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var requestBody RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if requestBody.RefreshToken == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	patreonID, err := a.db.RotateRefreshToken(r.Context(), requestBody.RefreshToken)
	if err != nil {
		if !errors.Is(err, db.ErrInvalidRefreshToken) {
			log.Printf("ERROR: Failed to rotate refresh token: %v", err)
		}
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	account, err := a.db.GetUserAccount(r.Context(), patreonID)
	if err != nil {
		log.Printf("ERROR: Failed to load account for Patreon ID %s: %v", patreonID, err)
		http.Error(w, "Failed to resolve user ID", http.StatusInternalServerError)
		return
	}
	if account.Closed {
		http.Error(w, "Account closed", http.StatusForbidden)
		return
	}

	newJWT, newRefreshToken, err := issueTokens(r.Context(), a.db, account)
	if err != nil {
		log.Printf("ERROR: Failed to issue tokens (Patreon ID: %s): %v", patreonID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := AuthResponse{
		Status:       "ok",
		Message:      "token refreshed",
		Token:        newJWT,
		RefreshToken: newRefreshToken,
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ERROR: Failed to encode response: %v", err)
	}
}

func (a *PatreonAuth) HandleAuthStatus(w http.ResponseWriter, r *http.Request) {
	// Try to extract and validate Bearer token
	tokenString, err := extractBearerToken(r)
	if err == nil {
		claims, err := validateJWT(tokenString)
		if err == nil {
			// Token is valid, return authenticated status
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := AuthStatusResponse{
				Status: "authenticated",
				UserID: claims["sub"],
				Tier:   claims["tier"],
			}
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Printf("ERROR: Failed to encode response: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			return
		}
	}

	// No valid Bearer token found
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := AuthStatusResponse{Status: "unauthenticated"}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("ERROR: Failed to encode response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// appRedirectURL returns the post-login redirect URL for a known app.
// Tokens are passed as URL-safe query params; the app's callback page reads them.
func appRedirectURL(appName, jwtToken, refreshToken string) string {
	knownApps := map[string]string{
		"atlasforge": "https://theforgerealm.com/atlasforge/auth/callback",
	}
	base, ok := knownApps[appName]
	if !ok {
		return ""
	}
	return base + "?token=" + url.QueryEscape(jwtToken) + "&refresh_token=" + url.QueryEscape(refreshToken)
}

func generateSecureRandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Patron statuses login admits: active, and lapsed so the gate can let them
// spend unexpired credits (ED78). Null (never paid) is not admitted.
var admittedPatronStatuses = map[string]bool{
	"active_patron":   true,
	"declined_patron": true,
	"former_patron":   true,
}

// patronStatusClaim is Patreon's status, or non_patron for null (PR-11 D1).
func patronStatusClaim(status string) string {
	if status == "" {
		return nonPatronTier
	}
	return status
}

type refreshTokenStore interface {
	StoreRefreshToken(ctx context.Context, patreonID, token string) error
}

// issueTokens issues the JWT and a refresh token for an account. Every login
// and refresh path uses it, so all issue the same tier and patron_status.
func issueTokens(ctx context.Context, store refreshTokenStore, account db.UserAccount) (string, string, error) {
	jwtToken, err := generateJWT(account.ID, account.TierID, patronStatusClaim(account.PatronStatus))
	if err != nil {
		return "", "", fmt.Errorf("Failed to generate token")
	}
	refreshToken := generateSecureRandomToken()
	if err := store.StoreRefreshToken(ctx, account.PatreonID, refreshToken); err != nil {
		return "", "", fmt.Errorf("Failed to store refresh token")
	}
	return jwtToken, refreshToken, nil
}

func generateJWT(userID, tierCode, patronStatus string) (string, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_CURRENT"))
	if secret == "" {
		return "", fmt.Errorf("JWT_SECRET_CURRENT environment variable is not set")
	}
	claims := jwt.MapClaims{
		"sub":           userID,
		"tier":          tierCode,
		"patron_status": patronStatus,
		"exp":           time.Now().Add(4 * time.Hour).Unix(),
		"iat":           time.Now().Unix(),
		"iss":           "forgerealm-auth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func defaultExpiry(hours int) pgtype.Timestamp {
	return pgtype.Timestamp{
		Time:  time.Now().Add(time.Duration(hours) * time.Hour),
		Valid: true,
	}
}

// extractBearerToken extracts and validates the Bearer token from the Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	// Check if it's a Bearer token
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", fmt.Errorf("empty token")
	}

	return token, nil
}

// validateJWT validates a JWT token and returns the claims if valid
func validateJWT(tokenString string) (jwt.MapClaims, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_CURRENT"))
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET_CURRENT environment variable is not set")
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		// Validate the signing method to prevent algorithm confusion attacks
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// Context key types to avoid collisions
type contextKey string

const (
	userIDKey contextKey = "user_id"
	tierKey   contextKey = "tier"
)

// AuthMiddleware creates a middleware that validates Bearer tokens
func (a *PatreonAuth) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := extractBearerToken(r)
		if err != nil {
			http.Error(w, "Unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := validateJWT(tokenString)
		if err != nil {
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		// Add user information to request context
		ctx := context.WithValue(r.Context(), userIDKey, claims["sub"])
		ctx = context.WithValue(ctx, tierKey, claims["tier"])
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
