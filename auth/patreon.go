package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
)

// WebhookEvent represents a Patreon webhook event
type WebhookEvent struct {
	EventType    string          `json:"event_type"`
	PatreonID    string          `json:"patreon_id"`
	TierID       string          `json:"tier_id"`
	PatronStatus string          `json:"patron_status"`
	Payload      json.RawMessage `json:"payload"`
}

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
}

// PatreonIncluded represents included data from Patreon API
type PatreonIncluded struct {
	Type       string                    `json:"type"`
	ID         string                    `json:"id"`
	Attributes PatreonIncludedAttributes `json:"attributes"`
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

// MemberPledgeAttributes represents member attributes from pledge data
type MemberPledgeAttributes struct {
	Email        string `json:"email"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	PatronStatus string `json:"patron_status"`
}

// EntitledTierData represents entitled tier data from pledge data
type EntitledTierData struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// CurrentlyEntitledTiers represents currently entitled tiers from pledge data
type CurrentlyEntitledTiers struct {
	Data []EntitledTierData `json:"data"`
}

// MemberPledgeRelationships represents member relationships from pledge data
type MemberPledgeRelationships struct {
	CurrentlyEntitledTiers CurrentlyEntitledTiers `json:"currently_entitled_tiers"`
}

// MemberPledgeIncludedAttributes represents included attributes from pledge data
type MemberPledgeIncludedAttributes struct {
	Title       string `json:"title"`
	Description string `json:"description"`
}

// MemberPledgeIncluded represents included data from pledge data
type MemberPledgeIncluded struct {
	Type       string                         `json:"type"`
	ID         string                         `json:"id"`
	Attributes MemberPledgeIncludedAttributes `json:"attributes"`
}

// MemberPledgeDataStruct represents the data field in MemberPledgeData
type MemberPledgeDataStruct struct {
	Attributes    MemberPledgeAttributes    `json:"attributes"`
	Relationships MemberPledgeRelationships `json:"relationships"`
}

// MemberPledgeData represents the data structure for member events
type MemberPledgeData struct {
	Data     MemberPledgeDataStruct `json:"data"`
	Included []MemberPledgeIncluded `json:"included"`
}

type ExternalAuth interface {
	HandleLogin(http.ResponseWriter, *http.Request)
	HandleCallback(http.ResponseWriter, *http.Request)
	HandleWebhook(http.ResponseWriter, *http.Request)
}

type PatreonAuthDb interface {
	SaveUser(ctx context.Context, patreonID, email, givenName, surName, tierID, patronStatus, accessToken, refreshToken string, tokenExpiry pgtype.Timestamp) error
	SaveWebhookEvent(ctx context.Context, eventTypeID, patreonID, tierID, patronStatus string, rawPayload []byte) error
	VerifyRefreshToken(ctx context.Context, token string) (string, error)
	StoreRefreshToken(ctx context.Context, patreonID, token string) error
	GetTierCodeForUser(ctx context.Context, patreonID string) (string, error)
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
func (a *PatreonAuth) HandleLogin(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	url := a.patreonOAuthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline)
	if token != "" {
		url = a.patreonOAuthConfig.AuthCodeURL(token, oauth2.AccessTypeOffline)
	}
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

	// Get identity info with memberships and patron_status
	resp, err := client.Get("https://www.patreon.com/api/oauth2/v2/identity?include=memberships&fields[user]=email,first_name,last_name&fields[member]=patron_status")
	if err != nil {
		log.Printf("ERROR: Failed to get user info from Patreon API: %v", err)
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

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

	// Check if user is an active patron
	if len(result.Included) > 0 && result.Included[0].Attributes.PatronStatus == "active_patron" {
		// User is an active patron, proceed with authentication
	} else {
		http.Error(w, "You must be a patron to access this feature.", http.StatusForbidden)
		return
	}

	tierTitle := "apprentice" // Default tier for active patrons
	patronStatus := "active_patron"

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
	login_token := r.URL.Query().Get("state")
	if login_token == "" {
		log.Println("No login token (state param) returned in OAuth callback")
	} else if login_token != "state" {
		err = a.db.FulfillTokenLogin(r.Context(), login_token, userID)
		if err != nil {
			log.Printf("ERROR: Failed to fulfill token login (Patreon ID: %s): %v", userID, err)
			http.Error(w, "Failed to fulfill token login: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	jwtToken, err := generateJWT(userID, tierTitle)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	refreshToken := generateSecureRandomToken()
	err = a.db.StoreRefreshToken(r.Context(), userID, refreshToken)
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
		return
	}

	log.Printf("INFO: Successfully authenticated Patreon user ID: %s", userID)
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

func (a *PatreonAuth) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	// Parse the request body to get the refresh token
	var requestBody RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if requestBody.RefreshToken == "" {
		http.Error(w, "Missing refresh token", http.StatusBadRequest)
		return
	}

	patreonID, err := a.db.VerifyRefreshToken(r.Context(), requestBody.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Get tier info from DB (if needed)
	tierCode, _ := a.db.GetTierCodeForUser(r.Context(), patreonID)

	newJWT, err := generateJWT(patreonID, tierCode)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Generate a new refresh token
	newRefreshToken := generateSecureRandomToken()
	err = a.db.StoreRefreshToken(r.Context(), patreonID, newRefreshToken)
	if err != nil {
		http.Error(w, "Failed to store refresh token", http.StatusInternalServerError)
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
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
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

func generateSecureRandomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func generateJWT(patreonID, tierCode string) (string, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_CURRENT"))
	if secret == "" {
		return "", fmt.Errorf("JWT_SECRET_CURRENT environment variable is not set")
	}
	claims := jwt.MapClaims{
		"sub":  patreonID,
		"tier": tierCode,
		"exp":  time.Now().Add(1 * time.Hour).Unix(),
		"iat":  time.Now().Unix(),
		"iss":  "forgerealm-auth",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// verifySignature verifies the webhook signature
func verifySignature(r *http.Request, signature string) bool {
	secret := strings.TrimSpace(os.Getenv("WEBHOOK_SECRET"))
	if secret == "" {
		log.Printf("ERROR: WEBHOOK_SECRET environment variable is not set")
		return false
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read request body for signature verification: %v", err)
		return false
	}
	// Restore the body for later use
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Calculate HMAC
	h := hmac.New(md5.New, []byte(secret))
	h.Write(body)
	expectedSignature := hex.EncodeToString(h.Sum(nil))

	isValid := hmac.Equal([]byte(signature), []byte(expectedSignature))
	if !isValid {
		log.Printf("ERROR: Invalid webhook signature. Expected: %s, Received: %s", expectedSignature, signature)
	}
	return isValid
}

func (a *PatreonAuth) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	// Verify webhook signature
	signature := r.Header.Get("X-Patreon-Signature")
	if !verifySignature(r, signature) {
		log.Printf("ERROR: Webhook signature verification failed")
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	var event WebhookEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		log.Printf("ERROR: Failed to decode webhook event JSON: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("INFO: Processing webhook event: %s for Patreon ID: %s", event.EventType, event.PatreonID)

	// Parse the payload based on event type
	var pledgeData MemberPledgeData
	if event.EventType == "members:create" || event.EventType == "members:update" {
		if err := json.Unmarshal(event.Payload, &pledgeData); err != nil {
			log.Printf("ERROR: Failed to parse member payload for Patreon ID %s: %v", event.PatreonID, err)
			http.Error(w, "Invalid pledge data", http.StatusBadRequest)
			return
		}
	}

	// Save webhook event to database
	if err := a.db.SaveWebhookEvent(r.Context(), event.EventType, event.PatreonID, event.TierID, event.PatronStatus, event.Payload); err != nil {
		log.Printf("ERROR: Failed to save webhook event to database (Event: %s, Patreon ID: %s): %v", event.EventType, event.PatreonID, err)
		http.Error(w, "Failed to save webhook event", http.StatusInternalServerError)
		return
	}

	// Process webhook event based on type
	switch event.EventType {
	case "members:create":
		a.handleMemberCreate(event.PatreonID, event.TierID, event.PatronStatus, pledgeData)
	case "members:update":
		a.handleMemberUpdate(event.PatreonID, event.TierID, event.PatronStatus, pledgeData)
	case "members:delete":
		a.handleMemberDelete(event.PatreonID)
	default:
		log.Printf("WARN: Unknown webhook event type: %s for Patreon ID: %s", event.EventType, event.PatreonID)
	}

	log.Printf("INFO: Successfully processed webhook event: %s for Patreon ID: %s", event.EventType, event.PatreonID)
	w.WriteHeader(http.StatusOK)
}

// getTierCodeFromPledgeData extracts the tier code from pledge data
func getTierCodeFromPledgeData(data MemberPledgeData) string {
	// If no entitled tiers, return empty string
	if len(data.Data.Relationships.CurrentlyEntitledTiers.Data) == 0 {
		return ""
	}

	// Get the first entitled tier ID
	tierID := data.Data.Relationships.CurrentlyEntitledTiers.Data[0].ID

	// Look for the tier in the included data to get the title
	for _, included := range data.Included {
		if included.Type == "tier" && included.ID == tierID {
			// Map tier titles to tier codes
			switch included.Attributes.Title {
			case "Apprentice":
				return "apprentice"
			case "Journeyman":
				return "journeyman"
			case "Master":
				return "master"
			default:
				// For unknown tiers, use the title as the code (lowercase)
				return strings.ToLower(included.Attributes.Title)
			}
		}
	}

	// If we can't find the tier details, return a default
	return "apprentice"
}

// handleMemberCreate processes member creation events
func (a *PatreonAuth) handleMemberCreate(patreonID, tierID, patronStatus string, data MemberPledgeData) {
	log.Printf("INFO: Processing member create event for Patreon ID: %s, Tier: %s, Status: %s", patreonID, tierID, patronStatus)

	// Extract tier code from pledge data
	tierCode := getTierCodeFromPledgeData(data)
	log.Printf("INFO: Extracted tier code '%s' from pledge data for Patreon ID: %s", tierCode, patreonID)

	tokenExpiry := defaultExpiry(24)

	err := a.db.SaveUser(
		context.Background(),
		patreonID,
		data.Data.Attributes.Email,
		data.Data.Attributes.FirstName,
		data.Data.Attributes.LastName,
		tierCode,
		patronStatus,
		"", // No access token for webhook events
		"", // No refresh token for webhook events
		tokenExpiry,
	)

	if err != nil {
		log.Printf("ERROR: Failed to save user from member create webhook (Patreon ID: %s): %v", patreonID, err)
		return
	}

	log.Printf("INFO: Successfully saved user from member create webhook (Patreon ID: %s)", patreonID)
}

// handleMemberUpdate processes member update events
func (a *PatreonAuth) handleMemberUpdate(patreonID, tierID, patronStatus string, data MemberPledgeData) {
	log.Printf("INFO: Processing member update event for Patreon ID: %s, Tier: %s, Status: %s", patreonID, tierID, patronStatus)

	// Extract tier code from pledge data
	tierCode := getTierCodeFromPledgeData(data)
	log.Printf("INFO: Extracted tier code '%s' from pledge data for Patreon ID: %s", tierCode, patreonID)

	tokenExpiry := defaultExpiry(24)

	err := a.db.SaveUser(
		context.Background(),
		patreonID,
		data.Data.Attributes.Email,     // Use email from pledge data
		data.Data.Attributes.FirstName, // Use first name from pledge data
		data.Data.Attributes.LastName,  // Use last name from pledge data
		tierCode,                       // Use the extracted tier code instead of tierID
		patronStatus,
		"", // Keep existing access token
		"", // Keep existing refresh token
		tokenExpiry,
	)

	if err != nil {
		log.Printf("ERROR: Failed to save user from member update webhook (Patreon ID: %s): %v", patreonID, err)
		return
	}

	log.Printf("INFO: Successfully saved user from member update webhook (Patreon ID: %s)", patreonID)
}

// handleMemberDelete processes member deletion events
func (a *PatreonAuth) handleMemberDelete(patreonID string) {
	log.Printf("INFO: Processing member delete event for Patreon ID: %s", patreonID)

	tokenExpiry := defaultExpiry(24)

	err := a.db.SaveUser(
		context.Background(),
		patreonID,
		"", // Keep existing email
		"", // Keep existing given name
		"", // Keep existing surname
		"", // Clear tier ID
		"former_patron",
		"", // Keep existing access token
		"", // Keep existing refresh token
		tokenExpiry,
	)

	if err != nil {
		log.Printf("ERROR: Failed to save user from member delete webhook (Patreon ID: %s): %v", patreonID, err)
		return
	}

	log.Printf("INFO: Successfully saved user from member delete webhook (Patreon ID: %s)", patreonID)
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
