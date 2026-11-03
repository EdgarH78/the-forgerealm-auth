package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"forgerealm-auth/db"

	"github.com/golang-jwt/jwt/v5"
)

// The admin token AtlasForge verifies (Forge Credits PR-12 D1,
// atlasforge/apps/api/src/middleware/adminAuth.ts).
const (
	adminIssuer        = "forgerealm-auth-admin"
	adminAudience      = "atlasforge-admin"
	adminTokenLifetime = time.Hour
	adminClockSkew     = 30 * time.Second
	userIssuer         = "forgerealm-auth"
)

var (
	adminIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)
	uuidPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// AdminDatabase is what the admin routes read.
type AdminDatabase interface {
	GetUserRole(ctx context.Context, userID string) (role string, closed bool, err error)
	FindUsersByEmail(ctx context.Context, email string) ([]db.UserSummary, error)
	FindUserByPatreonID(ctx context.Context, patreonID string) (db.UserSummary, error)
}

// Admin serves /auth/admin/token and /auth/admin/users. They sit under /auth
// because the load balancer sends only /auth to this service.
type Admin struct {
	db  AdminDatabase
	now func() time.Time
}

func NewAdmin(store AdminDatabase) *Admin {
	return &Admin{db: store, now: time.Now}
}

// UserLookupResponse is the body of GET /auth/admin/users.
type UserLookupResponse struct {
	UserID       string `json:"userId"`
	Email        string `json:"email"`
	Tier         string `json:"tier"`
	PatronStatus string `json:"patronStatus"`
}

func adminSecret() string {
	return strings.TrimSpace(os.Getenv("ADMIN_JWT_SECRET"))
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("ERROR: Failed to encode response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

// HandleToken (POST /auth/admin/token) exchanges a user token for an admin
// token when the user's role, read now, is admin and the account is open.
func (a *Admin) HandleToken(w http.ResponseWriter, r *http.Request) {
	secret := adminSecret()
	if secret == "" {
		writeError(w, http.StatusServiceUnavailable, "admin_disabled")
		return
	}
	tokenString, err := extractBearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	userID, err := a.verifyUserToken(tokenString)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	role, closed, err := a.db.GetUserRole(r.Context(), userID)
	if errors.Is(err, db.ErrUserNotFound) {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if err != nil {
		log.Printf("ERROR: Failed to read role for %s: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if role != db.AdminRole || closed {
		log.Printf("WARN: Admin token refused for %s (role %s, closed %t)", userID, role, closed)
		writeError(w, http.StatusForbidden, "not_admin")
		return
	}
	token, err := a.signAdminToken(secret, userID)
	if err != nil {
		log.Printf("ERROR: Failed to sign admin token: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	log.Printf("INFO: Issued admin token to %s", userID)
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// HandleUsers (GET /auth/admin/users) looks up one user by email or Patreon
// id for the admin screen.
func (a *Admin) HandleUsers(w http.ResponseWriter, r *http.Request) {
	secret := adminSecret()
	if secret == "" {
		writeError(w, http.StatusServiceUnavailable, "admin_disabled")
		return
	}
	tokenString, err := extractBearerToken(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if _, err := a.verifyAdminToken(secret, tokenString); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}

	email := strings.TrimSpace(r.URL.Query().Get("email"))
	patreonID := strings.TrimSpace(r.URL.Query().Get("patreon_id"))
	if (email == "") == (patreonID == "") {
		writeError(w, http.StatusBadRequest, "email_or_patreon_id_required")
		return
	}

	var user db.UserSummary
	if email != "" {
		users, err := a.db.FindUsersByEmail(r.Context(), email)
		switch {
		case err != nil:
			log.Printf("ERROR: Failed to look up user by email: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		case len(users) == 0:
			writeError(w, http.StatusNotFound, "not_found")
			return
		case len(users) > 1:
			writeError(w, http.StatusConflict, "ambiguous_email")
			return
		}
		user = users[0]
	} else {
		user, err = a.db.FindUserByPatreonID(r.Context(), patreonID)
		if errors.Is(err, db.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "not_found")
			return
		}
		if err != nil {
			log.Printf("ERROR: Failed to look up user by Patreon id: %v", err)
			writeError(w, http.StatusInternalServerError, "internal")
			return
		}
	}

	writeJSON(w, http.StatusOK, UserLookupResponse{
		UserID:       user.ID,
		Email:        user.Email,
		Tier:         user.TierID,
		PatronStatus: patronStatusClaim(user.PatronStatus),
	})
}

// verifyUserToken returns the user id of a valid user token.
func (a *Admin) verifyUserToken(tokenString string) (string, error) {
	secret := strings.TrimSpace(os.Getenv("JWT_SECRET_CURRENT"))
	if secret == "" {
		return "", fmt.Errorf("JWT_SECRET_CURRENT environment variable is not set")
	}
	token, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) { return []byte(secret), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(userIssuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		return "", err
	}
	sub, err := token.Claims.GetSubject()
	if err != nil || !uuidPattern.MatchString(sub) {
		return "", fmt.Errorf("invalid subject")
	}
	return sub, nil
}

func (a *Admin) signAdminToken(secret, userID string) (string, error) {
	now := a.now()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"iss": adminIssuer,
		"aud": adminAudience,
		"iat": now.Unix(),
		"exp": now.Add(adminTokenLifetime).Unix(),
	}).SignedString([]byte(secret))
}

// verifyAdminToken applies the same rules as AtlasForge's adminAuth.ts and
// returns the admin's user id.
func (a *Admin) verifyAdminToken(secret, tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(*jwt.Token) (interface{}, error) { return []byte(secret), nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(adminIssuer),
		jwt.WithAudience(adminAudience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(adminClockSkew),
		jwt.WithTimeFunc(a.now),
	)
	if err != nil {
		return "", err
	}
	sub, err := token.Claims.GetSubject()
	if err != nil || !adminIDPattern.MatchString(sub) {
		return "", fmt.Errorf("invalid subject")
	}
	iat, err := token.Claims.GetIssuedAt()
	if err != nil || iat == nil {
		return "", fmt.Errorf("missing iat")
	}
	exp, err := token.Claims.GetExpirationTime()
	if err != nil || exp == nil {
		return "", fmt.Errorf("missing exp")
	}
	if iat.After(a.now().Add(adminClockSkew)) {
		return "", fmt.Errorf("issued in the future")
	}
	if exp.Sub(iat.Time) > adminTokenLifetime {
		return "", fmt.Errorf("lives too long")
	}
	return sub, nil
}
