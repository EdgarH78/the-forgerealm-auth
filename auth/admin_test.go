package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"forgerealm-auth/db"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAdminSecret = "test_admin_secret"
	testUserSecret  = "test_user_secret"
	testUserID      = "3f0c2a8e-9a51-4f7e-8c0e-0a1b2c3d4e5f"
)

type fakeAdminDB struct {
	role      string
	closed    bool
	roleErr   error
	byEmail   []db.UserSummary
	emailErr  error
	byPatreon map[string]db.UserSummary
	lastEmail string
}

func (f *fakeAdminDB) GetUserRole(_ context.Context, userID string) (string, bool, error) {
	if f.roleErr != nil {
		return "", false, f.roleErr
	}
	if userID != testUserID {
		return "", false, db.ErrUserNotFound
	}
	return f.role, f.closed, nil
}

func (f *fakeAdminDB) FindUsersByEmail(_ context.Context, email string) ([]db.UserSummary, error) {
	f.lastEmail = email
	return f.byEmail, f.emailErr
}

func (f *fakeAdminDB) FindUserByPatreonID(_ context.Context, id string) (db.UserSummary, error) {
	u, ok := f.byPatreon[id]
	if !ok {
		return db.UserSummary{}, db.ErrUserNotFound
	}
	return u, nil
}

func signHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return s
}

func userToken(t *testing.T, mutate func(jwt.MapClaims)) string {
	now := time.Now()
	c := jwt.MapClaims{"sub": testUserID, "iss": "forgerealm-auth", "tier": "master", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if mutate != nil {
		mutate(c)
	}
	return signHS256(t, testUserSecret, c)
}

func adminToken(t *testing.T, mutate func(jwt.MapClaims)) string {
	now := time.Now()
	c := jwt.MapClaims{"sub": testUserID, "iss": adminIssuer, "aud": adminAudience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	if mutate != nil {
		mutate(c)
	}
	return signHS256(t, testAdminSecret, c)
}

func setAdminEnv(t *testing.T) {
	t.Setenv("ADMIN_JWT_SECRET", testAdminSecret)
	t.Setenv("JWT_SECRET_CURRENT", testUserSecret)
}

func exchange(a *Admin, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/auth/admin/token", nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	a.HandleToken(w, req)
	return w
}

func lookup(a *Admin, bearer, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", "/auth/admin/users?"+query, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	a.HandleUsers(w, req)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body), w.Body.String())
	return body["error"]
}

// assertAtlasForgeAccepts applies the rules of atlasforge/apps/api/src/middleware/adminAuth.ts.
func assertAtlasForgeAccepts(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) { return []byte(testAdminSecret), nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("forgerealm-auth-admin"),
		jwt.WithAudience("atlasforge-admin"), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	sub, _ := claims.GetSubject()
	assert.Regexp(t, `^[A-Za-z0-9_-]{1,100}$`, sub)
	iat, _ := claims.GetIssuedAt()
	exp, _ := claims.GetExpirationTime()
	require.NotNil(t, iat)
	require.NotNil(t, exp)
	assert.False(t, iat.After(time.Now().Add(30*time.Second)), "iat in the future")
	assert.LessOrEqual(t, exp.Sub(iat.Time), time.Hour)
	return claims
}

func TestAdminToken_IssuesForAdmin(t *testing.T) {
	setAdminEnv(t)
	w := exchange(NewAdmin(&fakeAdminDB{role: "admin"}), userToken(t, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	claims := assertAtlasForgeAccepts(t, body["token"])
	assert.Equal(t, testUserID, claims["sub"])
	exp, _ := claims.GetExpirationTime()
	iat, _ := claims.GetIssuedAt()
	assert.Equal(t, time.Hour, exp.Sub(iat.Time))
	assert.NotContains(t, claims, "tier")
}

func TestAdminToken_Refusals(t *testing.T) {
	setAdminEnv(t)
	admin := &fakeAdminDB{role: "admin"}
	cases := []struct {
		name   string
		store  *fakeAdminDB
		bearer string
		status int
		code   string
	}{
		{"role user", &fakeAdminDB{role: "user"}, userToken(t, nil), 403, "not_admin"},
		{"closed admin", &fakeAdminDB{role: "admin", closed: true}, userToken(t, nil), 403, "not_admin"},
		{"no token", admin, "", 401, "invalid_token"},
		{"garbage", admin, "not.a.jwt", 401, "invalid_token"},
		{"expired", admin, userToken(t, func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }), 401, "invalid_token"},
		{"no exp", admin, userToken(t, func(c jwt.MapClaims) { delete(c, "exp") }), 401, "invalid_token"},
		{"wrong issuer", admin, userToken(t, func(c jwt.MapClaims) { c["iss"] = "someone-else" }), 401, "invalid_token"},
		{"wrong secret", admin, signHS256(t, "other", jwt.MapClaims{"sub": testUserID, "iss": "forgerealm-auth", "exp": time.Now().Add(time.Hour).Unix()}), 401, "invalid_token"},
		{"admin token as user token", admin, adminToken(t, nil), 401, "invalid_token"},
		{"sub not a uuid", admin, userToken(t, func(c jwt.MapClaims) { c["sub"] = "12345" }), 401, "invalid_token"},
		{"unknown user", admin, userToken(t, func(c jwt.MapClaims) { c["sub"] = "00000000-0000-0000-0000-000000000000" }), 401, "invalid_token"},
		{"db error", &fakeAdminDB{roleErr: errors.New("down")}, userToken(t, nil), 500, "internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := exchange(NewAdmin(tc.store), tc.bearer)
			assert.Equal(t, tc.status, w.Code, w.Body.String())
			assert.Equal(t, tc.code, errorCode(t, w))
		})
	}
}

func TestAdminToken_NoneAlgorithmRefused(t *testing.T) {
	setAdminEnv(t)
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": testUserID, "iss": "forgerealm-auth", "exp": time.Now().Add(time.Hour).Unix()}).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, exchange(NewAdmin(&fakeAdminDB{role: "admin"}), none).Code)
}

func TestAdmin_DisabledWithoutSecret(t *testing.T) {
	t.Setenv("ADMIN_JWT_SECRET", "")
	t.Setenv("JWT_SECRET_CURRENT", testUserSecret)
	a := NewAdmin(&fakeAdminDB{role: "admin"})
	w := exchange(a, userToken(t, nil))
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "admin_disabled", errorCode(t, w))
	w = lookup(a, adminToken(t, nil), "email=a@b.c")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Equal(t, "admin_disabled", errorCode(t, w))
}

func TestAdminUsers_Lookup(t *testing.T) {
	setAdminEnv(t)
	pat := db.UserSummary{ID: testUserID, Email: "pat@example.com", TierID: "master", PatronStatus: "active_patron"}
	store := &fakeAdminDB{
		byEmail:   []db.UserSummary{pat},
		byPatreon: map[string]db.UserSummary{"98765": {ID: testUserID, Email: "pat@example.com", TierID: "non_patron"}},
	}
	a := NewAdmin(store)
	tok := adminToken(t, nil)

	w := lookup(a, tok, "email=%20Pat%40Example.com%20")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"userId":"`+testUserID+`","email":"pat@example.com","tier":"master","patronStatus":"active_patron"}`, w.Body.String())
	assert.Equal(t, "Pat@Example.com", store.lastEmail)

	w = lookup(a, tok, "patreon_id=%2098765%20")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"userId":"`+testUserID+`","email":"pat@example.com","tier":"non_patron","patronStatus":"non_patron"}`, w.Body.String())

	w = lookup(a, tok, "patreon_id=11111")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "not_found", errorCode(t, w))

	store.byEmail = nil
	w = lookup(a, tok, "email=nobody@example.com")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "not_found", errorCode(t, w))

	store.byEmail = []db.UserSummary{pat, pat}
	w = lookup(a, tok, "email=pat@example.com")
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Equal(t, "ambiguous_email", errorCode(t, w))

	store.emailErr = errors.New("down")
	assert.Equal(t, http.StatusInternalServerError, lookup(a, tok, "email=pat@example.com").Code)

	for _, q := range []string{"", "email=", "email=%20%20", "email=a@b.c&patreon_id=1"} {
		w = lookup(a, tok, q)
		assert.Equal(t, http.StatusBadRequest, w.Code, q)
		assert.Equal(t, "email_or_patreon_id_required", errorCode(t, w), q)
	}
}

func TestAdminUsers_TokenRules(t *testing.T) {
	setAdminEnv(t)
	a := NewAdmin(&fakeAdminDB{byEmail: []db.UserSummary{{ID: testUserID}}})
	now := time.Now()
	cases := map[string]string{
		"none":         "",
		"user token":   userToken(t, nil),
		"wrong secret": signHS256(t, "other", jwt.MapClaims{"sub": testUserID, "iss": adminIssuer, "aud": adminAudience, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}),
		"wrong issuer": adminToken(t, func(c jwt.MapClaims) { c["iss"] = "forgerealm-auth" }),
		"wrong aud":    adminToken(t, func(c jwt.MapClaims) { c["aud"] = "someone" }),
		"expired": adminToken(t, func(c jwt.MapClaims) {
			c["iat"] = now.Add(-2 * time.Hour).Unix()
			c["exp"] = now.Add(-time.Hour).Unix()
		}),
		"no iat":        adminToken(t, func(c jwt.MapClaims) { delete(c, "iat") }),
		"future iat":    adminToken(t, func(c jwt.MapClaims) { c["iat"] = now.Add(time.Minute).Unix(); c["exp"] = now.Add(time.Hour).Unix() }),
		"too long":      adminToken(t, func(c jwt.MapClaims) { c["exp"] = now.Add(time.Hour + time.Second).Unix() }),
		"sub has colon": adminToken(t, func(c jwt.MapClaims) { c["sub"] = "a:b" }),
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			w := lookup(a, tok, "email=pat@example.com")
			assert.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
			assert.Equal(t, "invalid_token", errorCode(t, w))
		})
	}
	// An iat within the 30 s skew is accepted, as AtlasForge does.
	ok := adminToken(t, func(c jwt.MapClaims) {
		c["iat"] = now.Add(20 * time.Second).Unix()
		c["exp"] = now.Add(time.Hour).Unix()
	})
	assert.Equal(t, http.StatusOK, lookup(a, ok, "email=pat@example.com").Code)
}
