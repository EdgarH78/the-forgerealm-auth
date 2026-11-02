package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"forgerealm-auth/mockpatreon"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestE2E_LoginAgainstMockPatreon runs auth's real login and callback against
// the mock Patreon (AUTH-3) and Postgres, for every test user.
func TestE2E_LoginAgainstMockPatreon(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup()

	mock := httptest.NewServer(mockpatreon.NewServer("dev-client", "dev-secret").Handler())
	defer mock.Close()
	t.Setenv("PATREON_AUTHORIZE_URL", mock.URL+"/oauth2/authorize")
	t.Setenv("PATREON_TOKEN_URL", mock.URL+"/api/oauth2/token")
	t.Setenv("PATREON_API_BASE", mock.URL+"/")
	t.Setenv("ATLASFORGE_CALLBACK_URL", "http://localhost:5173/atlasforge/auth/callback")
	t.Setenv("JWT_SECRET_CURRENT", "test_jwt_secret_key_for_testing")

	a := NewPatreonAuth(tc.db, &oauth2.Config{
		ClientID:     "dev-client",
		ClientSecret: "dev-secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		Endpoint:     PatreonEndpoint(),
		Scopes:       []string{"identity", "identity[email]", "identity.memberships"},
	})
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// login walks /auth/login?<query> to the mock, picks the user, and runs the callback.
	login := func(t *testing.T, key, query string) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		a.HandleLogin(w, httptest.NewRequest("GET", "/auth/login?"+query, nil))
		require.Equal(t, http.StatusTemporaryRedirect, w.Code)
		authorize, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, mock.URL+"/oauth2/authorize", authorize.Scheme+"://"+authorize.Host+authorize.Path)
		q := authorize.Query()
		q.Set("mock_user", key)
		authorize.RawQuery = q.Encode()

		resp, err := noFollow.Get(authorize.String())
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		back, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		require.Equal(t, "/auth/callback", back.Path)

		w = httptest.NewRecorder()
		a.HandleCallback(w, httptest.NewRequest("GET", back.RequestURI(), nil))
		return w
	}

	cases := []struct{ key, tier, status string }{
		{"apprentice", "apprentice", "active_patron"},
		{"journeyman", "journeyman", "active_patron"},
		{"master", "master", "active_patron"},
		{"lapsed", "non_patron", "former_patron"},
		{"declined", "master", "declined_patron"},
		{"admin", "master", "active_patron"},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			w := login(t, c.key, "app=atlasforge")
			require.Equal(t, http.StatusTemporaryRedirect, w.Code, w.Body.String())
			dest, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, "localhost:5173", dest.Host)
			assert.Equal(t, "/atlasforge/auth/callback", dest.Path)
			assert.NotEmpty(t, dest.Query().Get("refresh_token"))

			claims, err := validateJWT(dest.Query().Get("token"))
			require.NoError(t, err)
			assert.Equal(t, c.tier, claims["tier"])
			assert.Equal(t, c.status, claims["patron_status"])
			acct, err := tc.db.GetUserAccount(context.Background(), "mock-"+c.key)
			require.NoError(t, err)
			assert.Equal(t, acct.ID, claims["sub"])
		})
	}

	t.Run("stranger refused", func(t *testing.T) {
		w := login(t, "stranger", "app=atlasforge")
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("no app answers JSON", func(t *testing.T) {
		w := login(t, "journeyman", "")
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp AuthResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.NotEmpty(t, resp.Token)
	})
}

func TestPatreonEndpointDefaults(t *testing.T) {
	for _, name := range []string{"PATREON_AUTHORIZE_URL", "PATREON_TOKEN_URL", "PATREON_API_BASE", "ATLASFORGE_CALLBACK_URL"} {
		t.Setenv(name, "")
	}
	ep := PatreonEndpoint()
	assert.Equal(t, "https://www.patreon.com/oauth2/authorize", ep.AuthURL)
	assert.Equal(t, "https://www.patreon.com/api/oauth2/token", ep.TokenURL)
	assert.Equal(t, "https://www.patreon.com", patreonAPIBase())
	assert.Equal(t, "https://theforgerealm.com/atlasforge/auth/callback?token=a&refresh_token=b", appRedirectURL("atlasforge", "a", "b"))
}
