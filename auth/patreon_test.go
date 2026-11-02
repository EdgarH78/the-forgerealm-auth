package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"forgerealm-auth/db"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// TestMain sets up environment variables for all tests
func TestMain(m *testing.M) {
	// Set up test environment variables
	setupTestEnv()

	// Run tests
	code := m.Run()

	// Clean up
	os.Exit(code)
}

// setupTestEnv sets up environment variables needed for tests
func setupTestEnv() {
	// Set required environment variables for tests
	os.Setenv("JWT_SECRET_CURRENT", "test_jwt_secret_key_for_testing")
	os.Setenv("WEB_HOOK_SECRET", "test_webhook_secret_for_testing")
	os.Setenv("PATREON_CLIENT_ID", "test_client_id")
	os.Setenv("PATREON_CLIENT_SECRET", "test_client_secret")
	os.Setenv("PATREON_REDIRECT_URL", "http://localhost:8080/auth/callback")
}

// MockDatabase implements db.Database for testing
type MockDatabase struct {
	mock.Mock
}

func (m *MockDatabase) SaveUser(ctx context.Context, patreonID, email, givenName, surName, tierID, patronStatus, accessToken, refreshToken string, tokenExpiry pgtype.Timestamp) error {
	args := m.Called(ctx, patreonID, email, givenName, surName, tierID, patronStatus, accessToken, refreshToken, tokenExpiry)
	return args.Error(0)
}

func (m *MockDatabase) RecordWebhook(ctx context.Context, rec db.WebhookRecord) error {
	args := m.Called(ctx, rec)
	return args.Error(0)
}

func (m *MockDatabase) StoreRefreshToken(ctx context.Context, patreonID, token string) error {
	args := m.Called(ctx, patreonID, token)
	return args.Error(0)
}

func (m *MockDatabase) RotateRefreshToken(ctx context.Context, token string) (string, error) {
	args := m.Called(ctx, token)
	return args.String(0), args.Error(1)
}

func (m *MockDatabase) FulfillTokenLogin(ctx context.Context, token string, userID string) error {
	args := m.Called(ctx, token, userID)
	return args.Error(0)
}

func (m *MockDatabase) GetUserAccount(ctx context.Context, patreonID string) (db.UserAccount, error) {
	args := m.Called(ctx, patreonID)
	return args.Get(0).(db.UserAccount), args.Error(1)
}

// MockOAuth2Config mocks the OAuth2 config for testing
type MockOAuth2Config struct {
	exchangeFunc    func(code string) (*oauth2.Token, error)
	clientFunc      func(token *oauth2.Token) *http.Client
	authCodeURLFunc func(state string, opts ...oauth2.AuthCodeOption) string
}

func (m *MockOAuth2Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	if m.exchangeFunc != nil {
		return m.exchangeFunc(code)
	}
	return nil, fmt.Errorf("mock exchange not configured")
}

func (m *MockOAuth2Config) Client(ctx context.Context, token *oauth2.Token) *http.Client {
	if m.clientFunc != nil {
		return m.clientFunc(token)
	}
	return &http.Client{}
}

func (m *MockOAuth2Config) AuthCodeURL(state string, opts ...oauth2.AuthCodeOption) string {
	if m.authCodeURLFunc != nil {
		return m.authCodeURLFunc(state, opts...)
	}
	return "https://www.patreon.com/oauth2/authorize?state=" + state
}

// MockHTTPClient mocks the HTTP client for Patreon API calls
type MockHTTPClient struct {
	doFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	if m.doFunc != nil {
		return m.doFunc(req)
	}
	return nil, fmt.Errorf("mock client not configured")
}

func (m *MockHTTPClient) Get(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	return m.Do(req)
}

// MockHTTPClientWrapper wraps MockHTTPClient to satisfy http.Client interface
type MockHTTPClientWrapper struct {
	*MockHTTPClient
}

func (m *MockHTTPClientWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.Do(req)
}

func TestHandleCallback_CompleteFlow(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		state          string
		mockExchange   func(code string) (*oauth2.Token, error)
		mockHTTPClient func() *http.Client
		mockDB         *MockDatabase
		expectedStatus int
		expectedBody   string
		checkCookies   bool
	}{
		{
			name:  "successful_authentication_with_token_login",
			code:  "valid_code",
			state: "login_token_123",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								// Mock Patreon API response
								responseBody := `{
									"data": {
										"id": "test_user_123",
										"attributes": {
											"email": "test@example.com",
											"first_name": "Test",
											"last_name": "User"
										},
										"relationships": {
											"memberships": {
												"data": [{"id": "membership_123"}]
											}
										}
									},
									"included": [
										{
											"type": "member",
											"id": "membership_123",
											"attributes": {
												"patron_status": "active_patron"
											},
											"relationships": {
												"campaign": {
													"data": {
														"id": "14358641",
														"type": "campaign"
													}
												},
												"currently_entitled_tiers": {
													"data": [
														{
															"id": "tier_1",
															"type": "tier"
														}
													]
												}
											}
										},
										{
											"type": "tier",
											"id": "tier_1",
											"attributes": {
												"title": "Apprentice"
											}
										}
									]
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusOK,
			expectedBody:   `"status":"ok"`,
			checkCookies:   true,
		},
		{
			name:  "successful_authentication_without_token_login",
			code:  "valid_code",
			state: "state",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								responseBody := `{
									"data": {
										"id": "test_user_456",
										"attributes": {
											"email": "test2@example.com",
											"first_name": "Test2",
											"last_name": "User2"
										},
										"relationships": {
											"memberships": {
												"data": [{"id": "membership_456"}]
											}
										}
									},
									"included": [
										{
											"type": "member",
											"id": "membership_456",
											"attributes": {
												"patron_status": "active_patron"
											},
											"relationships": {
												"campaign": {
													"data": {
														"id": "14358641",
														"type": "campaign"
													}
												},
												"currently_entitled_tiers": {
													"data": [
														{
															"id": "tier_1",
															"type": "tier"
														}
													]
												}
											}
										},
										{
											"type": "tier",
											"id": "tier_1",
											"attributes": {
												"title": "Apprentice"
											}
										}
									]
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusOK,
			expectedBody:   `"status":"ok"`,
			checkCookies:   true,
		},
		{
			name:  "non_patron_user_rejected",
			code:  "valid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								responseBody := `{
									"data": {
										"id": "test_user_789",
										"attributes": {
											"email": "nonpatron@example.com",
											"first_name": "Non",
											"last_name": "Patron"
										},
										"relationships": {
											"memberships": {
												"data": []
											}
										}
									},
									"included": []
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusForbidden,
			expectedBody:   "You must be a patron to access this feature.\n",
		},
		{
			name:  "oauth_exchange_failure",
			code:  "invalid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return nil, fmt.Errorf("invalid_grant")
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to exchange token: invalid_grant\n",
		},
		{
			name:  "patreon_api_failure",
			code:  "valid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								return nil, fmt.Errorf("network error")
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to get user info: Get \"https://www.patreon.com/api/oauth2/v2/identity?include=memberships,memberships.campaign,memberships.currently_entitled_tiers&fields[user]=email,first_name,last_name&fields[member]=patron_status&fields[tier]=title\": network error",
		},
		{
			name:  "invalid_json_response",
			code:  "valid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader("invalid json")),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to parse identity info\n",
		},
		{
			name:  "database_save_user_failure",
			code:  "valid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								responseBody := `{
									"data": {
										"id": "test_user_123",
										"attributes": {
											"email": "test@example.com",
											"first_name": "Test",
											"last_name": "User"
										},
										"relationships": {
											"memberships": {
												"data": [{"id": "membership_123"}]
											}
										}
									},
									"included": [
										{
											"type": "member",
											"id": "membership_123",
											"attributes": {
												"patron_status": "active_patron"
											},
											"relationships": {
												"campaign": {
													"data": {
														"id": "14358641",
														"type": "campaign"
													}
												},
												"currently_entitled_tiers": {
													"data": [
														{
															"id": "tier_1",
															"type": "tier"
														}
													]
												}
											}
										},
										{
											"type": "tier",
											"id": "tier_1",
											"attributes": {
												"title": "Apprentice"
											}
										}
									]
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to save user: database error\n",
		},
		{
			name:  "fulfill_token_login_failure",
			code:  "valid_code",
			state: "login_token_123",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								responseBody := `{
									"data": {
										"id": "test_user_123",
										"attributes": {
											"email": "test@example.com",
											"first_name": "Test",
											"last_name": "User"
										},
										"relationships": {
											"memberships": {
												"data": [{"id": "membership_123"}]
											}
										}
									},
									"included": [
										{
											"type": "member",
											"id": "membership_123",
											"attributes": {
												"patron_status": "active_patron"
											},
											"relationships": {
												"campaign": {
													"data": {
														"id": "14358641",
														"type": "campaign"
													}
												},
												"currently_entitled_tiers": {
													"data": [
														{
															"id": "tier_1",
															"type": "tier"
														}
													]
												}
											}
										},
										{
											"type": "tier",
											"id": "tier_1",
											"attributes": {
												"title": "Apprentice"
											}
										}
									]
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to fulfill token login: token login error\n",
		},
		{
			name:  "store_refresh_token_failure",
			code:  "valid_code",
			state: "",
			mockExchange: func(code string) (*oauth2.Token, error) {
				return &oauth2.Token{
					AccessToken:  "access_token_123",
					RefreshToken: "refresh_token_123",
				}, nil
			},
			mockHTTPClient: func() *http.Client {
				return &http.Client{
					Transport: &MockHTTPClientWrapper{
						&MockHTTPClient{
							doFunc: func(req *http.Request) (*http.Response, error) {
								responseBody := `{
									"data": {
										"id": "test_user_123",
										"attributes": {
											"email": "test@example.com",
											"first_name": "Test",
											"last_name": "User"
										},
										"relationships": {
											"memberships": {
												"data": [{"id": "membership_123"}]
											}
										}
									},
									"included": [
										{
											"type": "member",
											"id": "membership_123",
											"attributes": {
												"patron_status": "active_patron"
											},
											"relationships": {
												"campaign": {
													"data": {
														"id": "14358641",
														"type": "campaign"
													}
												},
												"currently_entitled_tiers": {
													"data": [
														{
															"id": "tier_1",
															"type": "tier"
														}
													]
												}
											}
										},
										{
											"type": "tier",
											"id": "tier_1",
											"attributes": {
												"title": "Apprentice"
											}
										}
									]
								}`
								return &http.Response{
									StatusCode: 200,
									Body:       io.NopCloser(strings.NewReader(responseBody)),
								}, nil
							},
						},
					},
				}
			},
			mockDB:         &MockDatabase{},
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "Failed to store refresh token\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up environment
			os.Setenv("JWT_SECRET_CURRENT", "test_secret_key_for_jwt_signing")

			// Set up mock expectations for database calls
			if strings.Contains(tt.name, "successful_authentication") {
				tt.mockDB.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				tt.mockDB.On("GetUserAccount", mock.Anything, mock.Anything).Return(db.UserAccount{ID: "test-uuid-1234", PatreonID: "test_user_123", TierID: "apprentice", PatronStatus: "active_patron"}, nil)
				tt.mockDB.On("StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				// Only expect FulfillTokenLogin if state is not "state" and not empty
				if strings.Contains(tt.name, "token_login") && tt.state != "state" && tt.state != "" {
					tt.mockDB.On("FulfillTokenLogin", mock.Anything, mock.Anything, mock.Anything).Return(nil)
				}
			} else if strings.Contains(tt.name, "database_save_user_failure") {
				tt.mockDB.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("database error"))
			} else if strings.Contains(tt.name, "fulfill_token_login_failure") {
				tt.mockDB.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				tt.mockDB.On("GetUserAccount", mock.Anything, mock.Anything).Return(db.UserAccount{ID: "test-uuid-1234", PatreonID: "test_user_123", TierID: "apprentice", PatronStatus: "active_patron"}, nil)
				tt.mockDB.On("FulfillTokenLogin", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("token login error"))
			} else if strings.Contains(tt.name, "store_refresh_token_failure") {
				tt.mockDB.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
				tt.mockDB.On("GetUserAccount", mock.Anything, mock.Anything).Return(db.UserAccount{ID: "test-uuid-1234", PatreonID: "test_user_123", TierID: "apprentice", PatronStatus: "active_patron"}, nil)
				tt.mockDB.On("StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("refresh token error"))
			}

			// Create mock OAuth config
			mockOAuthConfig := &MockOAuth2Config{
				exchangeFunc: tt.mockExchange,
				clientFunc: func(token *oauth2.Token) *http.Client {
					return tt.mockHTTPClient()
				},
			}

			// Create PatreonAuth with mocks
			auth := NewPatreonAuth(tt.mockDB, mockOAuthConfig)

			// Create request
			req := httptest.NewRequest("GET", "/callback", nil)
			q := req.URL.Query()
			q.Add("code", tt.code)
			if tt.state != "" {
				q.Add("state", tt.state)
			}
			req.URL.RawQuery = q.Encode()

			// Create response recorder
			w := httptest.NewRecorder()

			// Call HandleCallback
			auth.HandleCallback(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check response body
			if !strings.Contains(w.Body.String(), tt.expectedBody) {
				t.Errorf("expected body to contain '%s', got '%s'", tt.expectedBody, w.Body.String())
			}

			// Check JSON response format if expected
			if tt.checkCookies {
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				if err != nil {
					t.Errorf("expected valid JSON response, got error: %v", err)
				}

				// Verify response structure
				if response["status"] != "ok" {
					t.Errorf("expected status 'ok', got '%v'", response["status"])
				}
				if response["message"] != "authenticated" {
					t.Errorf("expected message 'authenticated', got '%v'", response["message"])
				}
				if response["token"] == nil || response["token"] == "" {
					t.Error("expected token to be present in response")
				}
				if response["refresh_token"] == nil || response["refresh_token"] == "" {
					t.Error("expected refresh_token to be present in response")
				}
			}

			// Verify all mock expectations were met
			tt.mockDB.AssertExpectations(t)
		})
	}
}

func TestNewPatreonAuth(t *testing.T) {
	mockDB := &MockDatabase{}
	config := &oauth2.Config{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
	}

	auth := NewPatreonAuth(mockDB, config)

	assert.NotNil(t, auth)
	assert.Equal(t, mockDB, auth.db)
	assert.Equal(t, config, auth.patreonOAuthConfig)
}

func TestPatreonAuth_HandleLogin(t *testing.T) {
	mockDB := &MockDatabase{}
	config := &oauth2.Config{
		ClientID:     "test_client_id",
		ClientSecret: "test_client_secret",
		RedirectURL:  "http://localhost:8080/auth/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://www.patreon.com/oauth2/authorize",
		},
	}

	auth := NewPatreonAuth(mockDB, config)

	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()

	auth.HandleLogin(w, req)

	assert.Equal(t, http.StatusTemporaryRedirect, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "https://www.patreon.com/oauth2/authorize")
}

// identityWith returns a Patreon identity response with one membership of the
// Forge Realm campaign. Empty status is sent as null; empty tier means none entitled.
func identityWith(status, tierTitle string) string {
	statusJSON := "null"
	if status != "" {
		statusJSON = fmt.Sprintf("%q", status)
	}
	tiers, tierInc := `[]`, ``
	if tierTitle != "" {
		tiers = `[{"id": "tier_1", "type": "tier"}]`
		tierInc = fmt.Sprintf(`, {"type": "tier", "id": "tier_1", "attributes": {"title": %q}}`, tierTitle)
	}
	return fmt.Sprintf(`{
		"data": {"id": "lapsed_user", "attributes": {"email": "l@example.com"},
			"relationships": {"memberships": {"data": [{"id": "m1"}]}}},
		"included": [{"type": "member", "id": "m1", "attributes": {"patron_status": %s},
			"relationships": {"campaign": {"data": {"id": "14358641", "type": "campaign"}},
				"currently_entitled_tiers": {"data": %s}}}%s]
	}`, statusJSON, tiers, tierInc)
}

func callbackWithIdentity(t *testing.T, mockDB *MockDatabase, identity string) *httptest.ResponseRecorder {
	t.Helper()
	cfg := &MockOAuth2Config{
		exchangeFunc: func(code string) (*oauth2.Token, error) { return &oauth2.Token{AccessToken: "a"}, nil },
		clientFunc: func(token *oauth2.Token) *http.Client {
			return &http.Client{Transport: &MockHTTPClientWrapper{&MockHTTPClient{
				doFunc: func(req *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(identity))}, nil
				},
			}}}
		},
	}
	w := httptest.NewRecorder()
	NewPatreonAuth(mockDB, cfg).HandleCallback(w, httptest.NewRequest("GET", "/auth/callback?code=c", nil))
	return w
}

func TestHandleCallback_AdmitsLapsedPatrons(t *testing.T) {
	for _, tt := range []struct{ status, tier, wantTier string }{
		{"active_patron", "Journeyman", "journeyman"},
		{"declined_patron", "Journeyman", "journeyman"},
		{"former_patron", "", "non_patron"},
	} {
		t.Run(tt.status, func(t *testing.T) {
			mockDB := &MockDatabase{}
			mockDB.On("SaveUser", mock.Anything, "lapsed_user", mock.Anything, mock.Anything, mock.Anything, tt.wantTier, tt.status, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			mockDB.On("GetUserAccount", mock.Anything, "lapsed_user").Return(db.UserAccount{ID: "uuid-1", PatreonID: "lapsed_user", TierID: tt.wantTier, PatronStatus: tt.status}, nil)
			mockDB.On("StoreRefreshToken", mock.Anything, "lapsed_user", mock.Anything).Return(nil)

			w := callbackWithIdentity(t, mockDB, identityWith(tt.status, tt.tier))
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var resp AuthResponse
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			claims, err := validateJWT(resp.Token)
			require.NoError(t, err)
			assert.Equal(t, "uuid-1", claims["sub"])
			assert.Equal(t, tt.wantTier, claims["tier"])
			assert.Equal(t, tt.status, claims["patron_status"])
			mockDB.AssertExpectations(t)
		})
	}
}

func TestHandleCallback_RefusesNullStatus(t *testing.T) {
	mockDB := &MockDatabase{}
	w := callbackWithIdentity(t, mockDB, identityWith("", ""))
	assert.Equal(t, http.StatusForbidden, w.Code)
	mockDB.AssertNotCalled(t, "SaveUser")
}

func TestHandleCallback_RefusesClosedAccount(t *testing.T) {
	mockDB := &MockDatabase{}
	mockDB.On("SaveUser", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockDB.On("GetUserAccount", mock.Anything, "lapsed_user").Return(db.UserAccount{ID: "uuid-1", PatreonID: "lapsed_user", Closed: true}, nil)

	w := callbackWithIdentity(t, mockDB, identityWith("active_patron", "Apprentice"))
	assert.Equal(t, http.StatusForbidden, w.Code)
	mockDB.AssertNotCalled(t, "StoreRefreshToken")
}
