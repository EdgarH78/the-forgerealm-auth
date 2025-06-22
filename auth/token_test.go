package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockTokenDatabase struct {
	mock.Mock
}

func (m *MockTokenDatabase) SaveTokenLogin(ctx context.Context, token string, expiresAt time.Time) error {
	args := m.Called(ctx, token, expiresAt)
	return args.Error(0)
}

func (m *MockTokenDatabase) CheckTokenLogin(ctx context.Context, token string) (bool, error) {
	args := m.Called(ctx, token)
	return args.Bool(0), args.Error(1)
}

func TestStartTokenLogin_Success(t *testing.T) {
	mockDB := new(MockTokenDatabase)
	tokenLogin := &TokenLogin{db: mockDB}

	// We don't know the token value in advance, so use mock.Anything
	mockDB.On("SaveTokenLogin", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	req := httptest.NewRequest("POST", "/auth/token/start", nil)
	w := httptest.NewRecorder()

	tokenLogin.StartTokenLogin(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
	mockDB.AssertCalled(t, "SaveTokenLogin", mock.Anything, mock.Anything, mock.Anything)
}

func TestStartTokenLogin_DBError(t *testing.T) {
	mockDB := new(MockTokenDatabase)
	tokenLogin := &TokenLogin{db: mockDB}
	mockDB.On("SaveTokenLogin", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("db error"))

	req := httptest.NewRequest("POST", "/auth/token/start", nil)
	w := httptest.NewRecorder()

	tokenLogin.StartTokenLogin(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "Failed to create login token")
}

func TestCheckTokenStatus_Success(t *testing.T) {
	mockDB := new(MockTokenDatabase)
	tokenLogin := &TokenLogin{db: mockDB}
	mockDB.On("CheckTokenLogin", mock.Anything, "sometoken").Return(true, nil)

	req := httptest.NewRequest("GET", "/auth/token/status?token=sometoken", nil)
	w := httptest.NewRecorder()

	tokenLogin.CheckTokenStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]bool
	err := json.NewDecoder(w.Body).Decode(&resp)
	assert.NoError(t, err)
	assert.Equal(t, true, resp["fulfilled"])
}

func TestCheckTokenStatus_MissingToken(t *testing.T) {
	mockDB := new(MockTokenDatabase)
	tokenLogin := &TokenLogin{db: mockDB}

	req := httptest.NewRequest("GET", "/auth/token/status", nil)
	w := httptest.NewRecorder()

	tokenLogin.CheckTokenStatus(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Missing token")
}

func TestCheckTokenStatus_DBError(t *testing.T) {
	mockDB := new(MockTokenDatabase)
	tokenLogin := &TokenLogin{db: mockDB}
	mockDB.On("CheckTokenLogin", mock.Anything, "badtoken").Return(false, errors.New("not found"))

	req := httptest.NewRequest("GET", "/auth/token/status?token=badtoken", nil)
	w := httptest.NewRecorder()

	tokenLogin.CheckTokenStatus(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}
