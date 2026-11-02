package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"forgerealm-auth/auth"

	"github.com/stretchr/testify/assert"
)

// The admin screen calls both admin routes from the editor's origin with an
// Authorization header (PR-12b D7).
func TestCORS_AdminRoutesAllowEditorOrigin(t *testing.T) {
	r := router(auth.NewPatreonAuth(nil, nil), auth.NewTokenLogin(nil), auth.NewAdmin(nil))
	for _, route := range []struct{ method, path string }{{"POST", "/admin/token"}, {"GET", "/admin/users"}} {
		req := httptest.NewRequest("OPTIONS", route.path, nil)
		req.Header.Set("Origin", "https://editor.example.com")
		req.Header.Set("Access-Control-Request-Method", route.method)
		req.Header.Set("Access-Control-Request-Headers", "Authorization")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, route.path)
		assert.Equal(t, "https://editor.example.com", w.Header().Get("Access-Control-Allow-Origin"), route.path)
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), route.method, route.path)
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization", route.path)
	}
}
