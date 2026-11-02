// Package mockpatreon fakes the parts of Patreon that forgerealm-auth calls
// during login (AUTH-3): the authorize page, the token exchange and the v2
// identity endpoint. It is for local development and tests only; the command
// is cmd/mockpatreon.
package mockpatreon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type grant struct {
	user        User
	redirectURI string
}

// Server is the mock. Codes and tokens live in memory.
type Server struct {
	clientID     string
	clientSecret string

	mu     sync.Mutex
	codes  map[string]grant // single use
	tokens map[string]User  // access token to user
}

// NewServer accepts only this client id and secret.
func NewServer(clientID, clientSecret string) *Server {
	return &Server{clientID: clientID, clientSecret: clientSecret, codes: map[string]grant{}, tokens: map[string]User{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /oauth2/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /api/oauth2/token", s.handleToken)
	mux.HandleFunc("GET /api/oauth2/v2/identity", s.handleIdentity)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("OK")) })
	return mux
}

func randomHex() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

var authorizePage = template.Must(template.New("authorize").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><title>Mock Patreon</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:2rem auto;padding:0 1rem}
a{display:block;padding:.6rem .8rem;margin:.4rem 0;border:1px solid #888;border-radius:6px;text-decoration:none;color:inherit}
small{color:#666}</style></head>
<body><h1>Mock Patreon</h1><p>Log in as:</p>
{{range .}}<a href="{{.Link}}"><b>{{.User.Key}}</b> <small>{{.User.Note}}</small></a>
{{end}}</body></html>`))

// handleAuthorize shows the test users, or with mock_user redirects straight
// back to redirect_uri with a code and the state unchanged.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != s.clientID {
		http.Error(w, "response_type must be code and client_id must match", http.StatusBadRequest)
		return
	}
	redirectURI, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redirectURI.Scheme == "" || redirectURI.Host == "" {
		http.Error(w, "redirect_uri must be an absolute URL", http.StatusBadRequest)
		return
	}

	key := q.Get("mock_user")
	if key == "" {
		type option struct {
			User User
			Link string
		}
		options := make([]option, 0, len(Users))
		for _, u := range Users {
			pick := r.URL.Query()
			pick.Set("mock_user", u.Key)
			options = append(options, option{User: u, Link: r.URL.Path + "?" + pick.Encode()})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := authorizePage.Execute(w, options); err != nil {
			log.Printf("ERROR: render authorize page: %v", err)
		}
		return
	}
	user, ok := findUser(key)
	if !ok {
		http.Error(w, "unknown mock_user "+key, http.StatusBadRequest)
		return
	}

	code := randomHex()
	s.mu.Lock()
	s.codes[code] = grant{user: user, redirectURI: redirectURI.String()}
	s.mu.Unlock()

	back := redirectURI.Query()
	back.Set("code", code)
	back.Set("state", q.Get("state"))
	redirectURI.RawQuery = back.Encode()
	log.Printf("INFO: authorize %s, redirecting to %s", user.Key, redirectURI.Host+redirectURI.Path)
	http.Redirect(w, r, redirectURI.String(), http.StatusFound)
}

func tokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// handleToken exchanges a code once for an access token. The client may send
// its credentials as HTTP basic auth or as form fields, as Patreon accepts.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if !equal(id, s.clientID) || !equal(secret, s.clientSecret) {
		tokenError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		tokenError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	s.mu.Lock()
	g, found := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	s.mu.Unlock()
	if !found || g.redirectURI != r.PostForm.Get("redirect_uri") {
		tokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	access := "mock-access-" + randomHex()
	s.mu.Lock()
	s.tokens[access] = g.user
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"refresh_token": "mock-refresh-" + randomHex(),
		"expires_in":    2678400,
		"token_type":    "Bearer",
		"scope":         "identity identity[email] identity.memberships",
	})
}

type ref struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// handleIdentity returns the v2 identity document with the user's memberships,
// their campaign and entitled tiers included, as Patreon does for
// include=memberships,memberships.campaign,memberships.currently_entitled_tiers.
func (s *Server) handleIdentity(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	user, known := s.tokens[token]
	s.mu.Unlock()
	if !ok || !known {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]any{"errors": []map[string]any{{"code": 1, "status": "401", "title": "Unauthorized"}}})
		return
	}
	w.Header().Set("Content-Type", "application/vnd.api+json")
	_ = json.NewEncoder(w).Encode(identityDocument(user))
}

func identityDocument(u User) map[string]any {
	memberships := []ref{}
	included := []any{}
	if u.Campaign != "" {
		memberID := "member-" + u.PatreonID
		memberships = append(memberships, ref{ID: memberID, Type: "member"})
		tiers := []ref{}
		var status any
		if u.PatronStatus != "" {
			status = u.PatronStatus
		}
		if u.Tier != "" {
			tierID := "tier-" + strings.ToLower(u.Tier)
			tiers = append(tiers, ref{ID: tierID, Type: "tier"})
			included = append(included, map[string]any{"id": tierID, "type": "tier", "attributes": map[string]any{"title": u.Tier}})
		}
		included = append(included,
			map[string]any{
				"id": memberID, "type": "member",
				"attributes": map[string]any{"patron_status": status},
				"relationships": map[string]any{
					"campaign":                 map[string]any{"data": ref{ID: u.Campaign, Type: "campaign"}},
					"currently_entitled_tiers": map[string]any{"data": tiers},
				},
			},
			map[string]any{"id": u.Campaign, "type": "campaign", "attributes": map[string]any{}},
		)
	}
	return map[string]any{
		"data": map[string]any{
			"id": u.PatreonID, "type": "user",
			"attributes": map[string]any{"email": u.Email, "first_name": u.FirstName, "last_name": u.LastName},
			"relationships": map[string]any{
				"memberships": map[string]any{"data": memberships},
			},
		},
		"included": included,
		"links":    map[string]any{"self": "https://www.patreon.com/api/oauth2/v2/user/" + u.PatreonID},
	}
}
