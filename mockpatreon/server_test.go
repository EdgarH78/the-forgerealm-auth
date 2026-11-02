package mockpatreon

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const callback = "http://auth.local/auth/callback"

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func newTestServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(NewServer("cid", "csecret").Handler())
	t.Cleanup(ts.Close)
	return ts
}

func authorizeURL(ts *httptest.Server, extra url.Values) string {
	q := url.Values{"response_type": {"code"}, "client_id": {"cid"}, "redirect_uri": {callback}, "state": {"app:atlasforge:abc"}}
	for k, v := range extra {
		q[k] = v
	}
	return ts.URL + "/oauth2/authorize?" + q.Encode()
}

// authorize picks a user and returns the code from the redirect.
func authorize(t *testing.T, ts *httptest.Server, key string) string {
	t.Helper()
	c := &http.Client{CheckRedirect: noRedirect}
	resp, err := c.Get(authorizeURL(ts, url.Values{"mock_user": {key}}))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	loc, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "auth.local", loc.Host)
	assert.Equal(t, "/auth/callback", loc.Path)
	assert.Equal(t, "app:atlasforge:abc", loc.Query().Get("state"))
	return loc.Query().Get("code")
}

func exchange(t *testing.T, ts *httptest.Server, form url.Values, basic bool) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+"/api/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth("cid", "csecret")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp, body
}

func codeForm(code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {callback}, "client_id": {"cid"}, "client_secret": {"csecret"}}
}

func TestAuthorizePageListsUsers(t *testing.T) {
	ts := newTestServer(t)
	resp, err := http.Get(authorizeURL(ts, nil))
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	buf := new(strings.Builder)
	_, _ = io.Copy(buf, resp.Body)
	for _, u := range Users {
		assert.Contains(t, buf.String(), "mock_user="+u.Key)
	}
	assert.Contains(t, buf.String(), "state=app%3Aatlasforge%3Aabc")
}

func TestAuthorizeRefusals(t *testing.T) {
	ts := newTestServer(t)
	for name, extra := range map[string]url.Values{
		"unknown user": {"mock_user": {"nobody"}},
		"wrong client": {"client_id": {"other"}},
		"no code type": {"response_type": {"token"}},
		"relative uri": {"redirect_uri": {"/auth/callback"}},
	} {
		resp, err := http.Get(authorizeURL(ts, extra))
		require.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, name)
	}
}

func TestTokenExchange(t *testing.T) {
	ts := newTestServer(t)

	resp, body := exchange(t, ts, codeForm(authorize(t, ts, "master")), false)
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, "Bearer", body["token_type"])
	assert.NotEmpty(t, body["access_token"])
	assert.NotEmpty(t, body["refresh_token"])

	// Basic auth works too; a code is single use.
	code := authorize(t, ts, "master")
	form := codeForm(code)
	form.Del("client_id")
	form.Del("client_secret")
	resp, _ = exchange(t, ts, form, true)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, body = exchange(t, ts, form, true)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])

	bad := codeForm(authorize(t, ts, "master"))
	bad.Set("client_secret", "wrong")
	resp, body = exchange(t, ts, bad, false)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, "invalid_client", body["error"])

	resp, body = exchange(t, ts, codeForm("unknown"), false)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])

	wrongURI := codeForm(authorize(t, ts, "master"))
	wrongURI.Set("redirect_uri", "http://elsewhere/cb")
	resp, _ = exchange(t, ts, wrongURI, false)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func identity(t *testing.T, ts *httptest.Server, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("GET", ts.URL+"/api/oauth2/v2/identity?include=memberships", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp.StatusCode, body
}

func TestIdentity(t *testing.T) {
	ts := newTestServer(t)
	status, _ := identity(t, ts, "")
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = identity(t, ts, "made-up")
	assert.Equal(t, http.StatusUnauthorized, status)

	for _, u := range Users {
		t.Run(u.Key, func(t *testing.T) {
			_, tok := exchange(t, ts, codeForm(authorize(t, ts, u.Key)), false)
			status, doc := identity(t, ts, tok["access_token"].(string))
			require.Equal(t, http.StatusOK, status)
			data := doc["data"].(map[string]any)
			assert.Equal(t, u.PatreonID, data["id"])
			assert.Equal(t, u.Email, data["attributes"].(map[string]any)["email"])
			mems := data["relationships"].(map[string]any)["memberships"].(map[string]any)["data"].([]any)
			require.Len(t, mems, 1)
			var member, tier map[string]any
			for _, x := range doc["included"].([]any) {
				m := x.(map[string]any)
				switch m["type"] {
				case "member":
					member = m
				case "tier":
					tier = m
				}
			}
			require.NotNil(t, member)
			rel := member["relationships"].(map[string]any)
			assert.Equal(t, u.Campaign, rel["campaign"].(map[string]any)["data"].(map[string]any)["id"])
			if u.Tier == "" {
				assert.Nil(t, tier)
				assert.Empty(t, rel["currently_entitled_tiers"].(map[string]any)["data"])
			} else {
				require.NotNil(t, tier)
				assert.Equal(t, u.Tier, tier["attributes"].(map[string]any)["title"])
			}
		})
	}
}
