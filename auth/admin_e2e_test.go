package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"forgerealm-auth/db"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestE2E_AdminRoleAndLookup(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup()
	setAdminEnv(t)
	ctx := context.Background()
	pool := tc.db.GetPool()

	insert := func(patreonID, email string) string {
		var id string
		require.NoError(t, pool.QueryRow(ctx, `
			INSERT INTO forgerealm_auth.users (patreon_id, email, tier_id, patron_status)
			VALUES ($1, $2, 'master', 'active_patron') RETURNING id::text`, patreonID, email).Scan(&id))
		return id
	}
	edgarID := insert("p_admin", "Admin@Example.com")
	otherID := insert("p_other", "other@example.com")
	insert("p_dup1", "dup@example.com")
	insert("p_dup2", "DUP@example.com")

	// New users default to role user; an unknown role fails the FK.
	role, closed, err := tc.db.GetUserRole(ctx, otherID)
	require.NoError(t, err)
	assert.Equal(t, "user", role)
	assert.False(t, closed)
	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET role_id = 'super_admin' WHERE id = $1`, otherID)
	assert.Error(t, err)
	_, _, err = tc.db.GetUserRole(ctx, "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, db.ErrUserNotFound)

	a := NewAdmin(tc.db)
	tokenFor := func(id string) string {
		return userToken(t, func(c jwt.MapClaims) { c["sub"] = id })
	}

	assert.Equal(t, http.StatusForbidden, exchange(a, tokenFor(edgarID)).Code, "role user before the SQL update")

	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET role_id = 'admin' WHERE id = $1`, edgarID)
	require.NoError(t, err)
	w := exchange(a, tokenFor(edgarID))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	claims := assertAtlasForgeAccepts(t, body["token"])
	assert.Equal(t, edgarID, claims["sub"])
	adminTok := body["token"]

	// Lookups with the issued token.
	w = lookup(a, adminTok, "email=%20other%40EXAMPLE.com")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.JSONEq(t, `{"userId":"`+otherID+`","email":"other@example.com","tier":"master","patronStatus":"active_patron"}`, w.Body.String())
	w = lookup(a, adminTok, "patreon_id=p_other")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), otherID)
	assert.Equal(t, http.StatusConflict, lookup(a, adminTok, "email=dup@example.com").Code)
	assert.Equal(t, http.StatusOK, lookup(a, adminTok, "patreon_id=p_dup2").Code)
	assert.Equal(t, http.StatusNotFound, lookup(a, adminTok, "email=nobody@example.com").Code)
	assert.Equal(t, http.StatusNotFound, lookup(a, adminTok, "patreon_id=nope").Code)

	// A null tier and status read as non_patron.
	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET tier_id = NULL, patron_status = NULL WHERE id = $1`, otherID)
	require.NoError(t, err)
	assert.JSONEq(t, `{"userId":"`+otherID+`","email":"other@example.com","tier":"non_patron","patronStatus":"non_patron"}`,
		lookup(a, adminTok, "patreon_id=p_other").Body.String())

	// Removing the role refuses the next exchange; a closed admin is refused too.
	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET role_id = 'user' WHERE id = $1`, edgarID)
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, exchange(a, tokenFor(edgarID)).Code)
	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET role_id = 'admin', closed_at = $2 WHERE id = $1`, edgarID, time.Now())
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, exchange(a, tokenFor(edgarID)).Code)

	// Login and webhooks never touch the role.
	_, err = pool.Exec(ctx, `UPDATE forgerealm_auth.users SET closed_at = NULL WHERE id = $1`, edgarID)
	require.NoError(t, err)
	require.NoError(t, tc.db.SaveUser(ctx, "p_admin", "admin@example.com", "E", "H", "master", "active_patron", "", "", pgtype.Timestamp{Time: time.Now(), Valid: true}))
	t.Setenv("WEB_HOOK_SECRET", testWebhookSecret)
	require.Equal(t, http.StatusOK, postWebhook(t, NewPatreonAuth(tc.db, &oauth2.Config{}), "members:pledge:update",
		memberWebhook("p_admin", "Master", "active_patron", "", "", 1500)).Code)
	role, _, err = tc.db.GetUserRole(ctx, edgarID)
	require.NoError(t, err)
	assert.Equal(t, "admin", role)
}
