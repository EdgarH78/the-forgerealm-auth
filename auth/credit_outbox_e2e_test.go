package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"forgerealm-auth/db"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const testWebhookSecret = "test_webhook_secret_for_testing"

// memberWebhook builds a Patreon member webhook body. An empty tierTitle means no
// entitled tier; empty patronStatus, chargeStatus or chargeDate are sent as null.
func memberWebhook(patreonID, tierTitle, patronStatus, chargeStatus, chargeDate string, amountCents int) string {
	nullable := func(v string) string {
		if v == "" {
			return "null"
		}
		return fmt.Sprintf("%q", v)
	}
	tiers := `[]`
	included := fmt.Sprintf(`{"type": "user", "id": %q, "attributes": {"first_name": "Pat", "last_name": "Ron"}}`, patreonID)
	if tierTitle != "" {
		tiers = `[{"id": "tier_9", "type": "tier"}]`
		included += fmt.Sprintf(`, {"type": "tier", "id": "tier_9", "attributes": {"title": %q}}`, tierTitle)
	}
	return fmt.Sprintf(`{
		"data": {
			"type": "member",
			"id": "member-%s",
			"attributes": {
				"email": "%s@example.com",
				"patron_status": %s,
				"last_charge_status": %s,
				"last_charge_date": %s,
				"currently_entitled_amount_cents": %d
			},
			"relationships": {
				"user": {"data": {"id": %q, "type": "user"}},
				"currently_entitled_tiers": {"data": %s}
			}
		},
		"included": [%s]
	}`, patreonID, patreonID, nullable(patronStatus), nullable(chargeStatus), nullable(chargeDate), amountCents, patreonID, tiers, included)
}

func postWebhook(t *testing.T, a *PatreonAuth, event, body string) *httptest.ResponseRecorder {
	t.Helper()
	h := hmac.New(md5.New, []byte(testWebhookSecret))
	h.Write([]byte(body))
	req := httptest.NewRequest("POST", "/auth/webhook", bytes.NewBufferString(body))
	req.Header.Set("X-Patreon-Signature", hex.EncodeToString(h.Sum(nil)))
	if event != "" {
		req.Header.Set("X-Patreon-Event", event)
	}
	w := httptest.NewRecorder()
	a.HandleWebhook(w, req)
	return w
}

type outboxRow struct {
	UserID      string
	Tier        string
	ChargedAt   time.Time
	AmountCents int
}

func outboxRows(t *testing.T, tc *TestContainer, patreonID string) []outboxRow {
	t.Helper()
	rows, err := tc.db.GetPool().Query(context.Background(), `
		SELECT o.user_id::text, o.tier, o.charged_at, o.amount_cents
		FROM forgerealm_auth.credit_outbox o JOIN forgerealm_auth.users u ON u.id = o.user_id
		WHERE u.patreon_id = $1 ORDER BY o.id`, patreonID)
	require.NoError(t, err)
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (outboxRow, error) {
		var o outboxRow
		err := r.Scan(&o.UserID, &o.Tier, &o.ChargedAt, &o.AmountCents)
		return o, err
	})
	require.NoError(t, err)
	return out
}

func eventCount(t *testing.T, tc *TestContainer, patreonID string) int {
	t.Helper()
	var n int
	require.NoError(t, tc.db.GetPool().QueryRow(context.Background(),
		`SELECT count(*) FROM forgerealm_auth.webhook_events WHERE patreon_id = $1`, patreonID).Scan(&n))
	return n
}

func TestE2E_CreditOutbox(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup()
	t.Setenv("WEB_HOOK_SECRET", testWebhookSecret)
	a := NewPatreonAuth(tc.db, &oauth2.Config{})
	ctx := context.Background()

	t.Run("charged_at must be whole seconds", func(t *testing.T) {
		_, err := tc.db.GetPool().Exec(ctx, `
			INSERT INTO forgerealm_auth.credit_outbox (user_id, tier, charged_at, amount_cents)
			VALUES (gen_random_uuid(), 'apprentice', '2026-10-01T12:00:00.5Z', 300)`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "credit_outbox_charged_at_whole_seconds")
	})

	t.Run("outbox role reads the outbox and updates only bookkeeping", func(t *testing.T) {
		_, err := tc.db.GetPool().Exec(ctx, `ALTER ROLE atlasforge_credit_outbox LOGIN PASSWORD 'outbox_test'`)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:create",
			memberWebhook("role_user", "Apprentice", "active_patron", "Paid", "2026-10-01T12:00:00+00:00", 500)).Code)

		roleURL := strings.Replace(tc.connStr, "testuser:testpass", "atlasforge_credit_outbox:outbox_test", 1)
		conn, err := pgx.Connect(ctx, roleURL)
		require.NoError(t, err)
		defer conn.Close(ctx)

		var n int
		require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM forgerealm_auth.credit_outbox`).Scan(&n))
		assert.Equal(t, 1, n)
		_, err = conn.Exec(ctx, `UPDATE forgerealm_auth.credit_outbox SET claimed_at = now(), attempts = attempts + 1, last_error = 'x', completed_at = now()`)
		assert.NoError(t, err)

		for _, stmt := range []string{
			`UPDATE forgerealm_auth.credit_outbox SET tier = 'master'`,
			`UPDATE forgerealm_auth.credit_outbox SET amount_cents = 0`,
			`INSERT INTO forgerealm_auth.credit_outbox (user_id, tier, charged_at, amount_cents) VALUES (gen_random_uuid(), 'master', now()::timestamp(0), 1)`,
			`DELETE FROM forgerealm_auth.credit_outbox`,
			`SELECT count(*) FROM forgerealm_auth.users`,
			`SELECT count(*) FROM forgerealm_auth.refresh_tokens`,
		} {
			_, err := conn.Exec(ctx, stmt)
			assert.Error(t, err, stmt)
		}
	})

	t.Run("a paid charge writes one row with the charge's user, tier, second and amount", func(t *testing.T) {
		body := memberWebhook("paid_user", "Journeyman", "active_patron", "Paid", "2026-10-05T08:30:15.789+00:00", 1000)
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:create", body).Code)
		// Patreon resends, and other event types carry the same charge.
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:create", body).Code)
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:update", body).Code)

		rows := outboxRows(t, tc, "paid_user")
		require.Len(t, rows, 1)
		acct, err := tc.db.GetUserAccount(ctx, "paid_user")
		require.NoError(t, err)
		assert.Equal(t, acct.ID, rows[0].UserID)
		assert.Equal(t, "journeyman", rows[0].Tier)
		assert.True(t, rows[0].ChargedAt.Equal(time.Date(2026, 10, 5, 8, 30, 15, 0, time.UTC)), rows[0].ChargedAt)
		assert.Equal(t, 1000, rows[0].AmountCents)
		assert.Equal(t, 3, eventCount(t, tc, "paid_user"))

		// The next month's charge is a second row.
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
			memberWebhook("paid_user", "Journeyman", "active_patron", "Paid", "2026-11-05T08:30:15+00:00", 1000)).Code)
		assert.Len(t, outboxRows(t, tc, "paid_user"), 2)
	})

	t.Run("no row unless the last charge was paid and a tier is entitled", func(t *testing.T) {
		for i, body := range []string{
			memberWebhook("unpaid_user", "Apprentice", "declined_patron", "Declined", "2026-10-01T00:00:00+00:00", 500),
			memberWebhook("unpaid_user", "Apprentice", "active_patron", "Pending", "2026-10-02T00:00:00+00:00", 500),
			memberWebhook("unpaid_user", "Apprentice", "active_patron", "", "", 500),
			memberWebhook("unpaid_user", "", "former_patron", "Paid", "2026-10-03T00:00:00+00:00", 0),
		} {
			require.Equal(t, http.StatusOK, postWebhook(t, a, "members:update", body).Code, i)
		}
		assert.Empty(t, outboxRows(t, tc, "unpaid_user"))
		acct, err := tc.db.GetUserAccount(ctx, "unpaid_user")
		require.NoError(t, err)
		assert.Equal(t, "non_patron", acct.TierID)
		assert.Equal(t, "former_patron", acct.PatronStatus)
	})

	t.Run("a failed outbox insert rolls back the user and the event", func(t *testing.T) {
		err := tc.db.RecordWebhook(ctx, db.WebhookRecord{
			EventType: "members:pledge:create", PatreonID: "rollback_user", Email: "r@example.com",
			TierID: "apprentice", PatronStatus: "active_patron", RawPayload: []byte(`{}`),
			Charge: &db.Charge{Tier: "apprentice", ChargedAt: time.Now(), AmountCents: -1},
		})
		require.Error(t, err)
		assert.Equal(t, 0, eventCount(t, tc, "rollback_user"))
		_, err = tc.db.GetUserAccount(ctx, "rollback_user")
		assert.Error(t, err)
	})

	t.Run("a Refunded charge leaves the account open", func(t *testing.T) {
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
			memberWebhook("refunded_user", "Apprentice", "active_patron", "Refunded", "2026-10-01T00:00:00+00:00", 500)).Code)
		acct, err := tc.db.GetUserAccount(ctx, "refunded_user")
		require.NoError(t, err)
		assert.False(t, acct.Closed)
	})

	for _, status := range []string{"Refunded by Patreon", "Fraud"} {
		t.Run(status+" closes the account for good", func(t *testing.T) {
			patreonID := strings.ReplaceAll(strings.ToLower(status), " ", "_") + "_user"
			require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
				memberWebhook(patreonID, "Apprentice", "active_patron", "Paid", "2026-10-01T00:00:00+00:00", 500)).Code)
			require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
				memberWebhook(patreonID, "Apprentice", "active_patron", status, "2026-10-01T00:00:00+00:00", 500)).Code)
			acct, err := tc.db.GetUserAccount(ctx, patreonID)
			require.NoError(t, err)
			assert.True(t, acct.Closed)

			// A later paid charge neither reopens the account nor writes a row.
			require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
				memberWebhook(patreonID, "Apprentice", "active_patron", "Paid", "2026-11-01T00:00:00+00:00", 500)).Code)
			acct, err = tc.db.GetUserAccount(ctx, patreonID)
			require.NoError(t, err)
			assert.True(t, acct.Closed)
			assert.Len(t, outboxRows(t, tc, patreonID), 1, "only the charge before closing")
		})
	}

	t.Run("delete sets former_patron and non_patron", func(t *testing.T) {
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:create",
			memberWebhook("deleted_user", "Master", "active_patron", "", "", 2500)).Code)
		require.Equal(t, http.StatusOK, postWebhook(t, a, "members:delete",
			memberWebhook("deleted_user", "Master", "active_patron", "", "", 2500)).Code)
		acct, err := tc.db.GetUserAccount(ctx, "deleted_user")
		require.NoError(t, err)
		assert.Equal(t, "non_patron", acct.TierID)
		assert.Equal(t, "former_patron", acct.PatronStatus)
	})

	t.Run("the event type comes from the header", func(t *testing.T) {
		body := memberWebhook("header_user", "Apprentice", "active_patron", "Paid", "2026-10-01T00:00:00+00:00", 500)
		assert.Equal(t, http.StatusBadRequest, postWebhook(t, a, "", body).Code)
		assert.Equal(t, http.StatusOK, postWebhook(t, a, "posts:publish", body).Code)
		assert.Equal(t, 0, eventCount(t, tc, "header_user"))
	})

	t.Run("a tier missing from the tiers table answers 500 and records nothing", func(t *testing.T) {
		w := postWebhook(t, a, "members:pledge:create",
			memberWebhook("unknown_tier_user", "Grandmaster", "active_patron", "Paid", "2026-10-01T00:00:00+00:00", 9900))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, 0, eventCount(t, tc, "unknown_tier_user"))
	})

	t.Run("the signature uses WEB_HOOK_SECRET", func(t *testing.T) {
		body := memberWebhook("sig_user", "Apprentice", "active_patron", "", "", 500)
		t.Setenv("WEB_HOOK_SECRET", "a_different_secret")
		assert.Equal(t, http.StatusUnauthorized, postWebhook(t, a, "members:create", body).Code)
	})
}

func TestE2E_RefreshIssuesCurrentAccount(t *testing.T) {
	tc := setupTestContainer(t)
	defer tc.cleanup()
	t.Setenv("WEB_HOOK_SECRET", testWebhookSecret)
	a := NewPatreonAuth(tc.db, &oauth2.Config{})
	ctx := context.Background()

	refresh := func(token string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"refresh_token": token})
		w := httptest.NewRecorder()
		a.HandleRefresh(w, httptest.NewRequest("POST", "/auth/refresh", bytes.NewBuffer(body)))
		return w
	}

	require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:create",
		memberWebhook("refresh_user", "Master", "active_patron", "", "", 2500)).Code)
	require.NoError(t, tc.db.StoreRefreshToken(ctx, "refresh_user", "first_refresh_token"))

	// The membership lapses after the refresh token was issued.
	require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:delete",
		memberWebhook("refresh_user", "", "former_patron", "", "", 0)).Code)

	w := refresh("first_refresh_token")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp AuthResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	claims, err := validateJWT(resp.Token)
	require.NoError(t, err)
	acct, err := tc.db.GetUserAccount(ctx, "refresh_user")
	require.NoError(t, err)
	assert.Equal(t, acct.ID, claims["sub"])
	assert.Equal(t, "non_patron", claims["tier"])
	assert.Equal(t, "former_patron", claims["patron_status"])

	// The token it was given is spent; the new one works once.
	assert.Equal(t, http.StatusUnauthorized, refresh("first_refresh_token").Code)
	_, err = tc.db.VerifyRefreshToken(ctx, "first_refresh_token")
	assert.Error(t, err)

	// A closed account is refused.
	require.Equal(t, http.StatusOK, postWebhook(t, a, "members:pledge:update",
		memberWebhook("refresh_user", "Master", "active_patron", "Fraud", "2026-10-01T00:00:00+00:00", 2500)).Code)
	assert.Equal(t, http.StatusForbidden, refresh(resp.RefreshToken).Code)
}
