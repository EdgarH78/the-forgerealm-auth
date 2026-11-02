package db

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidRefreshToken means the refresh token is unknown, expired or already used.
var ErrInvalidRefreshToken = errors.New("invalid refresh token")

// UserAccount is what a token is issued from: the user's id, current tier and
// Patreon status, and whether the account is closed (ED77, ED78).
type UserAccount struct {
	ID           string
	PatreonID    string
	TierID       string
	PatronStatus string
	Closed       bool
}

// Charge is one paid Patreon charge, written to the credit outbox (ED76).
type Charge struct {
	Tier        string
	ChargedAt   time.Time
	AmountCents int
}

// WebhookRecord is everything one Patreon webhook changes, applied in one transaction.
type WebhookRecord struct {
	EventType    string
	PatreonID    string
	Email        string
	GivenName    string
	SurName      string
	TierID       string
	PatronStatus string // Patreon's value, or "" for null
	RawPayload   []byte
	// Charge is the member's last charge when it was paid, or nil.
	Charge *Charge
	// CloseReason closes the account when set ("Refunded by Patreon" or "Fraud").
	CloseReason string
}

// RecordWebhook upserts the user, stores the event, closes the account if asked,
// and writes the paid charge to the credit outbox, all in one transaction. A
// charge already recorded writes nothing, and a closed account gets no charge.
func (db *PostgresDB) RecordWebhook(ctx context.Context, rec WebhookRecord) error {
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin webhook transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	var closed bool
	err = tx.QueryRow(ctx, `
		INSERT INTO forgerealm_auth.users (patreon_id, email, given_name, sur_name, tier_id, patron_status)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, NULLIF($6, ''))
		ON CONFLICT (patreon_id) DO UPDATE
		SET email = COALESCE(NULLIF($2, ''), users.email),
			given_name = COALESCE(NULLIF($3, ''), users.given_name),
			sur_name = COALESCE(NULLIF($4, ''), users.sur_name),
			tier_id = $5,
			patron_status = NULLIF($6, ''),
			updated_at = CURRENT_TIMESTAMP
		RETURNING id::text, closed_at IS NOT NULL
	`, rec.PatreonID, rec.Email, rec.GivenName, rec.SurName, rec.TierID, rec.PatronStatus).Scan(&userID, &closed)
	if err != nil {
		return fmt.Errorf("upsert webhook user: %w", err)
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO forgerealm_auth.webhook_events (event_type_id, patreon_id, tier_id, patron_status, raw_payload)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5)
	`, rec.EventType, rec.PatreonID, rec.TierID, rec.PatronStatus, rec.RawPayload); err != nil {
		return fmt.Errorf("insert webhook event: %w", err)
	}

	if rec.CloseReason != "" && !closed {
		if _, err = tx.Exec(ctx, `
			UPDATE forgerealm_auth.users SET closed_at = now(), closed_reason = $2
			WHERE id = $1 AND closed_at IS NULL
		`, userID, rec.CloseReason); err != nil {
			return fmt.Errorf("close account: %w", err)
		}
		closed = true
		log.Printf("INFO: Closed account %s (Patreon ID: %s): %s", userID, rec.PatreonID, rec.CloseReason)
	}

	if rec.Charge != nil && !closed {
		if _, err = tx.Exec(ctx, `
			INSERT INTO forgerealm_auth.credit_outbox (user_id, tier, charged_at, amount_cents)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (user_id, charged_at) DO NOTHING
		`, userID, rec.Charge.Tier, rec.Charge.ChargedAt.UTC().Truncate(time.Second), rec.Charge.AmountCents); err != nil {
			return fmt.Errorf("insert credit outbox row: %w", err)
		}
	}

	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit webhook transaction: %w", err)
	}
	return nil
}

// RotateRefreshToken revokes a valid refresh token and returns its Patreon ID.
// A token can be used once; a second use returns ErrInvalidRefreshToken.
func (db *PostgresDB) RotateRefreshToken(ctx context.Context, token string) (string, error) {
	var patreonID string
	err := db.pool.QueryRow(ctx, `
		UPDATE forgerealm_auth.refresh_tokens SET revoked = true
		WHERE id = $1 AND NOT revoked AND expires_at > CURRENT_TIMESTAMP
		RETURNING patreon_id
	`, hashToken(token)).Scan(&patreonID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidRefreshToken
	}
	if err != nil {
		return "", fmt.Errorf("rotate refresh token: %w", err)
	}
	return patreonID, nil
}

// GetUserAccount returns the account a token is issued from. A null tier reads
// as non_patron.
func (db *PostgresDB) GetUserAccount(ctx context.Context, patreonID string) (UserAccount, error) {
	acct := UserAccount{PatreonID: patreonID}
	var tier, status *string
	err := db.pool.QueryRow(ctx, `
		SELECT id::text, tier_id, patron_status, closed_at IS NOT NULL
		FROM forgerealm_auth.users WHERE patreon_id = $1
	`, patreonID).Scan(&acct.ID, &tier, &status, &acct.Closed)
	if err != nil {
		return UserAccount{}, fmt.Errorf("get user account %s: %w", patreonID, err)
	}
	acct.TierID = "non_patron"
	if tier != nil && *tier != "" {
		acct.TierID = *tier
	}
	if status != nil {
		acct.PatronStatus = *status
	}
	return acct, nil
}
