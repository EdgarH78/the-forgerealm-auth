package db

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ErrUserNotFound means no user matches.
var ErrUserNotFound = errors.New("user not found")

// AdminRole is the role that may exchange a user token for an admin token.
const AdminRole = "admin"

// UserSummary is what the admin lookup returns about a user.
type UserSummary struct {
	ID           string
	Email        string
	TierID       string // non_patron when null
	PatronStatus string // "" when null
}

// GetUserRole returns a user's role and whether the account is closed, read at
// call time so a role change applies to the next exchange.
func (db *PostgresDB) GetUserRole(ctx context.Context, userID string) (string, bool, error) {
	var role string
	var closed bool
	err := db.pool.QueryRow(ctx, `
		SELECT role_id, closed_at IS NOT NULL FROM forgerealm_auth.users WHERE id = $1::uuid
	`, userID).Scan(&role, &closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrUserNotFound
	}
	if err != nil {
		return "", false, fmt.Errorf("get user role %s: %w", userID, err)
	}
	return role, closed, nil
}

// FindUsersByEmail returns up to two users with this email, trimmed and
// compared case-insensitively. Emails aren't unique, so two means ambiguous.
func (db *PostgresDB) FindUsersByEmail(ctx context.Context, email string) ([]UserSummary, error) {
	return db.findUsers(ctx, `lower(email) = lower($1) ORDER BY updated_at DESC LIMIT 2`, strings.TrimSpace(email))
}

// FindUserByPatreonID returns the user with this Patreon id, which is unique.
func (db *PostgresDB) FindUserByPatreonID(ctx context.Context, patreonID string) (UserSummary, error) {
	users, err := db.findUsers(ctx, `patreon_id = $1`, strings.TrimSpace(patreonID))
	if err != nil {
		return UserSummary{}, err
	}
	if len(users) == 0 {
		return UserSummary{}, ErrUserNotFound
	}
	return users[0], nil
}

func (db *PostgresDB) findUsers(ctx context.Context, where, arg string) ([]UserSummary, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT id::text, email, COALESCE(NULLIF(tier_id, ''), 'non_patron'), COALESCE(patron_status, '')
		FROM forgerealm_auth.users WHERE `+where, arg)
	if err != nil {
		return nil, fmt.Errorf("find users: %w", err)
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (UserSummary, error) {
		var u UserSummary
		err := row.Scan(&u.ID, &u.Email, &u.TierID, &u.PatronStatus)
		return u, err
	})
	if err != nil {
		return nil, fmt.Errorf("find users: %w", err)
	}
	return users, nil
}
