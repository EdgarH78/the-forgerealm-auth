package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"crypto/sha256"
	"encoding/hex"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresDB struct {
	pool *pgxpool.Pool
}

// InitDB initializes the database connection pool
func (db *PostgresDB) InitDB() error {
	connString := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if connString == "" {
		log.Printf("ERROR: DATABASE_URL environment variable is not set")
		return fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	var err error
	db.pool, err = pgxpool.New(context.Background(), connString)
	if err != nil {
		log.Printf("ERROR: Failed to create database connection pool: %v", err)
		return fmt.Errorf("unable to create connection pool: %v", err)
	}

	// Test the connection
	if err := db.pool.Ping(context.Background()); err != nil {
		log.Printf("ERROR: Failed to ping database: %v", err)
		return fmt.Errorf("unable to ping database: %v", err)
	}

	log.Printf("INFO: Successfully initialized database connection pool")
	return nil
}

// CloseDB closes the database connection pool
func (db *PostgresDB) CloseDB() {
	if db.pool != nil {
		db.pool.Close()
	}
}

// GetPool returns the database connection pool
func (db *PostgresDB) GetPool() *pgxpool.Pool {
	return db.pool
}

// SaveUser saves or updates a user in the database
func (db *PostgresDB) SaveUser(ctx context.Context, patreonID, email, givenName, surName, tierID, patronStatus, accessToken, refreshToken string, tokenExpiry pgtype.Timestamp) error {
	query := `
		INSERT INTO forgerealm_auth.users (
			patreon_id, email, given_name, sur_name, tier_id, 
			patron_status, access_token, refresh_token, token_expiry
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (patreon_id) DO UPDATE
		SET email = COALESCE(NULLIF($2, ''), users.email),
			given_name = COALESCE(NULLIF($3, ''), users.given_name),
			sur_name = COALESCE(NULLIF($4, ''), users.sur_name),
			tier_id = COALESCE(NULLIF($5, ''), users.tier_id),
			patron_status = COALESCE(NULLIF($6, ''), users.patron_status),
			access_token = COALESCE(NULLIF($7, ''), users.access_token),
			refresh_token = COALESCE(NULLIF($8, ''), users.refresh_token),
			token_expiry = $9,
			updated_at = CURRENT_TIMESTAMP
	`

	log.Printf("INFO: Saving user to database (Patreon ID: %s, Email: %s, Given Name: %s, Sur Name: %s, Tier ID: %s, Patron Status: %s)", patreonID, email, givenName, surName, tierID, patronStatus)
	_, err := db.pool.Exec(ctx, query, patreonID, email, givenName, surName, tierID,
		patronStatus, accessToken, refreshToken, tokenExpiry)
	if err != nil {
		log.Printf("ERROR: Failed to save user to database (Patreon ID: %s): %v", patreonID, err)
		return err
	}

	log.Printf("INFO: Successfully saved user to database (Patreon ID: %s)", patreonID)
	return nil
}

// SaveWebhookEvent saves a webhook event to the database
func (db *PostgresDB) SaveWebhookEvent(ctx context.Context, eventTypeID, patreonID, tierID, patronStatus string, rawPayload []byte) error {
	query := `
		INSERT INTO forgerealm_auth.webhook_events (
			event_type_id, patreon_id, tier_id, patron_status, raw_payload
		)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := db.pool.Exec(ctx, query, eventTypeID, patreonID, tierID, patronStatus, rawPayload)
	if err != nil {
		log.Printf("ERROR: Failed to save webhook event to database (Event: %s, Patreon ID: %s): %v", eventTypeID, patreonID, err)
		return err
	}

	log.Printf("INFO: Successfully saved webhook event to database (Event: %s, Patreon ID: %s)", eventTypeID, patreonID)
	return nil
}

// VerifyRefreshToken verifies a refresh token and returns the associated Patreon ID
func (db *PostgresDB) VerifyRefreshToken(ctx context.Context, token string) (string, error) {
	query := `
		SELECT patreon_id
		FROM forgerealm_auth.refresh_tokens
		WHERE expires_at > CURRENT_TIMESTAMP AND id = $1
	`

	var patreonID string
	err := db.pool.QueryRow(ctx, query, hashToken(token)).Scan(&patreonID)
	if err != nil {
		log.Printf("ERROR: Failed to query refresh token: %v", err)
		return "", fmt.Errorf("invalid refresh token")
	}

	log.Printf("INFO: Successfully verified refresh token for Patreon ID: %s", patreonID)
	return patreonID, nil
}

// StoreRefreshToken stores a hashed refresh token for a user
func (db *PostgresDB) StoreRefreshToken(ctx context.Context, patreonID, token string) error {
	// Hash the token before storing
	tokenHash := hashToken(token)

	query := `
		INSERT INTO forgerealm_auth.refresh_tokens (patreon_id, id, expires_at)
		VALUES ($1, $2, CURRENT_TIMESTAMP + INTERVAL '30 days')
		ON CONFLICT (id) DO UPDATE
		SET id = $2, expires_at = CURRENT_TIMESTAMP + INTERVAL '30 days'
	`

	_, err := db.pool.Exec(ctx, query, patreonID, string(tokenHash))
	if err != nil {
		log.Printf("ERROR: Failed to store refresh token for Patreon ID %s: %v", patreonID, err)
		return err
	}

	log.Printf("INFO: Successfully stored hashed refresh token for Patreon ID: %s", patreonID)
	return nil
}

// GetTierCodeForUser retrieves the tier code for a user
func (db *PostgresDB) GetTierCodeForUser(ctx context.Context, patreonID string) (string, error) {
	query := `
		SELECT tier_id 
		FROM forgerealm_auth.users 
		WHERE patreon_id = $1
	`

	var tierID string
	err := db.pool.QueryRow(ctx, query, patreonID).Scan(&tierID)
	if err != nil {
		log.Printf("ERROR: Failed to get tier code for Patreon ID %s: %v", patreonID, err)
		return "", err
	}

	log.Printf("INFO: Successfully retrieved tier code '%s' for Patreon ID: %s", tierID, patreonID)
	return tierID, nil
}

func (db *PostgresDB) SaveTokenLogin(ctx context.Context, token string, expiresAt time.Time) error {
	query := `
		INSERT INTO forgerealm_auth.token_logins (token, expires_at)
		VALUES ($1, $2)
	`

	_, err := db.pool.Exec(ctx, query, token, expiresAt)
	if err != nil {
		log.Printf("ERROR: Failed to save token login: %v", err)
		return err
	}

	log.Printf("INFO: Successfully saved token login for token: %s", token)
	return nil
}

func (db *PostgresDB) CheckTokenLogin(ctx context.Context, token string) (bool, error) {
	var fulfilled bool
	err := db.pool.QueryRow(ctx,
		`SELECT fulfilled FROM forgerealm_auth.token_logins WHERE token = $1 AND expires_at > now()`,
		token,
	).Scan(&fulfilled)
	if err != nil {
		log.Printf("ERROR: Failed to check token login: %v", err)
		return false, err
	}
	log.Printf("INFO: Successfully checked token login for token: %s", token)
	return fulfilled, nil
}

func (db *PostgresDB) FulfillTokenLogin(ctx context.Context, token string, userID string) error {
	query := `
		UPDATE forgerealm_auth.token_logins
		SET fulfilled = true, user_id = (
			SELECT id FROM forgerealm_auth.users WHERE patreon_id = $2
		)
		WHERE token = $1 AND fulfilled = false
	`
	_, err := db.pool.Exec(ctx, query, token, userID)
	if err != nil {
		log.Printf("ERROR: Failed to fulfill token login: %v", err)
		return err
	}

	log.Printf("INFO: Successfully fulfilled token login for token: %s", token)
	return nil
}

func hashToken(token string) string {
	h := sha256.New()
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}
