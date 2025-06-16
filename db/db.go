package db

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var pool *pgxpool.Pool

// InitDB initializes the database connection pool
func InitDB() error {
	connString := os.Getenv("DATABASE_URL")
	if connString == "" {
		return fmt.Errorf("DATABASE_URL environment variable is not set")
	}

	var err error
	pool, err = pgxpool.New(context.Background(), connString)
	if err != nil {
		return fmt.Errorf("unable to create connection pool: %v", err)
	}

	// Test the connection
	if err := pool.Ping(context.Background()); err != nil {
		return fmt.Errorf("unable to ping database: %v", err)
	}

	return nil
}

// CloseDB closes the database connection pool
func CloseDB() {
	if pool != nil {
		pool.Close()
	}
}

// GetPool returns the database connection pool
func GetPool() *pgxpool.Pool {
	return pool
}

// CreateTables creates the necessary database tables if they don't exist
func CreateTables(ctx context.Context) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id SERIAL PRIMARY KEY,
			patreon_id VARCHAR(255) UNIQUE NOT NULL,
			email VARCHAR(255) UNIQUE NOT NULL,
			access_token TEXT NOT NULL,
			refresh_token TEXT NOT NULL,
			token_expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS webhook_events (
			id SERIAL PRIMARY KEY,
			event_type VARCHAR(255) NOT NULL,
			payload JSONB NOT NULL,
			processed BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}

	for _, query := range queries {
		_, err := pool.Exec(ctx, query)
		if err != nil {
			return fmt.Errorf("error creating table: %v", err)
		}
	}

	return nil
}

// SaveUser saves or updates a user in the database
func SaveUser(ctx context.Context, patreonID, email, accessToken, refreshToken string, tokenExpiresAt pgtype.Timestamp) error {
	query := `
		INSERT INTO users (patreon_id, email, access_token, refresh_token, token_expires_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (patreon_id) DO UPDATE
		SET email = $2,
			access_token = $3,
			refresh_token = $4,
			token_expires_at = $5,
			updated_at = CURRENT_TIMESTAMP
	`

	_, err := pool.Exec(ctx, query, patreonID, email, accessToken, refreshToken, tokenExpiresAt)
	return err
}

// SaveWebhookEvent saves a webhook event to the database
func SaveWebhookEvent(ctx context.Context, eventType string, payload []byte) error {
	query := `
		INSERT INTO webhook_events (event_type, payload)
		VALUES ($1, $2)
	`

	_, err := pool.Exec(ctx, query, eventType, payload)
	return err
}
