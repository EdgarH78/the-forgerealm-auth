# ForgeRealm Auth Service

A Go Cloud Run microservice that handles Patreon OAuth2 authentication, JWT token management, and webhook processing for the ForgeRealm platform.

## Features

- Patreon OAuth2 authentication with automatic patron verification
- JWT token generation and refresh token management
- Secure refresh token storage with SHA256 hashing
- Webhook handling for Patreon member events (create, update, delete)
- PostgreSQL database integration using pgx
- Chi router for HTTP routing with middleware
- Environment-based configuration
- Comprehensive logging and error handling
- Unit tests with testify and mocking

## Prerequisites

- Go 1.21 or later
- PostgreSQL database
- Patreon Developer account

## Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/forgerealm-auth.git
cd forgerealm-auth
```

2. Install dependencies:
```bash
go mod download
```

3. Create a `.env` file based on `.env.example`:
```bash
cp .env.example .env
```

4. Update the `.env` file with your configuration:
- Set your Patreon OAuth2 credentials
- Configure your PostgreSQL database URL
- Set your JWT and webhook secrets

5. Run the database migrations:
```bash
# Execute the SQL script in scripts/001_create_tables.sql
```

6. Run the service:
```bash
go run main.go
```

## Environment Variables

### Required Variables
- `DATABASE_URL`: PostgreSQL connection string
- `PATREON_CLIENT_ID`: Patreon OAuth2 client ID
- `PATREON_CLIENT_SECRET`: Patreon OAuth2 client secret
- `JWT_SECRET_CURRENT`: Secret key for JWT token signing
- `WEBHOOK_SECRET`: Secret for webhook signature verification

### Optional Variables
- `PORT`: Server port (default: 8080)
- `PATREON_REDIRECT_URL`: OAuth2 callback URL (default: https://theforgerealm.com/auth/callback)

## API Endpoints

### Authentication Endpoints
- `GET /`: Home page
- `GET /auth/login`: Initiate Patreon OAuth2 login
- `GET /auth/callback`: OAuth2 callback handler
- `POST /auth/refresh`: Refresh JWT token using refresh token

### Webhook Endpoints
- `POST /auth/webhook`: Webhook endpoint for Patreon member events

## Authentication Flow

1. **Login**: User visits `/auth/login` and is redirected to Patreon OAuth
2. **Callback**: After OAuth, user data is saved and JWT + refresh tokens are set as cookies
3. **Refresh**: When JWT expires, client calls `/auth/refresh` with refresh token cookie
4. **Webhooks**: Patreon sends member events to `/auth/webhook` for real-time updates

## Database Schema

### Users Table
```sql
CREATE TABLE forgerealm_auth.users (
    id SERIAL PRIMARY KEY,
    patreon_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255),
    given_name VARCHAR(255),
    sur_name VARCHAR(255),
    tier_id VARCHAR(255),
    patron_status VARCHAR(255),
    access_token TEXT,
    refresh_token TEXT,
    token_expiry TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Refresh Tokens Table
```sql
CREATE TABLE forgerealm_auth.refresh_tokens (
    id SERIAL PRIMARY KEY,
    patreon_id VARCHAR(255) UNIQUE NOT NULL,
    id VARCHAR(255) NOT NULL, -- SHA256 hash of the refresh token
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Webhook Events Table
```sql
CREATE TABLE forgerealm_auth.webhook_events (
    id SERIAL PRIMARY KEY,
    event_type_id VARCHAR(255) NOT NULL,
    patreon_id VARCHAR(255),
    tier_id VARCHAR(255),
    patron_status VARCHAR(255),
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

## Security Features

- **JWT Tokens**: 1-hour expiration with secure signing
- **Refresh Tokens**: 30-day expiration, stored as SHA256 hashes
- **Webhook Verification**: HMAC MD5 signature verification
- **Secure Cookies**: HttpOnly, Secure, SameSite flags
- **Database Security**: Parameterized queries to prevent SQL injection

## Webhook Events

The service handles the following Patreon webhook events:
- `members:create`: New patron joins
- `members:update`: Patron tier or status changes
- `members:delete`: Patron cancels membership

## Testing

Run the test suite:
```bash
go test ./auth -v
```

Tests cover:
- OAuth flow and error handling
- JWT token generation and validation
- Refresh token management
- Webhook signature verification
- Database operations with mocking

## Deployment

The service is designed to be deployed on Google Cloud Run. Follow these steps:

1. Build the Docker image:
```bash
docker build -t gcr.io/your-project/forgerealm-auth .
```

2. Push to Google Container Registry:
```bash
docker push gcr.io/your-project/forgerealm-auth
```

3. Deploy to Cloud Run:
```bash
gcloud run deploy forgerealm-auth \
  --image gcr.io/your-project/forgerealm-auth \
  --platform managed \
  --region your-region \
  --allow-unauthenticated \
  --set-env-vars DATABASE_URL="your-db-url",JWT_SECRET_CURRENT="your-jwt-secret",WEBHOOK_SECRET="your-webhook-secret"
```

## Development

### Project Structure
```
forgerealm-auth/
├── auth/           # Authentication logic
├── db/            # Database operations
├── scripts/       # Database migrations
├── main.go        # Application entry point
├── Dockerfile     # Container configuration
└── README.md      # This file
```

### Key Components
- `auth/patreon.go`: Patreon OAuth2 and webhook handling
- `db/db.go`: Database interface and PostgreSQL implementation
- `main.go`: HTTP server setup and routing

## License

MIT License 