# ForgeRealm Auth Service

A Go Cloud Run microservice that handles Patreon OAuth2 authentication and webhook processing for the ForgeRealm platform.

## Features

- Patreon OAuth2 authentication
- Webhook handling for Patreon events
- PostgreSQL database integration using pgx
- Chi router for HTTP routing
- Environment-based configuration

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
- Set your webhook secret

5. Run the service:
```bash
go run main.go
```

## Environment Variables

- `PORT`: Server port (default: 8080)
- `DATABASE_URL`: PostgreSQL connection string
- `PATREON_CLIENT_ID`: Patreon OAuth2 client ID
- `PATREON_CLIENT_SECRET`: Patreon OAuth2 client secret
- `PATREON_REDIRECT_URL`: OAuth2 callback URL
- `WEBHOOK_SECRET`: Secret for webhook signature verification

## API Endpoints

- `GET /`: Home page
- `GET /auth/login`: Initiate Patreon OAuth2 login
- `GET /auth/callback`: OAuth2 callback handler
- `POST /webhook`: Webhook endpoint for Patreon events

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    patreon_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    token_expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Webhook Events Table
```sql
CREATE TABLE webhook_events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(255) NOT NULL,
    payload JSONB NOT NULL,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

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
  --allow-unauthenticated
```

## License

MIT License 