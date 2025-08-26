#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG ---
SECRETS=(
  AUTH_DB_URL
  JWT_SECRET_CURRENT
  JWT_SECRET_NEXT
  PATREON_CLIENT_ID
  PATREON_CLIENT_SECRET
  PATREON_REDIRECT_URL
  WEB_HOOK_SECRET
)

# gcloud config set project "Scryforge" >/dev/null

# Rebuild .env file
: > .env
for s in "${SECRETS[@]}"; do
  printf "%s=" "$s" >> .env
  gcloud secrets versions access latest --secret="$s" >> .env
  printf "\n" >> .env
done

echo "✅ Wrote $(wc -l < .env) environment variables to .env"
