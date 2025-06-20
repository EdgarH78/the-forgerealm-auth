-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tiers table
CREATE TABLE IF NOT EXISTS forgerealm_auth.tiers (
  id TEXT PRIMARY KEY,         -- Patreon tier ID
  tier_code TEXT NOT NULL      -- Internal enum used for localization (e.g., 'apprentice', 'pro')
);

INSERT INTO forgerealm_auth.tiers (id, tier_code) VALUES
  ('non_patron', 'non_patron'),
  ('apprentice', 'apprentice'),
  ('journeyman', 'journeyman'),
  ('master', 'master')
ON CONFLICT (id) DO NOTHING;

-- Users table
CREATE TABLE IF NOT EXISTS forgerealm_auth.users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  patreon_id TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  given_name TEXT,
  sur_name TEXT,

  tier_id TEXT REFERENCES tiers(id),
  patron_status TEXT,              -- e.g. 'active_patron', 'former_patron'

  access_token TEXT,
  refresh_token TEXT,
  token_expiry TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE UNIQUE INDEX ON forgerealm_auth.users(patreon_id);

CREATE TABLE forgerealm_auth.event_types (
  id TEXT PRIMARY KEY,         -- e.g., 'members:pledge:create'
  description TEXT             -- Optional, e.g., 'User became a patron'
);

INSERT INTO forgerealm_auth.event_types (id, description) VALUES
  ('members:create', 'User became a patron'),
  ('members:update', 'User updated their pledge or tier'),
  ('members:delete', 'User ended their membership')
ON CONFLICT (id) DO NOTHING;


CREATE TABLE forgerealm_auth.webhook_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  event_type_id TEXT NOT NULL REFERENCES forgerealm_auth.event_types(id),
  patreon_id TEXT NOT NULL,
  tier_id TEXT REFERENCES forgerealm_auth.tiers(id),
  patron_status TEXT,

  received_at TIMESTAMPTZ DEFAULT now(),
  processed BOOLEAN DEFAULT FALSE,

  raw_payload JSONB
);

CREATE INDEX idx_webhook_events_patreon_id 
  ON forgerealm_auth.webhook_events(patreon_id);


CREATE TABLE forgerealm_auth.refresh_tokens (
    id TEXT PRIMARY KEY, -- hashed token string
    patreon_id TEXT NOT NULL REFERENCES forgerealm_auth.users(patreon_id) ON DELETE CASCADE,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    revoked BOOLEAN NOT NULL DEFAULT false
);
