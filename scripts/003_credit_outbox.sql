-- AUTH-1: the credit outbox Atlas Forge's worker polls (Forge Credits ED76,
-- PR-9 D1 and D5), closed accounts (ED77), and the Patreon pledge event types.
-- The table and grants match atlasforge/scripts/db/forgerealm-auth/001_credit_outbox.sql.
-- Keep the two in step: the table is the contract between the repositories.
BEGIN;

-- One row per paid Patreon charge, written in the charge's transaction.
CREATE TABLE forgerealm_auth.credit_outbox (
  id            BIGSERIAL PRIMARY KEY,
  user_id       UUID NOT NULL,
  tier          TEXT NOT NULL,
  -- Whole seconds, so the worker's grant key (user, charge second) is this row's
  -- unique key and two charges can never share one grant.
  charged_at    TIMESTAMPTZ NOT NULL
                CONSTRAINT credit_outbox_charged_at_whole_seconds CHECK (charged_at = date_trunc('second', charged_at)),
  amount_cents  INT NOT NULL CHECK (amount_cents >= 0),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  claimed_at    TIMESTAMPTZ,
  attempts      INT NOT NULL DEFAULT 0,
  last_error    TEXT,
  completed_at  TIMESTAMPTZ,
  UNIQUE (user_id, charged_at)
);

CREATE INDEX credit_outbox_pending ON forgerealm_auth.credit_outbox (id) WHERE completed_at IS NULL;

-- A refund by Patreon or a chargeback closes the account permanently (ED77).
ALTER TABLE forgerealm_auth.users
  ADD COLUMN closed_at TIMESTAMPTZ,
  ADD COLUMN closed_reason TEXT;

INSERT INTO forgerealm_auth.event_types (id, description) VALUES
  ('members:pledge:create', 'User started a paid pledge'),
  ('members:pledge:update', 'User changed a paid pledge or was charged'),
  ('members:pledge:delete', 'User ended a paid pledge')
ON CONFLICT (id) DO NOTHING;

-- The worker's role reads this one table and updates only its bookkeeping
-- columns; it can never change who was charged, for what, or when. It is
-- created without a password so no credential lives in git. In production:
--   ALTER ROLE atlasforge_credit_outbox LOGIN PASSWORD '<generated>';
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'atlasforge_credit_outbox') THEN
    CREATE ROLE atlasforge_credit_outbox NOLOGIN;
  END IF;
END
$$;
GRANT USAGE ON SCHEMA forgerealm_auth TO atlasforge_credit_outbox;
GRANT SELECT ON forgerealm_auth.credit_outbox TO atlasforge_credit_outbox;
GRANT UPDATE (claimed_at, attempts, last_error, completed_at) ON forgerealm_auth.credit_outbox TO atlasforge_credit_outbox;

COMMIT;
