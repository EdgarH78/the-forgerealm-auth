-- AUTH-2: one role per user (Forge Credits ED34, revised 2026-11-02). An admin
-- exchanges their user token for an admin token at /admin/token. Only SQL
-- changes a role; login, webhooks and refresh never write role_id.
BEGIN;

CREATE TABLE forgerealm_auth.roles (
  id          TEXT PRIMARY KEY,
  description TEXT
);

INSERT INTO forgerealm_auth.roles (id, description) VALUES
  ('admin', 'Can get an admin token, look up users and grant credits'),
  ('user', 'A Patreon login with no admin access')
ON CONFLICT (id) DO NOTHING;

ALTER TABLE forgerealm_auth.users
  ADD COLUMN role_id TEXT NOT NULL DEFAULT 'user' REFERENCES forgerealm_auth.roles(id);

COMMIT;
