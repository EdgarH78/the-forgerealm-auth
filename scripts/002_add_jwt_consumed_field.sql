-- Add jwt_consumed field to token_logins table
ALTER TABLE forgerealm_auth.token_logins 
ADD COLUMN jwt_consumed BOOLEAN NOT NULL DEFAULT false;

-- Add index for better performance on jwt_consumed queries
CREATE INDEX idx_token_logins_jwt_consumed 
ON forgerealm_auth.token_logins(jwt_consumed) 
WHERE jwt_consumed = false; 