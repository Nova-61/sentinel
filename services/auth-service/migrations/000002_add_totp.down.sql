ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_totp_consistent,
    DROP COLUMN IF EXISTS totp_enabled,
    DROP COLUMN IF EXISTS totp_secret_enc;
