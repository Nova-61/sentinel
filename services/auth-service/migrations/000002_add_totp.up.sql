ALTER TABLE users
    ADD COLUMN totp_secret_enc BYTEA,
    ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT users_totp_consistent
        CHECK (NOT totp_enabled OR totp_secret_enc IS NOT NULL);
