-- Migration: 0003_nullable_email_enc.sql
--
-- What:
--   Makes `users.email_enc` nullable during initial OPAQUE signup (Phase 1, Step 3C).
--
-- Why:
--   The email-verification step will populate `email_enc` once server-side AEAD encryption
--   is introduced in a later step. Until then, `signup/finish` stores `NULL` in `email_enc`
--   so that plaintext email addresses are never stored anywhere in the database.

ALTER TABLE users
    ALTER COLUMN email_enc DROP NOT NULL;

ALTER TABLE users
    DROP CONSTRAINT chk_users_email_enc_len,
    ADD CONSTRAINT chk_users_email_enc_len CHECK (
        email_enc IS NULL OR (octet_length(email_enc) > 0 AND octet_length(email_enc) <= 1024)
    );
