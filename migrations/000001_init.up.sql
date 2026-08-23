-- Users. The crypto columns keep the client-side encryption
-- material: the server stores them but cannot use them.
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    login varchar(255) NOT NULL UNIQUE,
    -- Argon2id hash of the account password
    password_hash varchar(255) NOT NULL,
    -- Random salt for the KEK derivation on the client.
    kek_salt bytea NOT NULL,
    -- Argon2id params for the KEK derivation (memory, time, threads).
    kdf_params jsonb NOT NULL,
    -- DEK encrypted with the KEK. Only the client can decrypt it.
    encrypted_dek bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Secrets. The payload is an encrypted blob; the server cannot
-- read it. "version" grows on every update (last write wins).
-- "deleted" is a soft-delete flag.
CREATE TABLE secrets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type varchar(20) NOT NULL CHECK (type IN ('login_password', 'text', 'binary', 'card')),
    encrypted_payload bytea NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    deleted boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX secrets_user_id_idx ON secrets (user_id);
