-- Durable, tenant-scoped support NIP-98 nonce replay guard.
CREATE TABLE support_admission_nonces (
    community_id UUID NOT NULL REFERENCES communities(id),
    nonce_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, nonce_hash),
    CONSTRAINT chk_support_admission_nonce_hash_len CHECK (length(nonce_hash) = 32)
);
CREATE INDEX idx_support_admission_nonces_expiry
    ON support_admission_nonces (community_id, expires_at);