-- Support-only admission grants. These rows deliberately do not reference or
-- populate relay_members: a support grant authorizes exactly one restricted DM.
CREATE TABLE support_grants (
    community_id UUID NOT NULL REFERENCES communities(id),
    subject_pubkey BYTEA NOT NULL,
    channel_id UUID NOT NULL,
    support_pubkey BYTEA NOT NULL,
    escalation_pubkey BYTEA NOT NULL,
    capability_generation VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (community_id, subject_pubkey),
    FOREIGN KEY (community_id, channel_id)
        REFERENCES channels (community_id, id) ON DELETE CASCADE,
    CONSTRAINT chk_support_grants_subject_len CHECK (length(subject_pubkey) = 32),
    CONSTRAINT chk_support_grants_support_len CHECK (length(support_pubkey) = 32),
    CONSTRAINT chk_support_grants_escalation_len CHECK (length(escalation_pubkey) = 32),
    CONSTRAINT chk_support_grants_participants_distinct CHECK (
        subject_pubkey <> support_pubkey
        AND subject_pubkey <> escalation_pubkey
        AND support_pubkey <> escalation_pubkey
    )
);
CREATE INDEX idx_support_grants_active
    ON support_grants (community_id, subject_pubkey, expires_at)
    WHERE revoked_at IS NULL;
CREATE INDEX idx_support_grants_channel
    ON support_grants (community_id, channel_id);

-- Durable, tenant-scoped nonce consumption. The unique key makes concurrent
-- replay checks atomic across pods and process restarts.
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

-- Community deletion and archival fences were introduced in migration 0029.
SELECT attach_community_write_fence('support_grants');
SELECT attach_community_write_fence('support_admission_nonces');
