-- ── Support-only grants ──────────────────────────────────────────────────────
-- Separate from relay_members: authorizes exactly one three-party support DM.
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