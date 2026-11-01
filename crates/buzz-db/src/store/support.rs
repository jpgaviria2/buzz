//! Support-only admission grant persistence.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::{Db, DbError, Result};
use buzz_core::CommunityId;

/// An active support-only authorization bound to one exact DM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportGrant {
    /// Customer identity admitted by the grant.
    pub subject_pubkey: Vec<u8>,
    /// Sole channel authorized by the grant.
    pub channel_id: Uuid,
    /// Trails/Hermes support identity in the DM.
    pub support_pubkey: Vec<u8>,
    /// JP escalation identity in the DM.
    pub escalation_pubkey: Vec<u8>,
    /// Rotatable capability generation which issued the grant.
    pub capability_generation: String,
    /// Grant expiry.
    pub expires_at: DateTime<Utc>,
}

/// Result of idempotent support admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportAdmission {
    /// The resulting active grant.
    pub grant: SupportGrant,
    /// Whether this call created/replaced the grant.
    pub changed: bool,
}

fn grant_from_row(row: sqlx::postgres::PgRow) -> Result<SupportGrant> {
    Ok(SupportGrant {
        subject_pubkey: row.try_get("subject_pubkey")?,
        channel_id: row.try_get("channel_id")?,
        support_pubkey: row.try_get("support_pubkey")?,
        escalation_pubkey: row.try_get("escalation_pubkey")?,
        capability_generation: row.try_get("capability_generation")?,
        expires_at: row.try_get("expires_at")?,
    })
}

/// Atomically consume a NIP-98 nonce. Returns false when already consumed.
pub async fn consume_nonce(
    pool: &PgPool,
    community: CommunityId,
    nonce_hash: &[u8; 32],
    expires_at: DateTime<Utc>,
) -> Result<bool> {
    sqlx::query(
        "DELETE FROM support_admission_nonces WHERE community_id = $1 AND expires_at <= now()",
    )
    .bind(community.as_uuid())
    .execute(pool)
    .await?;
    let result = sqlx::query(
        "INSERT INTO support_admission_nonces (community_id, nonce_hash, expires_at) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(community.as_uuid())
    .bind(nonce_hash.as_slice())
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Insert or refresh one support grant without creating relay membership.
///
/// The caller must provide the canonical three-party DM created by `dm::create_dm`.
pub async fn admit(
    pool: &PgPool,
    community: CommunityId,
    subject_pubkey: &[u8],
    channel_id: Uuid,
    support_pubkey: &[u8],
    escalation_pubkey: &[u8],
    capability_generation: &str,
    expires_at: DateTime<Utc>,
) -> Result<SupportAdmission> {
    for pubkey in [subject_pubkey, support_pubkey, escalation_pubkey] {
        if pubkey.len() != 32 {
            return Err(DbError::InvalidData(
                "support participant pubkeys must be 32 bytes".into(),
            ));
        }
    }
    if subject_pubkey == support_pubkey
        || subject_pubkey == escalation_pubkey
        || support_pubkey == escalation_pubkey
    {
        return Err(DbError::InvalidData(
            "support participants must be distinct".into(),
        ));
    }
    if capability_generation.is_empty() || capability_generation.len() > 128 {
        return Err(DbError::InvalidData(
            "invalid support capability generation".into(),
        ));
    }

    let row = sqlx::query(
        r#"
        INSERT INTO support_grants (
            community_id, subject_pubkey, channel_id, support_pubkey,
            escalation_pubkey, capability_generation, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (community_id, subject_pubkey) DO UPDATE SET
            channel_id = EXCLUDED.channel_id,
            support_pubkey = EXCLUDED.support_pubkey,
            escalation_pubkey = EXCLUDED.escalation_pubkey,
            capability_generation = EXCLUDED.capability_generation,
            expires_at = GREATEST(support_grants.expires_at, EXCLUDED.expires_at),
            revoked_at = NULL,
            updated_at = now()
        RETURNING subject_pubkey, channel_id, support_pubkey, escalation_pubkey,
                  capability_generation, expires_at, (xmax = 0) AS inserted
        "#,
    )
    .bind(community.as_uuid())
    .bind(subject_pubkey)
    .bind(channel_id)
    .bind(support_pubkey)
    .bind(escalation_pubkey)
    .bind(capability_generation)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    let changed: bool = row.try_get("inserted")?;
    Ok(SupportAdmission {
        grant: grant_from_row(row)?,
        changed,
    })
}

/// Load an unexpired, unrevoked grant from the writer.
pub async fn active_grant(
    pool: &PgPool,
    community: CommunityId,
    subject_pubkey: &[u8],
) -> Result<Option<SupportGrant>> {
    let row = sqlx::query(
        r#"
        SELECT sg.subject_pubkey, sg.channel_id, sg.support_pubkey, sg.escalation_pubkey,
               sg.capability_generation, sg.expires_at
        FROM support_grants sg
        WHERE sg.community_id = $1 AND sg.subject_pubkey = $2
          AND sg.revoked_at IS NULL AND sg.expires_at > now()
          AND EXISTS (
              SELECT 1 FROM channels c
              WHERE c.community_id = sg.community_id AND c.id = sg.channel_id
                AND c.channel_type = 'dm' AND c.visibility = 'private'
                AND c.deleted_at IS NULL AND c.archived_at IS NULL
          )
          AND 3 = (
              SELECT count(*) FROM channel_members cm
              WHERE cm.community_id = sg.community_id AND cm.channel_id = sg.channel_id
                AND cm.removed_at IS NULL
                AND cm.pubkey IN (sg.subject_pubkey, sg.support_pubkey, sg.escalation_pubkey)
          )
          AND NOT EXISTS (
              SELECT 1 FROM channel_members cm
              WHERE cm.community_id = sg.community_id AND cm.channel_id = sg.channel_id
                AND cm.removed_at IS NULL
                AND cm.pubkey NOT IN (sg.subject_pubkey, sg.support_pubkey, sg.escalation_pubkey)
          )
        "#,
    )
    .bind(community.as_uuid())
    .bind(subject_pubkey)
    .fetch_optional(pool)
    .await?;
    row.map(grant_from_row).transpose()
}

/// Revoke one customer's support grant.
pub async fn revoke(pool: &PgPool, community: CommunityId, subject_pubkey: &[u8]) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE support_grants SET revoked_at = now(), updated_at = now() \
         WHERE community_id = $1 AND subject_pubkey = $2 AND revoked_at IS NULL",
    )
    .bind(community.as_uuid())
    .bind(subject_pubkey)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

impl Db {
    /// Atomically consume a support-admission nonce.
    pub async fn consume_support_nonce(
        &self,
        community: CommunityId,
        nonce_hash: &[u8; 32],
        expires_at: DateTime<Utc>,
    ) -> Result<bool> {
        consume_nonce(&self.pool, community, nonce_hash, expires_at).await
    }

    /// Create or refresh a support-only grant.
    #[allow(clippy::too_many_arguments)]
    pub async fn admit_support(
        &self,
        community: CommunityId,
        subject_pubkey: &[u8],
        channel_id: Uuid,
        support_pubkey: &[u8],
        escalation_pubkey: &[u8],
        capability_generation: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<SupportAdmission> {
        admit(
            &self.pool,
            community,
            subject_pubkey,
            channel_id,
            support_pubkey,
            escalation_pubkey,
            capability_generation,
            expires_at,
        )
        .await
    }

    /// Load the current active support-only grant from the writer.
    pub async fn active_support_grant(
        &self,
        community: CommunityId,
        subject_pubkey: &[u8],
    ) -> Result<Option<SupportGrant>> {
        active_grant(&self.pool, community, subject_pubkey).await
    }

    /// Revoke a support-only grant.
    pub async fn revoke_support_grant(
        &self,
        community: CommunityId,
        subject_pubkey: &[u8],
    ) -> Result<bool> {
        revoke(&self.pool, community, subject_pubkey).await
    }
}
