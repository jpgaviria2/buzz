//! Pre-membership support-only admission endpoint and authorization helpers.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use base64::Engine as _;
use chrono::{TimeDelta, Utc};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{SupportAdmissionConfig, SupportCapabilityConfig};
use crate::state::AppState;

use super::{api_error, bridge, internal_error};

const ADMISSION_RATE_LIMIT: u32 = 5;
const RATE_CACHE_CAPACITY: u64 = 20_000;
const RATE_WINDOW: Duration = Duration::from_secs(60);
const NONCE_MAX_BYTES: usize = 128;
const NONCE_MIN_BYTES: usize = 16;
const NONCE_REPLAY_TTL_SECS: i64 = 120;

static RATE_LIMITER: LazyLock<moka::sync::Cache<String, Arc<AtomicU32>>> = LazyLock::new(|| {
    moka::sync::Cache::builder()
        .max_capacity(RATE_CACHE_CAPACITY)
        .time_to_live(RATE_WINDOW)
        .build()
});
static DM_CREATE_RATE_LIMITER: LazyLock<moka::sync::Cache<String, Arc<AtomicU32>>> =
    LazyLock::new(|| {
        moka::sync::Cache::builder()
            .max_capacity(RATE_CACHE_CAPACITY)
            .time_to_live(Duration::from_secs(60 * 60))
            .build()
    });

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmitRequest {
    capability: String,
}

fn rate_key(community: buzz_core::CommunityId, suffix: &str) -> String {
    format!("{}:{suffix}", community)
}

fn rate_limited_at(key: String, limit: u32) -> bool {
    let counter = RATE_LIMITER.get_with(key, || Arc::new(AtomicU32::new(0)));
    counter.fetch_add(1, Ordering::Relaxed) >= limit
}

fn rate_limited(key: String) -> bool {
    rate_limited_at(key, ADMISSION_RATE_LIMIT)
}

fn dm_creation_rate_limited(community: buzz_core::CommunityId, pubkey: &nostr::PublicKey) -> bool {
    let key = rate_key(community, &format!("dm-create:{}", pubkey.to_hex()));
    let counter = DM_CREATE_RATE_LIMITER.get_with(key, || Arc::new(AtomicU32::new(0)));
    counter.fetch_add(1, Ordering::Relaxed) >= 3
}

/// Apply the support-specific sustained message budget (30/minute).
pub(crate) fn message_rate_limited(
    community: buzz_core::CommunityId,
    pubkey: &nostr::PublicKey,
) -> bool {
    rate_limited_at(
        rate_key(community, &format!("message:{}", pubkey.to_hex())),
        30,
    )
}

fn capability_match<'a>(
    config: &'a SupportAdmissionConfig,
    raw: &str,
    now: i64,
) -> Result<&'a SupportCapabilityConfig, StatusCode> {
    let candidate: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let mut matched = None;
    for capability in &config.capabilities {
        if capability.capability_hash.ct_eq(&candidate).into() {
            matched = Some(capability);
        }
    }
    let Some(capability) = matched else {
        return Err(StatusCode::FORBIDDEN);
    };
    if capability.revoked {
        return Err(StatusCode::FORBIDDEN);
    }
    if capability.expires_at <= now {
        return Err(StatusCode::GONE);
    }
    Ok(capability)
}

fn strict_nip98_event(headers: &HeaderMap) -> Result<nostr::Event, (StatusCode, Json<Value>)> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid_nip98_authorization",
        ));
    };
    let encoded = value
        .to_str()
        .ok()
        .and_then(|value| value.strip_prefix("Nostr "))
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_authorization"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_authorization"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_authorization"))
}

fn extract_nonce(event: &nostr::Event) -> Result<String, (StatusCode, Json<Value>)> {
    let nonce_tags = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("nonce"))
        .collect::<Vec<_>>();
    let Some(values) = nonce_tags.first().map(|tag| tag.as_slice()) else {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_nonce"));
    };
    if nonce_tags.len() != 1 || values.len() != 2 {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_nonce"));
    }
    let nonce = values[1].as_str();
    if !(NONCE_MIN_BYTES..=NONCE_MAX_BYTES).contains(&nonce.len())
        || !nonce.is_ascii()
        || nonce.chars().any(char::is_whitespace)
    {
        return Err(api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_nonce"));
    }
    Ok(nonce.to_owned())
}

/// `POST /api/support/admit` — issue a support-only grant and exact three-party DM.
pub async fn admit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    admit_checked(state, Some(remote.ip()), headers, body).await
}

async fn admit_checked(
    state: Arc<AppState>,
    remote_ip: Option<IpAddr>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(config) = state.config.support_admission.as_ref() else {
        return api_error(StatusCode::NOT_FOUND, "support_admission_not_configured")
            .into_response();
    };
    let raw_host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let tenant = match crate::tenant::bind_community(&state.db, raw_host).await {
        Ok(tenant) => tenant,
        Err(_) => {
            return api_error(
                StatusCode::NOT_FOUND,
                "relay: no community is configured for this host",
            )
            .into_response()
        }
    };
    if let Some(ip) = remote_ip {
        if rate_limited(rate_key(tenant.community(), &format!("ip:{ip}"))) {
            return api_error(
                StatusCode::TOO_MANY_REQUESTS,
                "support_admission_rate_limited",
            )
            .into_response();
        }
    }

    let request: AdmitRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid_request").into_response(),
    };
    if request.capability.len() > 512 {
        return api_error(StatusCode::BAD_REQUEST, "invalid_request").into_response();
    }

    let event = match strict_nip98_event(&headers) {
        Ok(event) => event,
        Err(error) => return error.into_response(),
    };
    let nonce = match extract_nonce(&event) {
        Ok(nonce) => nonce,
        Err(error) => return error.into_response(),
    };
    let url = bridge::nip98_expected_url(&state.config.relay_url, &tenant, "/api/support/admit");
    let verified =
        match bridge::verify_nip98_exempt_invite_claim(&headers, "POST", &url, Some(&body)) {
            Ok(verified) => verified,
            Err(_) => {
                return api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_authorization")
                    .into_response()
            }
        };
    if event.id.to_bytes() != verified.event_id_bytes || event.pubkey != verified.pubkey {
        return api_error(StatusCode::UNAUTHORIZED, "invalid_nip98_authorization").into_response();
    }
    if rate_limited(rate_key(
        tenant.community(),
        &format!("pubkey:{}", verified.pubkey.to_hex()),
    )) {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "support_admission_rate_limited",
        )
        .into_response();
    }

    let nonce_hash: [u8; 32] = Sha256::digest(nonce.as_bytes()).into();
    let nonce_expiry = Utc::now() + TimeDelta::seconds(NONCE_REPLAY_TTL_SECS);
    match state
        .db
        .consume_support_nonce(tenant.community(), &nonce_hash, nonce_expiry)
        .await
    {
        Ok(true) => {}
        Ok(false) => return api_error(StatusCode::CONFLICT, "replayed_nonce").into_response(),
        Err(error) => return internal_error(&format!("support nonce: {error}")).into_response(),
    }

    let capability = match capability_match(config, &request.capability, Utc::now().timestamp()) {
        Ok(capability) => capability,
        Err(StatusCode::GONE) => {
            return api_error(StatusCode::GONE, "expired_support_capability").into_response()
        }
        Err(_) => {
            return api_error(StatusCode::FORBIDDEN, "invalid_support_capability").into_response()
        }
    };

    match crate::handlers::auth::principal_ban_outcome(
        &state,
        tenant.community(),
        &verified.pubkey,
        true,
    )
    .await
    {
        crate::handlers::auth::BanOutcome::Clear => {}
        crate::handlers::auth::BanOutcome::Banned => {
            return api_error(StatusCode::FORBIDDEN, "support_admission_denied").into_response()
        }
        crate::handlers::auth::BanOutcome::DbError => {
            return api_error(StatusCode::SERVICE_UNAVAILABLE, "authorization_unavailable")
                .into_response()
        }
    }

    let subject = verified.pubkey.to_bytes();
    let support = config.support_pubkey.to_bytes();
    let escalation = config.escalation_pubkey.to_bytes();
    if subject == support || subject == escalation {
        return api_error(StatusCode::FORBIDDEN, "invalid_support_subject").into_response();
    }
    let participants: [&[u8]; 3] = [&subject, &support, &escalation];
    let participant_hash = buzz_db::dm::compute_participant_hash(&participants);
    let existing_dm = match state
        .db
        .find_dm_by_participants(tenant.community(), &participant_hash)
        .await
    {
        Ok(dm) => dm,
        Err(error) => {
            return internal_error(&format!("support DM lookup: {error}")).into_response()
        }
    };
    if existing_dm.is_none() && dm_creation_rate_limited(tenant.community(), &verified.pubkey) {
        return api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "support_dm_creation_rate_limited",
        )
        .into_response();
    }
    let channel = match existing_dm {
        Some(channel) => channel,
        None => match state
            .db
            .create_dm(tenant.community(), &participants, &support)
            .await
        {
            Ok(channel) => channel,
            Err(error) => return internal_error(&format!("support DM: {error}")).into_response(),
        },
    };
    let grant_expires_at =
        Utc::now() + TimeDelta::seconds(i64::try_from(config.grant_ttl_secs).unwrap_or(i64::MAX));
    let grant_expires_at = grant_expires_at.min(
        chrono::DateTime::from_timestamp(capability.expires_at, 0).unwrap_or(grant_expires_at),
    );
    let admission = match state
        .db
        .admit_support(
            tenant.community(),
            &subject,
            channel.id,
            &support,
            &escalation,
            &capability.generation,
            grant_expires_at,
        )
        .await
    {
        Ok(admission) => admission,
        Err(error) => return internal_error(&format!("support grant: {error}")).into_response(),
    };

    tracing::info!(
        community = %tenant.community(),
        subject = %verified.pubkey.to_hex(),
        generation = %capability.generation,
        channel_id = %admission.grant.channel_id,
        "support-only admission granted"
    );
    Json(serde_json::json!({
        "status": "support_admitted",
        "scope": "support_dm",
        "expiresAt": admission.grant.expires_at.timestamp(),
        "channelId": admission.grant.channel_id,
        "participants": [
            verified.pubkey.to_hex(),
            config.support_pubkey.to_hex(),
            config.escalation_pubkey.to_hex()
        ]
    }))
    .into_response()
}

/// Reload a grant for an already authenticated support-only principal.
pub(crate) async fn active_grant(
    state: &AppState,
    community: buzz_core::CommunityId,
    pubkey: &nostr::PublicKey,
) -> Result<Option<buzz_db::SupportGrant>, buzz_db::DbError> {
    state
        .db
        .active_support_grant(community, pubkey.as_bytes())
        .await
}

/// Whether a NIP-42 context was restricted by the support-only admission path.
pub(crate) fn is_support_only_context(ctx: &buzz_auth::AuthContext) -> bool {
    ctx.auth_method == buzz_auth::AuthMethod::Nip42
        && ctx.channel_ids.as_ref().is_some_and(|ids| ids.len() == 1)
        && ctx.scopes.len() == 2
        && ctx.scopes.contains(&buzz_auth::Scope::MessagesRead)
        && ctx.scopes.contains(&buzz_auth::Scope::MessagesWrite)
}

/// Enforce the support grant's exact kind, author, channel, and escalation tags.
pub(crate) fn validate_support_event(
    event: &nostr::Event,
    grant: &buzz_db::SupportGrant,
) -> Result<(), &'static str> {
    if event.kind.as_u16() != 9 {
        return Err("restricted: support grants may publish only kind 9");
    }
    if event.pubkey.as_bytes() != grant.subject_pubkey.as_slice() {
        return Err("restricted: support event author does not match grant");
    }
    let h_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("h"))
        .collect();
    let expected_channel = grant.channel_id.to_string();
    if h_tags.len() != 1
        || h_tags[0].as_slice().len() != 2
        || h_tags[0].as_slice().get(1).map(String::as_str) != Some(expected_channel.as_str())
    {
        return Err("restricted: message is outside the authorized support DM");
    }
    let p_tags: Vec<_> = event
        .tags
        .iter()
        .filter(|tag| tag.as_slice().first().map(String::as_str) == Some("p"))
        .collect();
    let escalation_hex = hex::encode(&grant.escalation_pubkey);
    if p_tags.len() > 1
        || p_tags.first().is_some_and(|tag| {
            tag.as_slice().len() != 2
                || tag.as_slice().get(1).map(String::as_str) != Some(escalation_hex.as_str())
        })
    {
        return Err("restricted: invalid support escalation target");
    }
    Ok(())
}

/// Enforce support-only REQ filters: kind 9 in the exact DM, or kind 0 for the
/// exact three participants needed to render it.
pub(crate) fn validate_support_filters(
    filters: &[nostr::Filter],
    grant: &buzz_db::SupportGrant,
) -> bool {
    let allowed_authors = [
        hex::encode(&grant.subject_pubkey),
        hex::encode(&grant.support_pubkey),
        hex::encode(&grant.escalation_pubkey),
    ];
    let h_tag = nostr::SingleLetterTag::lowercase(nostr::Alphabet::H);
    !filters.is_empty()
        && filters.iter().all(|filter| {
            let kinds = filter.kinds.as_ref();
            let profile_read = kinds.is_some_and(|kinds| {
                !kinds.is_empty() && kinds.iter().all(|kind| kind.as_u16() == 0)
            }) && filter.authors.as_ref().is_some_and(|authors| {
                !authors.is_empty()
                    && authors
                        .iter()
                        .all(|author| allowed_authors.contains(&author.to_hex()))
            }) && !filter.generic_tags.contains_key(&h_tag);
            let message_read = kinds.is_some_and(|kinds| {
                !kinds.is_empty() && kinds.iter().all(|kind| kind.as_u16() == 9)
            }) && filter.generic_tags.get(&h_tag).is_some_and(|values| {
                values.len() == 1
                    && values
                        .iter()
                        .next()
                        .is_some_and(|value| value == &grant.channel_id.to_string())
            });
            profile_read || message_read
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SupportAdmissionConfig, SupportCapabilityConfig};
    use nostr::Keys;

    fn config(capability: &str, expires_at: i64, revoked: bool) -> SupportAdmissionConfig {
        SupportAdmissionConfig {
            support_pubkey: Keys::generate().public_key(),
            escalation_pubkey: Keys::generate().public_key(),
            grant_ttl_secs: 60,
            capabilities: vec![SupportCapabilityConfig {
                generation: "g1".into(),
                capability_hash: Sha256::digest(capability.as_bytes()).into(),
                expires_at,
                revoked,
            }],
        }
    }

    #[test]
    fn capability_rotation_and_expiry_are_enforced() {
        let now = Utc::now().timestamp();
        let active = config("a-very-long-public-support-capability", now + 60, false);
        assert_eq!(
            capability_match(&active, "a-very-long-public-support-capability", now)
                .unwrap()
                .generation,
            "g1"
        );
        assert!(matches!(
            capability_match(&active, "wrong", now),
            Err(StatusCode::FORBIDDEN)
        ));
        assert!(matches!(
            capability_match(&config("cap", now - 1, false), "cap", now),
            Err(StatusCode::GONE)
        ));
        assert!(matches!(
            capability_match(&config("cap", now + 60, true), "cap", now),
            Err(StatusCode::FORBIDDEN)
        ));
    }

    #[test]
    fn admission_rate_limit_is_separate_and_bounded() {
        let key = format!("test:{}", uuid::Uuid::new_v4());
        for _ in 0..ADMISSION_RATE_LIMIT {
            assert!(!rate_limited(key.clone()));
        }
        assert!(rate_limited(key));

        let community = buzz_core::CommunityId::from_uuid(uuid::Uuid::new_v4());
        let pubkey = Keys::generate().public_key();
        for _ in 0..3 {
            assert!(!dm_creation_rate_limited(community, &pubkey));
        }
        assert!(dm_creation_rate_limited(community, &pubkey));
    }

    #[test]
    fn nonce_is_required_exactly_once_and_has_bounded_safe_shape() {
        fn auth_event(nonces: &[&str]) -> nostr::Event {
            let tags = nonces
                .iter()
                .map(|nonce| nostr::Tag::parse(["nonce", *nonce]).unwrap())
                .collect::<Vec<_>>();
            nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
                .tags(tags)
                .sign_with_keys(&Keys::generate())
                .unwrap()
        }
        let valid = "0123456789abcdef0123456789abcdef";
        assert_eq!(extract_nonce(&auth_event(&[valid])).unwrap(), valid);
        assert!(extract_nonce(&auth_event(&[])).is_err());
        assert!(extract_nonce(&auth_event(&[valid, valid])).is_err());
        assert!(extract_nonce(&auth_event(&["short"])).is_err());
        assert!(extract_nonce(&auth_event(&["contains whitespace"])).is_err());
        let extra = nostr::EventBuilder::new(nostr::Kind::HttpAuth, "")
            .tag(nostr::Tag::parse(["nonce", valid, "extra"]).unwrap())
            .sign_with_keys(&Keys::generate())
            .unwrap();
        assert!(extract_nonce(&extra).is_err());
    }

    fn grant(customer: &Keys, escalation: &Keys) -> buzz_db::SupportGrant {
        buzz_db::SupportGrant {
            subject_pubkey: customer.public_key().to_bytes().to_vec(),
            channel_id: uuid::Uuid::new_v4(),
            support_pubkey: Keys::generate().public_key().to_bytes().to_vec(),
            escalation_pubkey: escalation.public_key().to_bytes().to_vec(),
            capability_generation: "g1".into(),
            expires_at: Utc::now() + TimeDelta::minutes(5),
        }
    }

    fn message(
        keys: &Keys,
        grant: &buzz_db::SupportGrant,
        kind: u16,
        p: Option<String>,
    ) -> nostr::Event {
        let mut tags =
            vec![nostr::Tag::parse(["h", grant.channel_id.to_string().as_str()]).unwrap()];
        if let Some(p) = p {
            tags.push(nostr::Tag::parse(["p", p.as_str()]).unwrap());
        }
        nostr::EventBuilder::new(nostr::Kind::Custom(kind), "hello")
            .tags(tags)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn support_filters_are_limited_to_exact_dm_and_participant_profiles() {
        let customer = Keys::generate();
        let escalation = Keys::generate();
        let grant = grant(&customer, &escalation);
        let h = nostr::SingleLetterTag::lowercase(nostr::Alphabet::H);
        let message = nostr::Filter::new()
            .kind(nostr::Kind::Custom(9))
            .custom_tag(h, grant.channel_id.to_string());
        assert!(validate_support_filters(
            std::slice::from_ref(&message),
            &grant
        ));
        let wrong_channel = nostr::Filter::new()
            .kind(nostr::Kind::Custom(9))
            .custom_tag(h, uuid::Uuid::new_v4().to_string());
        assert!(!validate_support_filters(&[wrong_channel], &grant));
        assert!(!validate_support_filters(
            &[nostr::Filter::new().kind(nostr::Kind::Custom(9))],
            &grant,
        ));

        let customer_profile = nostr::Filter::new()
            .kind(nostr::Kind::Metadata)
            .author(customer.public_key());
        assert!(validate_support_filters(&[customer_profile], &grant));
        let outsider_profile = nostr::Filter::new()
            .kind(nostr::Kind::Metadata)
            .author(Keys::generate().public_key());
        assert!(!validate_support_filters(&[outsider_profile], &grant));
        assert!(!validate_support_filters(
            &[nostr::Filter::new().kind(nostr::Kind::Metadata)],
            &grant,
        ));
    }

    #[test]
    fn support_event_allows_plain_and_exact_jp_escalation_only() {
        let customer = Keys::generate();
        let jp = Keys::generate();
        let grant = grant(&customer, &jp);
        assert!(validate_support_event(&message(&customer, &grant, 9, None), &grant).is_ok());
        assert!(validate_support_event(
            &message(&customer, &grant, 9, Some(jp.public_key().to_hex())),
            &grant
        )
        .is_ok());
        let exact_channel = grant.channel_id.to_string();
        let jp_hex = jp.public_key().to_hex();
        let extra_p_field = nostr::EventBuilder::new(nostr::Kind::Custom(9), "hello")
            .tags([
                nostr::Tag::parse(["h", exact_channel.as_str()]).unwrap(),
                nostr::Tag::parse(["p", jp_hex.as_str(), "relay-hint"]).unwrap(),
            ])
            .sign_with_keys(&customer)
            .unwrap();
        assert_eq!(
            validate_support_event(&extra_p_field, &grant),
            Err("restricted: invalid support escalation target")
        );
        let extra_h_field = nostr::EventBuilder::new(nostr::Kind::Custom(9), "hello")
            .tag(nostr::Tag::parse(["h", exact_channel.as_str(), "extra"]).unwrap())
            .sign_with_keys(&customer)
            .unwrap();
        assert_eq!(
            validate_support_event(&extra_h_field, &grant),
            Err("restricted: message is outside the authorized support DM")
        );

        let outsider = Keys::generate();
        assert_eq!(
            validate_support_event(
                &message(&customer, &grant, 9, Some(outsider.public_key().to_hex())),
                &grant
            ),
            Err("restricted: invalid support escalation target")
        );
    }

    #[test]
    fn support_event_rejects_wrong_kind_author_and_channel() {
        let customer = Keys::generate();
        let jp = Keys::generate();
        let grant = grant(&customer, &jp);
        assert_eq!(
            validate_support_event(&message(&customer, &grant, 1, None), &grant),
            Err("restricted: support grants may publish only kind 9")
        );
        assert_eq!(
            validate_support_event(&message(&Keys::generate(), &grant, 9, None), &grant),
            Err("restricted: support event author does not match grant")
        );
        let mut wrong_channel = grant.clone();
        wrong_channel.channel_id = uuid::Uuid::new_v4();
        assert_eq!(
            validate_support_event(&message(&customer, &wrong_channel, 9, None), &grant),
            Err("restricted: message is outside the authorized support DM")
        );
    }
}
