//! Token and token policy management: `/auth/tokens/`.
//!
//! Two things worth knowing before minting tokens.
//!
//! A token starts with no permissions at all, so a provisioning token needs
//! `perm_create_domain` set explicitly at creation — [`TokenUpdate`] can express that,
//! which is what makes the difference between a usable provisioning credential and one
//! that can only read.
//!
//! Scoping works by longest-prefix match over policies, and a default policy — the one
//! with `domain`, `subname` and `type` all null — has to exist before any specific policy
//! can be added, and cannot be removed while others remain.

use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::client::{Client, Secret};
use crate::error::Result;
use crate::page::ListRequest;
use crate::ratelimit::{Scope, ScopeSet};
use crate::types::{DjangoDuration, RecordType, Subname};

/// An API or login token.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct Token {
    /// Identifies the token. Not the secret, and safe to log.
    pub id: Uuid,
    /// When the token was created.
    pub created: DateTime<Utc>,
    /// When the token was last used, or `None` if never.
    #[serde(default)]
    pub last_used: Option<DateTime<Utc>>,
    /// Email address of the account that created the token.
    pub owner: String,
    /// Email address of the account the token acts on, when it differs from the owner.
    #[serde(default)]
    pub user_override: Option<String>,
    /// `None` for an API token. For a login token, whether 2FA was used.
    #[serde(default)]
    pub mfa: Option<bool>,
    /// Free-text label.
    #[serde(default)]
    pub name: String,
    /// Whether the token may create domains.
    pub perm_create_domain: bool,
    /// Whether the token may delete domains.
    pub perm_delete_domain: bool,
    /// Whether the token may manage tokens and their policies.
    pub perm_manage_tokens: bool,
    /// Subnets a client must connect from. Defaults to `["0.0.0.0/0", "::/0"]`.
    #[serde(default)]
    pub allowed_subnets: Vec<String>,
    /// Whether deSEC maintains a permissive scoping policy automatically.
    pub auto_policy: bool,
    /// Whether the token is still valid under `max_age` and `max_unused_period`.
    pub is_valid: bool,
    /// Lifetime from creation, or `None` for no limit.
    #[serde(default)]
    pub max_age: Option<DjangoDuration>,
    /// Idle timeout, or `None` for no limit.
    #[serde(default)]
    pub max_unused_period: Option<DjangoDuration>,
    /// The secret.
    ///
    /// Returned only by [`TokensApi::create`] and [`AccountApi::log_in`], and never
    /// again — store it at that point or it is lost.
    ///
    /// [`AccountApi::log_in`]: crate::api::AccountApi::log_in
    #[serde(default)]
    pub token: Option<Secret>,
}

/// Fields to set when creating a token, or to change on an existing one.
///
/// Used for both `POST` and `PATCH`. Unset fields are omitted, which on `PATCH` means
/// "leave alone". The two duration fields distinguish "leave alone" from "clear": call
/// [`clear_max_age`](Self::clear_max_age) to send an explicit `null`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TokenUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    perm_create_domain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    perm_delete_domain: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    perm_manage_tokens: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_policy: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_subnets: Option<Vec<String>>,
    // The outer Option decides whether the field is sent; the inner one decides whether
    // it is sent as null. Without that distinction a duration could be set but never
    // cleared.
    #[serde(skip_serializing_if = "Option::is_none")]
    max_age: Option<Option<DjangoDuration>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_unused_period: Option<Option<DjangoDuration>>,
}

impl TokenUpdate {
    /// An update that changes nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the label.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Grants or revokes domain creation.
    pub fn perm_create_domain(mut self, allowed: bool) -> Self {
        self.perm_create_domain = Some(allowed);
        self
    }

    /// Grants or revokes domain deletion.
    pub fn perm_delete_domain(mut self, allowed: bool) -> Self {
        self.perm_delete_domain = Some(allowed);
        self
    }

    /// Grants or revokes token management.
    pub fn perm_manage_tokens(mut self, allowed: bool) -> Self {
        self.perm_manage_tokens = Some(allowed);
        self
    }

    /// Turns automatic scoping-policy maintenance on or off.
    pub fn auto_policy(mut self, enabled: bool) -> Self {
        self.auto_policy = Some(enabled);
        self
    }

    /// Restricts which subnets the token may be used from.
    pub fn allowed_subnets(mut self, subnets: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allowed_subnets = Some(subnets.into_iter().map(Into::into).collect());
        self
    }

    /// Expires the token this long after creation.
    pub fn max_age(mut self, max_age: DjangoDuration) -> Self {
        self.max_age = Some(Some(max_age));
        self
    }

    /// Removes the lifetime limit, by sending `max_age: null`.
    pub fn clear_max_age(mut self) -> Self {
        self.max_age = Some(None);
        self
    }

    /// Expires the token after this long without use.
    pub fn max_unused_period(mut self, period: DjangoDuration) -> Self {
        self.max_unused_period = Some(Some(period));
        self
    }

    /// Removes the idle timeout, by sending `max_unused_period: null`.
    pub fn clear_max_unused_period(mut self) -> Self {
        self.max_unused_period = Some(None);
        self
    }
}

/// An RRset scoping policy attached to a token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct TokenPolicy {
    /// Identifies the policy.
    pub id: Uuid,
    /// The domain this applies to, or `None` to match any.
    pub domain: Option<String>,
    /// The name this applies to, or `None` to match any.
    pub subname: Option<Subname>,
    /// The record type this applies to, or `None` to match any.
    #[serde(rename = "type")]
    pub record_type: Option<RecordType>,
    /// Whether matching RRsets may be written.
    pub perm_write: bool,
}

impl TokenPolicy {
    /// Whether this is the token's default policy, the one that matches everything.
    pub fn is_default(&self) -> bool {
        self.domain.is_none() && self.subname.is_none() && self.record_type.is_none()
    }
}

/// A policy to create.
///
/// All four fields are sent, because `null` is meaningful: it is the wildcard, and a
/// policy with all three of `domain`, `subname` and `type` null is the default policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewTokenPolicy {
    /// The domain to scope to, or `None` for any.
    pub domain: Option<String>,
    /// The name to scope to, or `None` for any.
    pub subname: Option<Subname>,
    /// The type to scope to, or `None` for any.
    #[serde(rename = "type")]
    pub record_type: Option<RecordType>,
    /// Whether matching RRsets may be written.
    pub perm_write: bool,
}

impl NewTokenPolicy {
    /// The default policy, which every token needs before it can have any other.
    ///
    /// Exactly one policy may have all three selectors null; a second one is rejected
    /// under `non_field_errors`.
    pub fn default_policy(perm_write: bool) -> Self {
        Self {
            domain: None,
            subname: None,
            record_type: None,
            perm_write,
        }
    }

    /// A policy scoped to one domain, matching every name and type within it.
    pub fn for_domain(domain: impl Into<String>, perm_write: bool) -> Self {
        Self {
            domain: Some(domain.into()),
            subname: None,
            record_type: None,
            perm_write,
        }
    }

    /// Narrows the policy to one name.
    pub fn subname(mut self, subname: Subname) -> Self {
        self.subname = Some(subname);
        self
    }

    /// Narrows the policy to one record type.
    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = Some(record_type);
        self
    }
}

/// A partial update to a policy.
///
/// `perm_write` is sent whenever it is set, including when set to `false`. That matters:
/// the API preserves the existing value for an omitted field, so a serializer that drops
/// `false` can grant write permission but never take it back.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TokenPolicyPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subname: Option<Option<Subname>>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    record_type: Option<Option<RecordType>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    perm_write: Option<bool>,
}

impl TokenPolicyPatch {
    /// An update that changes nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants or revokes write permission. Revoking works, because `false` is sent.
    pub fn perm_write(mut self, allowed: bool) -> Self {
        self.perm_write = Some(allowed);
        self
    }

    /// Re-scopes the policy to one domain.
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(Some(domain.into()));
        self
    }

    /// Widens the policy to any domain, by sending `domain: null`.
    ///
    /// If `subname` and `type` are already null this turns the policy into a default
    /// policy, which fails when the token already has one.
    pub fn any_domain(mut self) -> Self {
        self.domain = Some(None);
        self
    }

    /// Re-scopes the policy to one name.
    pub fn subname(mut self, subname: Subname) -> Self {
        self.subname = Some(Some(subname));
        self
    }

    /// Widens the policy to any name, by sending `subname: null`.
    pub fn any_subname(mut self) -> Self {
        self.subname = Some(None);
        self
    }

    /// Re-scopes the policy to one record type.
    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = Some(Some(record_type));
        self
    }

    /// Widens the policy to any record type, by sending `type: null`.
    pub fn any_record_type(mut self) -> Self {
        self.record_type = Some(None);
        self
    }

    /// Whether this update would change anything.
    pub fn is_empty(&self) -> bool {
        self.domain.is_none()
            && self.subname.is_none()
            && self.record_type.is_none()
            && self.perm_write.is_none()
    }
}

/// Token endpoints.
#[derive(Debug, Clone, Copy)]
pub struct TokensApi<'a> {
    client: &'a Client,
}

impl<'a> TokensApi<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    fn scope() -> ScopeSet {
        ScopeSet::new(Scope::AccountManagementPassive)
    }

    /// `POST /auth/tokens/` — creates a token.
    ///
    /// The returned [`Token::token`] holds the secret, which is the only time the API
    /// discloses it.
    pub async fn create(&self, token: &TokenUpdate) -> Result<Token> {
        let url = self.client.url(&["auth", "tokens"]);
        let req = self
            .client
            .request(Method::POST, url, Self::scope())
            .json(token)?;
        self.client.send_json(req).await
    }

    /// `GET /auth/tokens/` — lists tokens, without their secrets.
    pub fn list(&self) -> ListRequest<Token> {
        ListRequest::new(
            self.client.clone(),
            self.client.url(&["auth", "tokens"]),
            Self::scope(),
        )
    }

    /// `GET /auth/tokens/{id}/` — retrieves one token, without its secret.
    pub async fn get(&self, id: Uuid) -> Result<Token> {
        let url = self.client.url(&["auth", "tokens", &id.to_string()]);
        let req = self.client.request(Method::GET, url, Self::scope());
        self.client.send_json(req).await
    }

    /// As [`get`](Self::get), with `404` mapped onto `None`.
    pub async fn try_get(&self, id: Uuid) -> Result<Option<Token>> {
        let url = self.client.url(&["auth", "tokens", &id.to_string()]);
        let req = self.client.request(Method::GET, url, Self::scope());
        self.client.send_json_opt(req).await
    }

    /// `PATCH /auth/tokens/{id}/` — changes the fields the update sets.
    pub async fn patch(&self, id: Uuid, update: &TokenUpdate) -> Result<Token> {
        let url = self.client.url(&["auth", "tokens", &id.to_string()]);
        let req = self
            .client
            .request(Method::PATCH, url, Self::scope())
            .json(update)?;
        self.client.send_json(req).await
    }

    /// `PUT /auth/tokens/{id}/` — replaces a token's settings.
    ///
    /// Anything the update leaves unset reverts to its default. On a token that has a
    /// `user_override`, omitting that field is a `400`, so prefer
    /// [`patch`](Self::patch) unless a full reset is what you want.
    pub async fn replace(&self, id: Uuid, update: &TokenUpdate) -> Result<Token> {
        let url = self.client.url(&["auth", "tokens", &id.to_string()]);
        let req = self
            .client
            .request(Method::PUT, url, Self::scope())
            .json(update)?;
        self.client.send_json(req).await
    }

    /// `DELETE /auth/tokens/{id}/` — deletes a token.
    ///
    /// Idempotent: succeeds even for an id that does not exist.
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let url = self.client.url(&["auth", "tokens", &id.to_string()]);
        let req = self.client.request(Method::DELETE, url, Self::scope());
        self.client.send_empty(req).await
    }

    /// The RRset scoping policies of one token.
    pub fn policies(&self, token_id: Uuid) -> TokenPoliciesApi<'a> {
        TokenPoliciesApi {
            client: self.client,
            token_id,
        }
    }
}

/// Token policy endpoints, scoped to one token.
///
/// Every call here needs a token with `perm_manage_tokens`.
#[derive(Debug, Clone, Copy)]
pub struct TokenPoliciesApi<'a> {
    client: &'a Client,
    token_id: Uuid,
}

impl TokenPoliciesApi<'_> {
    fn scope() -> ScopeSet {
        ScopeSet::new(Scope::AccountManagementPassive)
    }

    fn collection_url(&self) -> url::Url {
        self.client.url(&[
            "auth",
            "tokens",
            &self.token_id.to_string(),
            "policies",
            "rrsets",
        ])
    }

    fn item_url(&self, policy_id: Uuid) -> url::Url {
        self.client.url(&[
            "auth",
            "tokens",
            &self.token_id.to_string(),
            "policies",
            "rrsets",
            &policy_id.to_string(),
        ])
    }

    /// `GET …/policies/rrsets/` — every policy on the token.
    ///
    /// Returns a plain vector because this endpoint sets `pagination_class = None`
    /// upstream; there are no cursors to follow.
    pub async fn list(&self) -> Result<Vec<TokenPolicy>> {
        let req = self
            .client
            .request(Method::GET, self.collection_url(), Self::scope());
        self.client.send_json(req).await
    }

    /// `POST …/policies/rrsets/` — adds a policy.
    ///
    /// A token needs its default policy — [`NewTokenPolicy::default_policy`] — before any
    /// narrower one is accepted.
    pub async fn create(&self, policy: &NewTokenPolicy) -> Result<TokenPolicy> {
        let req = self
            .client
            .request(Method::POST, self.collection_url(), Self::scope())
            .json(policy)?;
        self.client.send_json(req).await
    }

    /// `GET …/policies/rrsets/{policy}/` — retrieves one policy.
    pub async fn get(&self, policy_id: Uuid) -> Result<TokenPolicy> {
        let req = self
            .client
            .request(Method::GET, self.item_url(policy_id), Self::scope());
        self.client.send_json(req).await
    }

    /// As [`get`](Self::get), with `404` mapped onto `None`.
    pub async fn try_get(&self, policy_id: Uuid) -> Result<Option<TokenPolicy>> {
        let req = self
            .client
            .request(Method::GET, self.item_url(policy_id), Self::scope());
        self.client.send_json_opt(req).await
    }

    /// `PATCH …/policies/rrsets/{policy}/` — changes the fields the patch sets.
    pub async fn patch(&self, policy_id: Uuid, patch: &TokenPolicyPatch) -> Result<TokenPolicy> {
        let req = self
            .client
            .request(Method::PATCH, self.item_url(policy_id), Self::scope())
            .json(patch)?;
        self.client.send_json(req).await
    }

    /// `PUT …/policies/rrsets/{policy}/` — replaces a policy.
    pub async fn replace(&self, policy_id: Uuid, policy: &NewTokenPolicy) -> Result<TokenPolicy> {
        let req = self
            .client
            .request(Method::PUT, self.item_url(policy_id), Self::scope())
            .json(policy)?;
        self.client.send_json(req).await
    }

    /// `DELETE …/policies/rrsets/{policy}/` — removes a policy.
    ///
    /// The default policy cannot be removed while narrower ones remain.
    pub async fn delete(&self, policy_id: Uuid) -> Result<()> {
        let req = self
            .client
            .request(Method::DELETE, self.item_url(policy_id), Self::scope());
        self.client.send_empty(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).expect("serializes")
    }

    /// A provisioning token needs domain permissions at creation, not via a second call.
    #[test]
    fn create_can_express_domain_permissions() {
        let update = TokenUpdate::new()
            .name("provisioning")
            .perm_create_domain(true)
            .perm_delete_domain(true);
        assert_eq!(
            json(&update),
            r#"{"name":"provisioning","perm_create_domain":true,"perm_delete_domain":true}"#
        );
    }

    #[test]
    fn an_empty_update_sends_an_empty_object() {
        assert_eq!(json(&TokenUpdate::new()), "{}");
    }

    /// Omitting leaves a duration alone; clearing has to send an explicit null.
    #[test]
    fn durations_distinguish_leaving_alone_from_clearing() {
        assert_eq!(json(&TokenUpdate::new()), "{}");
        assert_eq!(
            json(&TokenUpdate::new().max_age(DjangoDuration::days(7))),
            r#"{"max_age":"7 00:00:00"}"#
        );
        assert_eq!(
            json(&TokenUpdate::new().clear_max_age()),
            r#"{"max_age":null}"#
        );
        assert_eq!(
            json(&TokenUpdate::new().clear_max_unused_period()),
            r#"{"max_unused_period":null}"#
        );
    }

    /// The API preserves an omitted field, so `false` has to go on the wire.
    #[test]
    fn revoking_write_permission_sends_false() {
        assert_eq!(
            json(&TokenPolicyPatch::new().perm_write(false)),
            r#"{"perm_write":false}"#
        );
    }

    #[test]
    fn a_policy_patch_touching_only_the_domain_leaves_perm_write_alone() {
        let patch = TokenPolicyPatch::new().domain("example.com");
        assert_eq!(json(&patch), r#"{"domain":"example.com"}"#);
        assert!(!json(&patch).contains("perm_write"));
    }

    #[test]
    fn widening_a_policy_selector_sends_null() {
        assert_eq!(
            json(&TokenPolicyPatch::new().any_domain()),
            r#"{"domain":null}"#
        );
    }

    /// The default policy is the all-null one, and every selector must be present.
    #[test]
    fn the_default_policy_sends_three_nulls() {
        assert_eq!(
            json(&NewTokenPolicy::default_policy(true)),
            r#"{"domain":null,"subname":null,"type":null,"perm_write":true}"#
        );
    }

    #[test]
    fn a_domain_scoped_policy_keeps_the_wildcard_selectors() {
        let policy = NewTokenPolicy::for_domain("example.com", true).record_type(RecordType::TXT);
        assert_eq!(
            json(&policy),
            r#"{"domain":"example.com","subname":null,"type":"TXT","perm_write":true}"#
        );
    }

    #[test]
    fn recognizes_the_default_policy_in_a_response() {
        let body = r#"{
            "id": "7aed3f71-bc81-4f7e-90ae-8f0df0d1c211",
            "domain": null,
            "subname": null,
            "type": null,
            "perm_write": true
        }"#;
        let policy: TokenPolicy = serde_json::from_str(body).expect("valid policy");
        assert!(policy.is_default());
    }

    #[test]
    fn deserializes_a_login_token_including_its_secret() {
        let body = r#"{
            "id": "f7ab039b-07b8-493d-ac61-4ddcf903d4de",
            "created": "2022-09-06T16:23:24.585329Z",
            "last_used": null,
            "owner": "you@example.com",
            "user_override": null,
            "mfa": false,
            "max_age": "7 00:00:00",
            "max_unused_period": "01:00:00",
            "name": "",
            "perm_create_domain": true,
            "perm_delete_domain": true,
            "perm_manage_tokens": true,
            "allowed_subnets": ["0.0.0.0/0", "::/0"],
            "auto_policy": false,
            "is_valid": true,
            "token": "i-T3b1h_OI-H9ab8tRS98stGtURe"
        }"#;
        let token: Token = serde_json::from_str(body).expect("valid token");
        assert_eq!(token.mfa, Some(false));
        assert_eq!(token.max_age, Some(DjangoDuration::days(7)));
        assert_eq!(token.max_unused_period, Some(DjangoDuration::hours(1)));
        assert_eq!(
            token.token.as_ref().map(Secret::expose),
            Some("i-T3b1h_OI-H9ab8tRS98stGtURe")
        );
        // A token is often logged for auditing; the secret must not ride along.
        assert!(!format!("{token:?}").contains("i-T3b1h"));
    }

    #[test]
    fn deserializes_an_api_token_without_a_secret() {
        let body = r#"{
            "id": "3a6b94b5-d20e-40bd-a7cc-521f5c79fab3",
            "created": "2018-09-06T09:08:43.762697Z",
            "last_used": null,
            "owner": "you@example.com",
            "user_override": null,
            "mfa": null,
            "max_age": null,
            "max_unused_period": null,
            "name": "my token",
            "perm_create_domain": false,
            "perm_delete_domain": false,
            "perm_manage_tokens": false,
            "allowed_subnets": ["0.0.0.0/0", "::/0"],
            "auto_policy": false,
            "is_valid": true
        }"#;
        let token: Token = serde_json::from_str(body).expect("valid token");
        assert!(token.token.is_none());
        assert_eq!(token.mfa, None, "null mfa marks an API token");
    }
}
