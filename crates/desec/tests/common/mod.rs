//! Shared harness for the mocked API tests.
//!
//! Every test runs against a [`wiremock`] server mounted at `/api/v1`, so the paths the
//! client builds are the real ones. Client-side rate limits are off and retries are
//! disabled unless a test asks otherwise, so nothing here sleeps.

#![allow(dead_code)]

use std::time::Duration;

use desec::{Client, RateLimits};
use wiremock::MockServer;

/// The token every request is expected to carry.
pub const TOKEN: &str = "i-T3b1h_OI-H9ab8tRS98stGtURe";

/// A mock server and a client pointed at it.
pub async fn mock() -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = client_for(&server);
    (server, client)
}

/// A client for an existing mock server, with limits and retries out of the way.
pub fn client_for(server: &MockServer) -> Client {
    Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited())
        .max_retries(0)
        .timeout(Duration::from_secs(5))
        .build()
        .expect("mock client configuration is valid")
}

/// A client that has no credentials, for the endpoints that take none.
pub fn anonymous_client_for(server: &MockServer) -> Client {
    Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .rate_limits(RateLimits::unlimited())
        .max_retries(0)
        .build()
        .expect("mock client configuration is valid")
}

/// The `Authorization` header value the client should send.
pub fn auth_header() -> String {
    format!("Token {TOKEN}")
}

/// A domain object as the API renders one, for reuse across tests.
pub fn domain_json(name: &str) -> serde_json::Value {
    serde_json::json!({
        "created": "2018-09-18T16:36:16.510368Z",
        "keys": [{
            "dnskey": "257 3 13 WFRl60",
            "ds": ["6006 13 2 f34b75", "6006 13 4 2fdcf8"],
            "managed": true,
        }],
        "minimum_ttl": 3600,
        "name": name,
        "published": "2018-09-18T17:21:38.348112Z",
        "touched": "2018-09-18T17:21:38.348112Z",
    })
}

/// An RRset object as the API renders one. `subname` is the payload spelling, so the apex
/// is `""`.
pub fn rrset_json(
    domain: &str,
    subname: &str,
    record_type: &str,
    ttl: u32,
    records: &[&str],
) -> serde_json::Value {
    let name = if subname.is_empty() {
        format!("{domain}.")
    } else {
        format!("{subname}.{domain}.")
    };
    serde_json::json!({
        "created": "2019-09-18T16:32:16.510368Z",
        "domain": domain,
        "subname": subname,
        "name": name,
        "records": records,
        "ttl": ttl,
        "touched": "2019-09-18T16:32:16.510368Z",
        "type": record_type,
    })
}

/// A token object as the API renders one. Pass `secret` only where the API discloses it.
pub fn token_json(id: &str, name: &str, secret: Option<&str>) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": id,
        "created": "2018-09-06T09:08:43.762697Z",
        "last_used": null,
        "owner": "you@example.com",
        "user_override": null,
        "mfa": null,
        "max_age": null,
        "max_unused_period": null,
        "name": name,
        "perm_create_domain": false,
        "perm_delete_domain": false,
        "perm_manage_tokens": false,
        "allowed_subnets": ["0.0.0.0/0", "::/0"],
        "auto_policy": false,
        "is_valid": true,
    });
    if let Some(secret) = secret {
        value["token"] = serde_json::Value::String(secret.to_owned());
    }
    value
}

/// A token policy object as the API renders one.
pub fn policy_json(
    id: &str,
    domain: Option<&str>,
    subname: Option<&str>,
    record_type: Option<&str>,
    perm_write: bool,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "domain": domain,
        "subname": subname,
        "type": record_type,
        "perm_write": perm_write,
    })
}
