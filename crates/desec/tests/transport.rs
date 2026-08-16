//! Authentication, error mapping, retries and rate limiting on the wire.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use std::time::Duration;

use desec::api::domains::NewDomain;
use desec::api::rrsets::RrsetPatch;
use desec::{Client, Error, Rate, RateLimits, RecordType, Scope, Subname};
use wiremock::matchers::{any, body_json, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const DOMAINS_PATH: &str = "/api/v1/domains/";
const DOMAIN_PATH: &str = "/api/v1/domains/example.com/";
const APEX_A_PATH: &str = "/api/v1/domains/example.com/rrsets/@/A/";

/// A client with limits out of the way and no per-attempt timeout, so the tests that run
/// on a paused clock cannot have a timeout fire while the socket is still working.
fn client_with_retries(server: &MockServer, retries: u32) -> Client {
    Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited())
        .max_retries(retries)
        .build()
        .expect("valid client")
}

/// A client whose cheap bucket holds one call per hour, so a second one is refused outright
/// rather than paced.
fn client_with_one_cheap_call(server: &MockServer) -> Client {
    Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited().with_scope(
            Scope::DnsApiCheap,
            [Rate::new(1, Duration::from_secs(3600)).expect("valid rate")],
        ))
        .max_rate_limit_wait(Duration::from_secs(1))
        .max_retries(0)
        .build()
        .expect("valid client")
}

fn ok_domain() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(domain_json("example.com"))
}

fn header_value(request: &Request, name: &str) -> Option<String> {
    request
        .headers
        .get(name)
        .map(|value| value.to_str().expect("header is text").to_owned())
}

async fn requests(server: &MockServer) -> Vec<Request> {
    server.received_requests().await.expect("recorded requests")
}

async fn request_count(server: &MockServer) -> usize {
    requests(server).await.len()
}

/// Mounts a single error response and returns the error a domain read produces.
async fn error_from(status: u16, body: &str, content_type: &str) -> Error {
    let (server, client) = mock().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(status).set_body_raw(body.to_owned(), content_type))
        .mount(&server)
        .await;
    client
        .domains()
        .get("example.com")
        .await
        .expect_err("an error status")
}

#[tokio::test]
async fn requests_authenticate_with_the_token_scheme() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ok_domain())
        .expect(1)
        .mount(&server)
        .await;

    client.domains().get("example.com").await.expect("a domain");

    // deSEC rejects `Bearer`, so the scheme is pinned rather than merely present.
    let sent = header_value(&requests(&server).await[0], "authorization");
    assert_eq!(sent.as_deref(), Some(auth_header().as_str()));
    server.verify().await;
}

#[tokio::test]
async fn a_client_without_a_token_sends_no_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    anonymous_client_for(&server)
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    assert_eq!(
        header_value(&requests(&server).await[0], "authorization"),
        None
    );
}

#[tokio::test]
async fn the_user_agent_names_the_crate_and_can_be_overridden() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    client_for(&server)
        .domains()
        .get("example.com")
        .await
        .expect("a domain");
    Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .user_agent("x/1")
        .rate_limits(RateLimits::unlimited())
        .max_retries(0)
        .build()
        .expect("valid client")
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    let sent = requests(&server).await;
    let default = header_value(&sent[0], "user-agent").expect("a user-agent");
    assert!(default.starts_with("desec-rs/"), "{default}");
    assert_eq!(header_value(&sent[1], "user-agent").as_deref(), Some("x/1"));
}

#[tokio::test]
async fn with_token_swaps_the_credential_and_keeps_the_base_url() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    let original = client_for(&server);
    let derived = original.with_token("other-token");
    derived
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    assert_eq!(
        header_value(&requests(&server).await[0], "authorization").as_deref(),
        Some("Token other-token")
    );
    assert_eq!(derived.base_url(), original.base_url());
}

#[tokio::test]
async fn a_json_body_is_typed_and_a_get_carries_none() {
    let server = MockServer::start().await;
    let client = client_for(&server);
    Mock::given(method("POST"))
        .and(path(DOMAINS_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(domain_json("example.com")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    client
        .domains()
        .create(&NewDomain::new("example.com"))
        .await
        .expect("a created domain");
    client.domains().get("example.com").await.expect("a domain");

    let sent = requests(&server).await;
    assert_eq!(
        header_value(&sent[0], "content-type").as_deref(),
        Some("application/json")
    );
    assert!(!sent[0].body.is_empty());
    assert!(sent[1].body.is_empty());
}

#[tokio::test]
async fn a_field_error_keeps_the_servers_message() {
    let err = error_from(
        400,
        r#"{"ttl":["Ensure this value is greater than or equal to 3600."]}"#,
        "application/json",
    )
    .await;

    assert!(err.is_validation(), "{err:?}");
    assert_eq!(
        err.api_error()
            .expect("api error")
            .field("ttl")
            .expect("ttl field")
            .messages(),
        ["Ensure this value is greater than or equal to 3600."]
    );
}

#[tokio::test]
async fn a_nested_error_keeps_its_path() {
    let err = error_from(
        400,
        r#"{"captcha":{"solution":["Invalid."]}}"#,
        "application/json",
    )
    .await;

    assert_eq!(
        err.api_error().expect("api error").messages(),
        [("captcha.solution".to_owned(), "Invalid.")]
    );
}

#[tokio::test]
async fn statuses_map_onto_the_classifiers() {
    for status in [401u16, 403, 404] {
        let err = error_from(status, r#"{"detail":"No."}"#, "application/json").await;
        let classified = match status {
            401 => err.is_unauthorized(),
            403 => err.is_forbidden(),
            _ => err.is_not_found(),
        };
        assert!(classified, "{status} was not classified: {err:?}");
        assert_eq!(err.api_error().expect("api error").detail(), Some("No."));
    }
}

#[tokio::test]
async fn a_non_json_error_body_is_kept_as_text() {
    let html = "<html><head><title>502 Bad Gateway</title></head></html>";
    let err = error_from(502, html, "text/html").await;

    assert_eq!(err.api_error().expect("api error").detail(), Some(html));
}

#[tokio::test]
async fn an_empty_error_body_is_harmless() {
    let err = error_from(400, "", "text/plain").await;

    assert!(err.is_validation(), "{err:?}");
    assert_eq!(err.api_error().expect("api error").detail(), Some(""));
}

#[tokio::test]
async fn an_unexpected_success_body_is_a_decode_error() {
    let (server, client) = mock().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"nope": 1})))
        .mount(&server)
        .await;

    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("the body does not decode");

    assert!(matches!(err, Error::Decode { .. }), "{err:?}");
    assert!(err.to_string().contains("Domain"), "{err}");
}

#[tokio::test]
async fn an_api_error_displays_the_method_path_and_status() {
    let err = error_from(404, r#"{"detail":"Not found."}"#, "application/json").await;

    let rendered = err.to_string();
    assert!(rendered.contains("GET"), "{rendered}");
    assert!(rendered.contains(DOMAIN_PATH), "{rendered}");
    assert!(rendered.contains("404"), "{rendered}");
}

#[tokio::test(start_paused = true)]
async fn a_server_error_is_retried_until_it_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    let domain = client_with_retries(&server, 2)
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    assert_eq!(domain.name, "example.com");
    assert_eq!(request_count(&server).await, 2);
}

#[tokio::test]
async fn retries_disabled_means_one_attempt() {
    let (server, client) = mock().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("a server error");

    assert_eq!(err.status().map(|s| s.as_u16()), Some(500));
    assert_eq!(request_count(&server).await, 1);
}

#[tokio::test(start_paused = true)]
async fn a_client_error_is_never_retried() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({"ttl": ["No."]})))
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 3)
        .domains()
        .get("example.com")
        .await
        .expect_err("a client error");

    // A 400 will answer the same way forever, so retrying only burns rate-limit budget.
    assert!(err.is_validation(), "{err:?}");
    assert_eq!(request_count(&server).await, 1);
}

/// A replay has to carry the original body, or the second attempt writes something else.
#[tokio::test(start_paused = true)]
async fn a_retry_resends_the_same_body() {
    let server = MockServer::start().await;
    let rrset_path = "/api/v1/domains/example.com/rrsets/www/A/";
    let body = serde_json::json!({
        "subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"],
    });
    Mock::given(method("PUT"))
        .and(path(rrset_path))
        .and(body_json(&body))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("PUT"))
        .and(path(rrset_path))
        .and(body_json(&body))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    client_with_retries(&server, 2)
        .rrsets("example.com")
        .replace(
            &"www".parse().expect("valid subname"),
            &desec::RecordType::A,
            3600,
            ["127.0.0.1"],
        )
        .await
        .expect("a replaced rrset");

    let sent = requests(&server).await;
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].body, sent[1].body);
    server.verify().await;
}

/// A 5xx leaves it unknown whether the server processed the request, so replaying a POST
/// could mint a second token or send a second confirmation email. Only idempotent methods
/// are retried.
#[tokio::test(start_paused = true)]
async fn a_non_idempotent_request_is_not_replayed_after_a_server_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DOMAINS_PATH))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 3)
        .domains()
        .create(&NewDomain::new("example.com"))
        .await
        .expect_err("a 500 on a POST is not retried");

    assert_eq!(err.status().expect("a status").as_u16(), 500);
    assert_eq!(request_count(&server).await, 1);
    server.verify().await;
}

/// A 429 was rejected before processing, so replaying it is safe for any method — the
/// idempotence rule that governs 5xx must not suppress throttle retries.
#[tokio::test(start_paused = true)]
async fn a_throttled_post_is_still_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(DOMAINS_PATH))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(DOMAINS_PATH))
        .respond_with(ResponseTemplate::new(201).set_body_json(domain_json("example.com")))
        .expect(1)
        .mount(&server)
        .await;

    client_with_retries(&server, 2)
        .domains()
        .create(&NewDomain::new("example.com"))
        .await
        .expect("a created domain");

    assert_eq!(request_count(&server).await, 2);
    server.verify().await;
}

/// A `Retry-After` the client refuses to honour must not be written into the limiter it
/// then refuses to wait out. `Scope::User` is in every scope set, so one absurd header
/// would otherwise take the whole client offline for its duration.
#[tokio::test(start_paused = true)]
async fn an_unhonoured_retry_after_does_not_wedge_later_requests() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "100000"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/other.example/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(domain_json("other.example")))
        .expect(1)
        .mount(&server)
        .await;

    // Real limits, so `record_throttled` actually has buckets to write a penalty into.
    let client = desec::Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .max_retries(0)
        .max_rate_limit_wait(Duration::from_secs(60))
        .build()
        .expect("valid client");

    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");
    assert!(err.is_rate_limited(), "{err:?}");

    // A different domain, and a scope that was never at fault, must still be reachable
    // once the capped penalty has elapsed rather than 27 hours later.
    tokio::time::advance(Duration::from_secs(61)).await;
    client
        .domains()
        .get("other.example")
        .await
        .expect("the penalty was capped at max_rate_limit_wait");
    server.verify().await;
}

/// The header is proxy-controlled and reaches `Instant` arithmetic, which panics on
/// overflow.
#[tokio::test(start_paused = true)]
async fn an_absurd_retry_after_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/"))
        .respond_with(
            ResponseTemplate::new(429).insert_header("retry-after", "18446744073709551615"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = desec::Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .max_retries(0)
        .build()
        .expect("valid client");

    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");
    assert!(err.is_rate_limited(), "{err:?}");
}

/// A domain name that `url` would collapse must be rejected rather than silently
/// addressing the collection endpoint.
#[tokio::test]
async fn a_dot_segment_domain_never_reaches_the_network() {
    let (server, client) = mock().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    for name in ["..", ".", ""] {
        let err = client
            .domains()
            .delete(name)
            .await
            .expect_err("not addressable");
        assert!(err.is_validation(), "{name:?}: {err:?}");
        let err = client
            .rrsets(name)
            .get(&desec::Subname::apex(), &desec::RecordType::A)
            .await
            .expect_err("not addressable");
        assert!(err.is_validation(), "{name:?}: {err:?}");
    }
    server.verify().await;
}

// The 429 tests run on a paused clock: `Retry-After` is honoured through
// `tokio::time::sleep`, and wiremock serves from its own runtime on another thread, so the
// test clock can jump the sleeps without the mock server noticing.
#[tokio::test(start_paused = true)]
async fn a_throttled_request_waits_out_retry_after_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    client_with_retries(&server, 1)
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    assert_eq!(request_count(&server).await, 2);
}

#[tokio::test(start_paused = true)]
async fn a_persistent_throttle_exhausts_the_retry_budget() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "1"))
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 1)
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");

    assert!(err.is_rate_limited(), "{err:?}");
    match err {
        Error::RateLimited {
            attempts,
            retry_after,
            ..
        } => {
            assert_eq!(attempts, 2);
            assert_eq!(retry_after, Some(Duration::from_secs(1)));
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
    assert_eq!(request_count(&server).await, 2);
}

#[tokio::test(start_paused = true)]
async fn a_retry_after_beyond_the_ceiling_fails_instead_of_sleeping() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "10"))
        .mount(&server)
        .await;
    let client = Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited())
        .max_retries(3)
        .max_retry_delay(Duration::from_secs(1))
        .build()
        .expect("valid client");

    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("a retry-after over the ceiling");

    assert!(
        matches!(err, Error::RateLimited { attempts: 1, .. }),
        "{err:?}"
    );
    assert_eq!(request_count(&server).await, 1);
}

#[tokio::test(start_paused = true)]
async fn a_throttle_without_retry_after_falls_back_to_backoff() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 1)
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");

    assert!(
        matches!(
            err,
            Error::RateLimited {
                attempts: 2,
                retry_after: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(request_count(&server).await, 2);
}

/// `Retry-After` in its HTTP-date form, offset from the wall clock. The parse resolves the
/// date against `Utc::now()`, which the paused test clock does not move, so the offset has
/// to be real seconds rather than a fixed calendar date.
fn http_date_offset_by(secs: i64) -> String {
    let at = chrono::Utc::now() + chrono::TimeDelta::seconds(secs);
    at.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[tokio::test(start_paused = true)]
async fn a_throttled_request_waits_out_an_http_date_retry_after_and_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(
            ResponseTemplate::new(429).insert_header("Retry-After", http_date_offset_by(30)),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(DOMAIN_PATH))
        .respond_with(ok_domain())
        .mount(&server)
        .await;

    client_with_retries(&server, 1)
        .domains()
        .get("example.com")
        .await
        .expect("a domain");

    assert_eq!(request_count(&server).await, 2);
}

/// A date that parsed into nothing would be indistinguishable from one that was honoured,
/// so the wait has to reach the caller. What the date resolves to exactly is pinned by the
/// unit tests over the parse itself.
#[tokio::test(start_paused = true)]
async fn an_http_date_retry_after_surfaces_to_the_caller() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(429).insert_header("Retry-After", http_date_offset_by(3600)),
        )
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 0)
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");

    match err {
        Error::RateLimited {
            attempts,
            retry_after,
            ..
        } => {
            assert_eq!(attempts, 1);
            retry_after.expect("the date parsed into a wait");
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
    assert_eq!(request_count(&server).await, 1);
}

/// A deadline that has already passed yields no wait at all rather than a zero or a
/// wrapped-around one, so the client falls back to its own backoff.
#[tokio::test(start_paused = true)]
async fn an_http_date_retry_after_in_the_past_falls_back_to_backoff() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT"),
        )
        .mount(&server)
        .await;

    let err = client_with_retries(&server, 1)
        .domains()
        .get("example.com")
        .await
        .expect_err("throttled");

    assert!(
        matches!(
            err,
            Error::RateLimited {
                attempts: 2,
                retry_after: None,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(request_count(&server).await, 2);
}

#[tokio::test]
async fn the_local_limiter_refuses_before_the_request_goes_out() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .expect(1)
        .mount(&server)
        .await;
    let client = client_with_one_cheap_call(&server);

    client.domains().get("example.com").await.expect("a domain");
    let err = client
        .domains()
        .get("example.com")
        .await
        .expect_err("the local limiter refuses");

    assert!(
        matches!(
            err,
            Error::RateLimitWouldBlock {
                scope: Scope::DnsApiCheap,
                ..
            }
        ),
        "{err:?}"
    );
    // The bucket is consulted before the socket, so a refused call costs nothing upstream.
    server.verify().await;
}

#[tokio::test]
async fn separately_built_clients_each_get_their_own_buckets() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .expect(2)
        .mount(&server)
        .await;
    let one = client_with_one_cheap_call(&server);
    let another = client_with_one_cheap_call(&server);

    one.domains().get("example.com").await.expect("a domain");
    another
        .domains()
        .get("example.com")
        .await
        .expect("a client built on its own does not inherit another's spending");

    server.verify().await;
}

#[tokio::test]
async fn derived_clients_pace_against_the_same_buckets() {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ok_domain())
        .expect(1)
        .mount(&server)
        .await;
    let client = client_with_one_cheap_call(&server);
    let cloned = client.clone();
    let reauthenticated = client.with_token("Kd8Nv2iQ-oJ4bF7xLpR1sYcTuWzA");

    client.domains().get("example.com").await.expect("a domain");

    for (how, derived) in [("clone", &cloned), ("with_token", &reauthenticated)] {
        let err = derived
            .domains()
            .get("example.com")
            .await
            .expect_err("the hour's single call is already spent");
        assert!(
            matches!(
                err,
                Error::RateLimitWouldBlock {
                    scope: Scope::DnsApiCheap,
                    ..
                }
            ),
            "{how}: {err:?}"
        );
    }

    server.verify().await;
}

#[tokio::test]
async fn rrset_reads_and_writes_draw_on_separate_scopes() {
    let server = MockServer::start().await;
    let rrset = rrset_json("example.com", "", "A", 3600, &["127.0.0.1"]);
    Mock::given(method("GET"))
        .and(path(APEX_A_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset.clone()))
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path(APEX_A_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset))
        .mount(&server)
        .await;
    let client = Client::builder()
        .base_url(format!("{}/api/v1", server.uri()))
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited().with_scope(
            Scope::DnsApiCheap,
            [Rate::new(1, Duration::from_secs(3600)).expect("valid rate")],
        ))
        .max_rate_limit_wait(Duration::from_secs(1))
        .max_retries(0)
        .build()
        .expect("valid client");

    client
        .rrsets("example.com")
        .get(&Subname::apex(), &RecordType::A)
        .await
        .expect("an rrset");
    client
        .rrsets("example.com")
        .patch(
            &Subname::apex(),
            &RecordType::A,
            &RrsetPatch::new().ttl(3600),
        )
        .await
        .expect("a patched rrset");
    let err = client
        .rrsets("example.com")
        .get(&Subname::apex(), &RecordType::A)
        .await
        .expect_err("the read budget is spent");

    // The write drew on the per-domain scope, so it must not have spent the read budget.
    assert!(
        matches!(
            err,
            Error::RateLimitWouldBlock {
                scope: Scope::DnsApiCheap,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(request_count(&server).await, 2);
}
