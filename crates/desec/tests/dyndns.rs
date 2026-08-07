//! The dynDNS update protocol, whose whole surface is the query string.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use desec::RateLimits;
use desec::dyndns::{DynDnsClient, Family, IpUpdate};
use wiremock::matchers::{any, method};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const HOST: &str = "example.dedyn.io";

/// A client with the `dyndns` scope unmetered; at 2 requests per 2 minutes the default
/// would pace these tests into a standstill.
fn dyndns_client(server: &MockServer) -> DynDnsClient {
    DynDnsClient::builder()
        .base_url(server.uri())
        .token(TOKEN)
        .rate_limits(RateLimits::unlimited())
        .max_retries(0)
        .build()
        .expect("valid client")
}

/// A server that answers every update with the protocol's success body.
async fn good_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("good"))
        .mount(&server)
        .await;
    server
}

/// Query parameters as the server decoded them, which is the level the protocol is
/// specified at.
fn query_of(request: &Request) -> Vec<(String, String)> {
    request
        .url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

async fn last_query(server: &MockServer) -> Vec<(String, String)> {
    let requests = server.received_requests().await.expect("recorded requests");
    query_of(requests.last().expect("a request reached the server"))
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_owned(), value.to_owned())
}

#[tokio::test]
async fn a_bare_update_sends_only_the_hostname() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .send()
        .await
        .expect("updates");

    // Omitting both address parameters is how the server is told to use the address it saw
    // the request arrive from; sending them empty would delete the records instead.
    assert_eq!(last_query(&server).await, [pair("hostname", HOST)]);
}

#[tokio::test]
async fn the_response_body_is_returned_verbatim() {
    let server = good_server().await;

    let body = dyndns_client(&server)
        .update(HOST)
        .send_body()
        .await
        .expect("updates");

    assert_eq!(body, "good");
}

#[tokio::test]
async fn an_ipv4_address_goes_in_myipv4() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv4(IpUpdate::set(["1.2.3.4"]))
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv4", "1.2.3.4")]
    );
}

#[tokio::test]
async fn an_ipv6_address_goes_in_myipv6() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv6(IpUpdate::set(["2001:db8::1"]))
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv6", "2001:db8::1")]
    );
}

#[tokio::test]
async fn several_addresses_join_with_commas() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv4(IpUpdate::set(["1.2.3.4", "5.6.7.8"]))
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv4", "1.2.3.4,5.6.7.8")]
    );
}

#[tokio::test]
async fn preserve_is_spelled_out() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv4(IpUpdate::Preserve)
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv4", "preserve")]
    );
}

#[tokio::test]
async fn remove_is_an_empty_value() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv4(IpUpdate::Remove)
        .send()
        .await
        .expect("updates");

    // `myipv4=` is the protocol's delete; dropping the parameter would instead let the
    // server fill the record in from the connection address.
    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv4", "")]
    );
}

#[tokio::test]
async fn a_delegated_prefix_passes_through_unchanged() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .ipv6(IpUpdate::set(["2a01:a:b:c::/64"]))
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", HOST), pair("myipv6", "2a01:a:b:c::/64")]
    );
}

#[tokio::test]
async fn several_hostnames_share_one_parameter() {
    let server = good_server().await;

    dyndns_client(&server)
        .update("a.example.dedyn.io")
        .hostname("b.example.dedyn.io")
        .send()
        .await
        .expect("updates");

    assert_eq!(
        last_query(&server).await,
        [pair("hostname", "a.example.dedyn.io,b.example.dedyn.io")]
    );
}

#[tokio::test]
async fn a_per_hostname_override_keeps_its_colon() {
    let server = good_server().await;

    dyndns_client(&server)
        .update(HOST)
        .address_for("a.example.dedyn.io", Family::V4, IpUpdate::set(["1.2.3.4"]))
        .send()
        .await
        .expect("updates");

    // The parameter *name* carries the hostname, so whatever encoding it travels under has
    // to decode back to a single colon-joined key.
    assert_eq!(
        last_query(&server).await,
        [
            pair("hostname", HOST),
            pair("myipv4:a.example.dedyn.io", "1.2.3.4"),
        ]
    );
}

#[tokio::test]
async fn basic_auth_is_sent_as_the_protocol_recommends() {
    let server = good_server().await;
    let client = DynDnsClient::builder()
        .base_url(server.uri())
        .basic_auth("user", "token")
        .rate_limits(RateLimits::unlimited())
        .build()
        .expect("valid client");

    client.update(HOST).send().await.expect("updates");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests[0]
            .headers
            .get("authorization")
            .expect("authorization header"),
        "Basic dXNlcjp0b2tlbg=="
    );
}

#[tokio::test]
async fn token_auth_uses_the_desec_scheme() {
    let server = good_server().await;
    let client = DynDnsClient::builder()
        .base_url(server.uri())
        .token("abc")
        .rate_limits(RateLimits::unlimited())
        .build()
        .expect("valid client");

    client.update(HOST).send().await.expect("updates");

    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests[0]
            .headers
            .get("authorization")
            .expect("authorization header"),
        "Token abc"
    );
}

#[tokio::test]
async fn query_credentials_travel_in_the_query_string() {
    let server = good_server().await;
    let client = DynDnsClient::builder()
        .base_url(server.uri())
        .query_credentials("user", "tok")
        .rate_limits(RateLimits::unlimited())
        .build()
        .expect("valid client");

    client.update(HOST).send().await.expect("updates");

    let query = last_query(&server).await;
    assert!(query.contains(&pair("username", "user")), "{query:?}");
    assert!(query.contains(&pair("password", "tok")), "{query:?}");
}

#[tokio::test]
async fn update_failures_map_onto_the_classifiers() {
    for status in [401u16, 404, 400] {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(status).set_body_string("badauth"))
            .mount(&server)
            .await;

        let err = dyndns_client(&server)
            .update(HOST)
            .send()
            .await
            .expect_err("badauth");
        let classified = match status {
            401 => err.is_unauthorized(),
            404 => err.is_not_found(),
            _ => err.is_validation(),
        };
        assert!(classified, "{status} was not classified: {err:?}");
    }
}

#[tokio::test]
async fn the_rate_limit_domain_stays_off_the_wire() {
    let server = good_server().await;
    let client = dyndns_client(&server);

    client
        .update("a.example.dedyn.io")
        .send()
        .await
        .expect("updates");
    client
        .update("a.example.dedyn.io")
        .rate_limit_domain(HOST)
        .send()
        .await
        .expect("updates");

    // It only picks the bucket the local limiter counts against.
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url.path(), requests[1].url.path());
    assert_eq!(query_of(&requests[0]), query_of(&requests[1]));
}
