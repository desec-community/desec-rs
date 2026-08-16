//! Cursor pagination over a real HTTP round trip.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use desec::api::rrsets::Rrset;
use desec::{Cursor, RecordType};
use futures_util::{StreamExt, TryStreamExt};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate};

const DOMAIN: &str = "example.com";
const RRSETS_PATH: &str = "/api/v1/domains/example.com/rrsets/";
const DOMAINS_PATH: &str = "/api/v1/domains/";
const TOKENS_PATH: &str = "/api/v1/auth/tokens/";
const TOKEN_ID: &str = "3a6b94b5-d20e-40bd-a7cc-521f5c79fab3";
const OTHER_TOKEN_ID: &str = "f7ab039b-07b8-493d-ac61-4ddcf903d4de";

/// The page size deSEC serves all three paginated collections at.
const FULL_PAGE: usize = 500;

/// A request for the page at `cursor` of any paginated collection.
fn page_at(collection: &str, cursor: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path(collection.to_owned()))
        .and(query_param("cursor", cursor))
}

/// A request for the page at `cursor`, with the response left to the caller.
fn list_page(cursor: &str) -> MockBuilder {
    page_at(RRSETS_PATH, cursor)
}

/// One `Link` entry, shaped as the API writes them: absolute URL, quoted `rel`.
fn link_to(server: &MockServer, collection: &str, rel: &str, cursor: &str) -> String {
    format!(
        "<{}{collection}?cursor={cursor}>; rel=\"{rel}\"",
        server.uri()
    )
}

fn link(server: &MockServer, rel: &str, cursor: &str) -> String {
    link_to(server, RRSETS_PATH, rel, cursor)
}

/// A page of any collection, advertising `next` when there is one.
fn page_of(
    server: &MockServer,
    collection: &str,
    items: Vec<serde_json::Value>,
    next: Option<&str>,
) -> ResponseTemplate {
    let response = ResponseTemplate::new(200).set_body_json(serde_json::Value::Array(items));
    match next {
        None => response,
        Some(next) => {
            let header = format!(
                "{}, {}",
                link_to(server, collection, "next", next),
                link_to(server, collection, "first", "")
            );
            response.insert_header("Link", header.as_str())
        }
    }
}

/// A page of RRsets, advertising `next` when there is one.
fn page_response(server: &MockServer, names: &[&str], next: Option<&str>) -> ResponseTemplate {
    let items = names
        .iter()
        .map(|name| rrset_json(DOMAIN, name, "A", 3600, &["127.0.0.1"]))
        .collect();
    page_of(server, RRSETS_PATH, items, next)
}

fn subnames(items: &[Rrset]) -> Vec<&str> {
    items.iter().map(|item| item.subname.as_payload()).collect()
}

/// The decoded query pairs of the most recent request.
async fn last_query(server: &MockServer) -> Vec<(String, String)> {
    let requests = server.received_requests().await.expect("recorded requests");
    requests
        .last()
        .expect("a request reached the server")
        .url
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_owned(), value.to_owned())
}

/// How many requests reached the server, across every mock.
async fn request_count(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("recorded requests")
        .len()
}

#[tokio::test]
async fn a_response_without_a_link_header_is_a_single_page() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["www", "mail"], None))
        .mount(&server)
        .await;

    let page = client.rrsets(DOMAIN).list().send().await.expect("a page");

    assert!(page.next.is_none());
    assert!(!page.has_next());
    assert_eq!(subnames(&page.items), ["www", "mail"]);
}

#[tokio::test]
async fn the_first_page_is_requested_with_an_empty_cursor() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &[], None))
        .expect(1)
        .mount(&server)
        .await;

    client.rrsets(DOMAIN).list().send().await.expect("a page");

    // Dropping the parameter instead of sending it empty is what makes the API answer
    // `400 Pagination required` once a zone outgrows one page.
    assert_eq!(last_query(&server).await, vec![pair("cursor", "")]);
    server.verify().await;
}

#[tokio::test]
async fn a_first_page_exposes_the_next_and_first_cursors() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["a"], Some("p2")))
        .mount(&server)
        .await;

    let page = client.rrsets(DOMAIN).list().send().await.expect("a page");

    assert!(page.has_next());
    assert_eq!(page.next.as_ref().map(Cursor::as_str), Some("p2"));
    assert_eq!(page.first.as_ref().map(Cursor::as_str), Some(""));
}

#[tokio::test]
async fn a_saved_cursor_resumes_at_that_page() {
    let (server, client) = mock().await;
    list_page("p2")
        .respond_with(page_response(&server, &["b"], None))
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .rrsets(DOMAIN)
        .list()
        .cursor("p2")
        .send()
        .await
        .expect("a page");

    assert_eq!(last_query(&server).await, vec![pair("cursor", "p2")]);
    assert_eq!(subnames(&page.items), ["b"]);
    assert!(page.next.is_none());
    server.verify().await;
}

#[tokio::test]
async fn all_walks_every_page_exactly_once() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["a", "b"], Some("p2")))
        .expect(1)
        .mount(&server)
        .await;
    list_page("p2")
        .respond_with(page_response(&server, &["c", "d"], Some("p3")))
        .expect(1)
        .mount(&server)
        .await;
    list_page("p3")
        .respond_with(page_response(&server, &["e"], None))
        .expect(1)
        .mount(&server)
        .await;

    let items = client.rrsets(DOMAIN).list().all().await.expect("all items");

    assert_eq!(subnames(&items), ["a", "b", "c", "d", "e"]);
    server.verify().await;
}

#[tokio::test]
async fn a_page_of_the_full_size_is_walked_whole() {
    let (server, client) = mock().await;
    let owned: Vec<String> = (0..FULL_PAGE).map(|n| format!("host{n}")).collect();
    let full: Vec<&str> = owned.iter().map(String::as_str).collect();
    let tail = ["tail-a", "tail-b", "tail-c"];
    list_page("")
        .respond_with(page_response(&server, &full, Some("p2")))
        .expect(1)
        .mount(&server)
        .await;
    list_page("p2")
        .respond_with(page_response(&server, &tail, None))
        .expect(1)
        .mount(&server)
        .await;

    let items = client.rrsets(DOMAIN).list().all().await.expect("all items");

    // A page boundary is where a dropped, duplicated or re-fetched item would hide, and the
    // boundary a real zone hits is the full one.
    let expected: Vec<&str> = full.iter().chain(tail.iter()).copied().collect();
    assert_eq!(subnames(&items), expected);
    assert_eq!(request_count(&server).await, 2);
    server.verify().await;
}

#[tokio::test]
async fn stream_yields_items_across_pages_in_order() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["a", "b"], Some("p2")))
        .mount(&server)
        .await;
    list_page("p2")
        .respond_with(page_response(&server, &["c"], Some("p3")))
        .mount(&server)
        .await;
    list_page("p3")
        .respond_with(page_response(&server, &["d", "e"], None))
        .mount(&server)
        .await;

    let items: Vec<Rrset> = client
        .rrsets(DOMAIN)
        .list()
        .stream()
        .try_collect()
        .await
        .expect("all items");

    assert_eq!(subnames(&items), ["a", "b", "c", "d", "e"]);
}

#[tokio::test]
async fn stream_does_not_fetch_a_page_nobody_consumed() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["a", "b"], Some("p2")))
        .expect(1)
        .mount(&server)
        .await;
    list_page("p2")
        .respond_with(page_response(&server, &["c"], None))
        .expect(0)
        .mount(&server)
        .await;

    let mut items = client.rrsets(DOMAIN).list().stream();
    let first = items.next().await.expect("a first item").expect("it is ok");
    drop(items);

    // Stopping early has to cost nothing, or streaming a zone of unknown size would be no
    // cheaper than collecting it.
    assert_eq!(first.subname.as_payload(), "a");
    server.verify().await;
}

#[tokio::test]
async fn filters_are_resent_on_every_page() {
    let (server, client) = mock().await;
    list_page("")
        .and(query_param("type", "A"))
        .respond_with(page_response(&server, &["a"], Some("p2")))
        .expect(1)
        .mount(&server)
        .await;
    list_page("p2")
        .and(query_param("type", "A"))
        .respond_with(page_response(&server, &["b"], None))
        .expect(1)
        .mount(&server)
        .await;

    let items = client
        .rrsets(DOMAIN)
        .list()
        .record_type(&RecordType::A)
        .all()
        .await
        .expect("all items");

    // A filter lost on page two would silently widen the result set.
    assert_eq!(subnames(&items), ["a", "b"]);
    server.verify().await;
}

#[tokio::test]
async fn a_second_page_of_domains_is_requested_with_the_next_cursor() {
    let (server, client) = mock().await;
    page_at(DOMAINS_PATH, "")
        .respond_with(page_of(
            &server,
            DOMAINS_PATH,
            vec![domain_json("one.example.com")],
            Some("p2"),
        ))
        .expect(1)
        .mount(&server)
        .await;
    page_at(DOMAINS_PATH, "p2")
        .respond_with(page_of(
            &server,
            DOMAINS_PATH,
            vec![domain_json("two.example.com")],
            None,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let domains = client.domains().list().all().await.expect("all domains");

    let names: Vec<&str> = domains.iter().map(|domain| domain.name.as_str()).collect();
    assert_eq!(names, ["one.example.com", "two.example.com"]);
    assert_eq!(last_query(&server).await, vec![pair("cursor", "p2")]);
    server.verify().await;
}

#[tokio::test]
async fn a_second_page_of_tokens_is_requested_with_the_next_cursor() {
    let (server, client) = mock().await;
    page_at(TOKENS_PATH, "")
        .respond_with(page_of(
            &server,
            TOKENS_PATH,
            vec![token_json(TOKEN_ID, "one", None)],
            Some("p2"),
        ))
        .expect(1)
        .mount(&server)
        .await;
    page_at(TOKENS_PATH, "p2")
        .respond_with(page_of(
            &server,
            TOKENS_PATH,
            vec![token_json(OTHER_TOKEN_ID, "two", None)],
            None,
        ))
        .expect(1)
        .mount(&server)
        .await;

    let tokens = client.tokens().list().all().await.expect("all tokens");

    let names: Vec<&str> = tokens.iter().map(|token| token.name.as_str()).collect();
    assert_eq!(names, ["one", "two"]);
    assert_eq!(last_query(&server).await, vec![pair("cursor", "p2")]);
    server.verify().await;
}

#[tokio::test]
async fn a_percent_encoded_comma_stays_inside_one_cursor() {
    let (server, client) = mock().await;
    let header = format!("<{}{RRSETS_PATH}?cursor=a%2Cb>; rel=\"next\"", server.uri());
    list_page("")
        .respond_with(page_response(&server, &["a"], None).insert_header("Link", header.as_str()))
        .mount(&server)
        .await;

    let page = client.rrsets(DOMAIN).list().send().await.expect("a page");

    assert_eq!(page.next.as_ref().map(Cursor::as_str), Some("a,b"));
}

#[tokio::test]
async fn the_long_spelling_of_previous_populates_prev() {
    let (server, client) = mock().await;
    let header = link(&server, "previous", "p1");
    list_page("p2")
        .respond_with(page_response(&server, &["b"], None).insert_header("Link", header.as_str()))
        .mount(&server)
        .await;

    let page = client
        .rrsets(DOMAIN)
        .list()
        .cursor("p2")
        .send()
        .await
        .expect("a page");

    assert_eq!(page.prev.as_ref().map(Cursor::as_str), Some("p1"));
}

#[tokio::test]
async fn a_link_without_a_cursor_is_ignored() {
    let (server, client) = mock().await;
    let header = format!("<{}{RRSETS_PATH}>; rel=\"next\"", server.uri());
    list_page("")
        .respond_with(page_response(&server, &["a"], None).insert_header("Link", header.as_str()))
        .mount(&server)
        .await;

    let page = client.rrsets(DOMAIN).list().send().await.expect("a page");

    assert!(page.next.is_none());
}

#[tokio::test]
async fn an_empty_page_terminates_both_consumers() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &[], None))
        .mount(&server)
        .await;

    assert!(
        client
            .rrsets(DOMAIN)
            .list()
            .all()
            .await
            .expect("all items")
            .is_empty()
    );
    let items: Vec<Rrset> = client
        .rrsets(DOMAIN)
        .list()
        .stream()
        .try_collect()
        .await
        .expect("all items");
    assert!(items.is_empty());
}

#[tokio::test]
async fn an_error_on_a_later_page_reaches_the_caller() {
    let (server, client) = mock().await;
    list_page("")
        .respond_with(page_response(&server, &["a"], Some("p2")))
        .mount(&server)
        .await;
    list_page("p2")
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"detail": "Invalid cursor."})),
        )
        .mount(&server)
        .await;

    let err = client
        .rrsets(DOMAIN)
        .list()
        .all()
        .await
        .expect_err("the cursor is invalid");
    assert!(err.is_validation(), "{err:?}");

    let mut items = client.rrsets(DOMAIN).list().stream();
    assert_eq!(
        items
            .next()
            .await
            .expect("a first item")
            .expect("it is ok")
            .subname
            .as_payload(),
        "a"
    );
    let err = items
        .next()
        .await
        .expect("a second item")
        .expect_err("the cursor is invalid");
    assert!(err.is_validation(), "{err:?}");
}
