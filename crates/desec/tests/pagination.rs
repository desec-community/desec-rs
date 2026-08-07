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

/// A request for the page at `cursor`, with the response left to the caller.
fn list_page(cursor: &str) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path(RRSETS_PATH))
        .and(query_param("cursor", cursor))
}

/// One `Link` entry, shaped as the API writes them: absolute URL, quoted `rel`.
fn link(server: &MockServer, rel: &str, cursor: &str) -> String {
    format!(
        "<{}{RRSETS_PATH}?cursor={cursor}>; rel=\"{rel}\"",
        server.uri()
    )
}

/// A page of RRsets, advertising `next` when there is one.
fn page_response(server: &MockServer, names: &[&str], next: Option<&str>) -> ResponseTemplate {
    let body = serde_json::Value::Array(
        names
            .iter()
            .map(|name| rrset_json(DOMAIN, name, "A", 3600, &["127.0.0.1"]))
            .collect(),
    );
    let response = ResponseTemplate::new(200).set_body_json(body);
    match next {
        None => response,
        Some(next) => {
            let header = format!(
                "{}, {}",
                link(server, "next", next),
                link(server, "first", "")
            );
            response.insert_header("Link", header.as_str())
        }
    }
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
