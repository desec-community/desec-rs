//! Mocked coverage of the `/domains/` endpoints, asserting request bodies and queries.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use desec::api::domains::NewDomain;
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

/// A list response really does omit `keys`, rather than sending an empty array.
fn domain_json_without_keys(name: &str) -> serde_json::Value {
    serde_json::json!({
        "created": "2018-09-18T16:36:16.510368Z",
        "minimum_ttl": 3600,
        "name": name,
        "published": "2018-09-18T17:21:38.348112Z",
        "touched": "2018-09-18T17:21:38.348112Z",
    })
}

#[tokio::test]
async fn a_plain_creation_sends_the_name_and_nothing_else() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(header("content-type", "application/json"))
        // Exact-body equality is what pins `zonefile` as absent: a `null` would be a 400.
        .and(body_json(serde_json::json!({"name": "example.com"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(domain_json("example.com")))
        .expect(1)
        .mount(&server)
        .await;

    let domain = client
        .domains()
        .create(&NewDomain::new("example.com"))
        .await
        .expect("creation succeeds");

    assert_eq!(domain.name, "example.com");
    assert_eq!(domain.minimum_ttl, 3600);
    assert_eq!(
        domain.created.to_rfc3339(),
        "2018-09-18T16:36:16.510368+00:00"
    );
    assert_eq!(
        domain.published.map(|t| t.to_rfc3339()),
        Some("2018-09-18T17:21:38.348112+00:00".to_owned())
    );
    assert_eq!(
        domain.touched.map(|t| t.to_rfc3339()),
        Some("2018-09-18T17:21:38.348112+00:00".to_owned())
    );
    assert_eq!(domain.keys.len(), 1);
    assert_eq!(domain.keys[0].dnskey, "257 3 13 WFRl60");
    assert_eq!(domain.keys[0].ds.len(), 2);
    assert!(domain.keys[0].managed);
}

#[tokio::test]
async fn a_zonefile_import_travels_alongside_the_name() {
    let (server, client) = mock().await;
    let zonefile = "www 3600 IN A 127.0.0.1\n";
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({
            "name": "example.com",
            "zonefile": zonefile,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(domain_json("example.com")))
        .expect(1)
        .mount(&server)
        .await;

    let domain = client
        .domains()
        .create(&NewDomain::new("example.com").zonefile(zonefile))
        .await
        .expect("creation succeeds");
    assert_eq!(domain.name, "example.com");
}

#[tokio::test]
async fn the_domain_limit_surfaces_as_forbidden() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({"name": "example.com"})))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "detail": "Domain limit exceeded. Please contact support@desec.io to create additional domains."
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .domains()
        .create(&NewDomain::new("example.com"))
        .await
        .expect_err("the account is at its limit");
    assert!(err.is_forbidden(), "{err:?}");
    assert!(!err.is_validation(), "{err:?}");
    assert_eq!(
        err.api_error()
            .expect("a 403 carries an error document")
            .detail(),
        Some(
            "Domain limit exceeded. Please contact support@desec.io to create additional domains."
        )
    );
}

#[tokio::test]
async fn a_rejected_name_keeps_its_per_field_message() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({"name": "com"})))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({"name": ["Invalid value."]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .domains()
        .create(&NewDomain::new("com"))
        .await
        .expect_err("a public suffix is not registrable");
    assert!(err.is_validation(), "{err:?}");
    let api = err.api_error().expect("a 400 carries an error document");
    assert_eq!(
        api.field("name")
            .expect("the message is filed under `name`")
            .messages(),
        vec!["Invalid value."]
    );
    assert_eq!(api.messages(), vec![("name".to_owned(), "Invalid value.")]);
}

#[tokio::test]
async fn listing_sends_an_empty_cursor_and_tolerates_absent_keys() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        // Omitting `cursor` entirely is what makes the API answer 400 once a collection
        // outgrows one page, so the empty value has to be on the wire.
        .and(query_param("cursor", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            domain_json_without_keys("example.com"),
            domain_json_without_keys("example.net"),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .domains()
        .list()
        .send()
        .await
        .expect("the list succeeds");
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].name, "example.com");
    assert_eq!(page.items[1].name, "example.net");
    assert!(page.items[0].keys.is_empty());
    assert!(page.items[1].keys.is_empty());
    assert!(!page.has_next());
    assert_eq!(page.next, None);
    assert_eq!(page.prev, None);
}

#[tokio::test]
async fn a_single_page_collection_costs_one_request() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param("cursor", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            domain_json_without_keys("example.com"),
            domain_json_without_keys("example.net"),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let domains = client
        .domains()
        .list()
        .all()
        .await
        .expect("the list succeeds");
    assert_eq!(
        domains.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        vec!["example.com", "example.net"]
    );
}

#[tokio::test]
async fn fetching_one_domain_yields_its_dnssec_keys() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(domain_json("example.com")))
        .expect(1)
        .mount(&server)
        .await;

    let domain = client
        .domains()
        .get("example.com")
        .await
        .expect("the domain is ours");
    assert_eq!(domain.name, "example.com");
    assert_eq!(domain.keys.len(), 1);
    assert_eq!(
        domain.keys[0].ds,
        vec!["6006 13 2 f34b75", "6006 13 4 2fdcf8"]
    );
}

#[tokio::test]
async fn an_unknown_domain_is_reported_as_not_found() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/absent.example/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"detail": "Not found."})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .domains()
        .get("absent.example")
        .await
        .expect_err("absent, or someone else's");
    assert!(err.is_not_found(), "{err:?}");
}

#[tokio::test]
async fn try_get_maps_absence_onto_none_and_presence_onto_some() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/absent.example/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"detail": "Not found."})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(domain_json("example.com")))
        .expect(1)
        .mount(&server)
        .await;

    assert_eq!(
        client
            .domains()
            .try_get("absent.example")
            .await
            .expect("a 404 is not an error here"),
        None
    );
    let found = client
        .domains()
        .try_get("example.com")
        .await
        .expect("the domain is ours")
        .expect("a 200 means Some");
    assert_eq!(found.name, "example.com");
}

#[tokio::test]
async fn owner_of_asks_the_server_where_the_zone_cut_is() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param("owns_qname", "_acme-challenge.foo.example.com"))
        .and(query_param("cursor", ""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([domain_json_without_keys("example.com")])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let owner = client
        .domains()
        .owner_of("_acme-challenge.foo.example.com")
        .await
        .expect("the query succeeds")
        .expect("one zone covers the name");
    assert_eq!(owner.name, "example.com");
}

#[tokio::test]
async fn owner_of_returns_none_when_no_zone_covers_the_name() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/"))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param("owns_qname", "www.elsewhere.example"))
        .and(query_param("cursor", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    assert!(
        client
            .domains()
            .owner_of("www.elsewhere.example")
            .await
            .expect("the query succeeds")
            .is_none()
    );
}

#[tokio::test]
async fn a_zonefile_export_comes_back_as_verbatim_text() {
    let (server, client) = mock().await;
    let zone = concat!(
        "$ORIGIN example.com.\n",
        "example.com.\t3600\tIN\tSOA\tget.desec.io. get.desec.io. 2021052300 86400 3600 2419200 3600\n",
        "example.com.\t3600\tIN\tNS\tns1.desec.io.\n",
        "example.com.\t3600\tIN\tNS\tns2.desec.org.\n",
        "www.example.com.\t3600\tIN\tA\t127.0.0.1\n",
    );
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/zonefile/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_raw(zone.as_bytes(), "text/plain"))
        .expect(1)
        .mount(&server)
        .await;

    let exported = client
        .domains()
        .zonefile("example.com")
        .await
        .expect("the export succeeds");
    assert_eq!(exported, zone);
}

#[tokio::test]
async fn deleting_a_domain_accepts_an_empty_204() {
    let (server, client) = mock().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/domains/example.com/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client
        .domains()
        .delete("example.com")
        .await
        .expect("deletion succeeds");
}

#[tokio::test]
async fn deleting_an_absent_domain_is_still_a_success() {
    let (server, client) = mock().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/domains/absent.example/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client
        .domains()
        .delete("absent.example")
        .await
        .expect("deletion is idempotent");
}

#[tokio::test]
async fn a_punycode_label_is_not_re_encoded_in_the_path() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/xn--bcher-kva.example/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(domain_json("xn--bcher-kva.example")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let domain = client
        .domains()
        .get("xn--bcher-kva.example")
        .await
        .expect("the domain is ours");
    assert_eq!(domain.name, "xn--bcher-kva.example");
}
