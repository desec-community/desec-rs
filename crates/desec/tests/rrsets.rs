//! Mocked coverage of the `/domains/{name}/rrsets/` endpoints, apex traps included.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use desec::api::rrsets::{BulkPatch, BulkPut, MAX_TTL, NewRrset, RrsetPatch};
use desec::{RecordType, Subname};
use wiremock::matchers::{any, body_json, header, method, path, query_param};
use wiremock::{Mock, ResponseTemplate};

fn www() -> Subname {
    "www".parse().expect("`www` is a valid subname")
}

#[tokio::test]
async fn creating_one_rrset_sends_all_four_fields() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(header("content-type", "application/json"))
        .and(body_json(serde_json::json!({
            "subname": "www",
            "type": "A",
            "ttl": 3600,
            "records": ["127.0.0.1"],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .create(&NewRrset::new(www(), RecordType::A, 3600, ["127.0.0.1"]))
        .await
        .expect("creation succeeds");

    assert_eq!(rrset.domain, "example.com");
    assert_eq!(rrset.subname, www());
    assert_eq!(rrset.record_type, RecordType::A);
    assert_eq!(rrset.name, "www.example.com.");
    assert_eq!(rrset.ttl, 3600);
    assert_eq!(rrset.records, vec!["127.0.0.1"]);
}

#[tokio::test]
async fn an_apex_creation_spells_the_subname_as_an_empty_string() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        // A body `subname` of `"@"` would create a literal `@` label, not the apex.
        .and(body_json(serde_json::json!({
            "subname": "",
            "type": "MX",
            "ttl": 3600,
            "records": ["10 mx.example.com."],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(rrset_json(
            "example.com",
            "",
            "MX",
            3600,
            &["10 mx.example.com."],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .create(&NewRrset::at_apex(
            RecordType::MX,
            3600,
            ["10 mx.example.com."],
        ))
        .await
        .expect("creation succeeds");
    assert!(rrset.subname.is_apex());
    assert_eq!(rrset.name, "example.com.");
}

#[tokio::test]
async fn a_bulk_creation_posts_a_json_array() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!([
            {"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"]},
            {"subname": "", "type": "TXT", "ttl": 600, "records": ["\"v=spf1 -all\""]},
        ])))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!([
            rrset_json("example.com", "www", "A", 3600, &["127.0.0.1"]),
            rrset_json("example.com", "", "TXT", 600, &["\"v=spf1 -all\""]),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let rrsets = client
        .rrsets("example.com")
        .create_bulk(&[
            NewRrset::new(www(), RecordType::A, 3600, ["127.0.0.1"]),
            NewRrset::at_apex(RecordType::TXT, 600, ["\"v=spf1 -all\""]),
        ])
        .await
        .expect("creation succeeds");

    assert_eq!(rrsets.len(), 2);
    assert_eq!(rrsets[0].subname, www());
    assert!(rrsets[1].subname.is_apex());
}

#[tokio::test]
async fn a_failed_bulk_creation_keeps_the_failing_position() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!([
            {"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"]},
            {"subname": "bad", "type": "A", "ttl": 3600, "records": ["not-an-address"]},
        ])))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!([
            {},
            {"records": ["Invalid record."]},
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .rrsets("example.com")
        .create_bulk(&[
            NewRrset::new(www(), RecordType::A, 3600, ["127.0.0.1"]),
            NewRrset::new(
                "bad".parse().expect("valid subname"),
                RecordType::A,
                3600,
                ["not-an-address"],
            ),
        ])
        .await
        .expect_err("the second item is invalid");

    assert!(err.is_validation(), "{err:?}");
    let api = err.api_error().expect("a 400 carries an error document");
    let items = api.bulk_items().expect("a bulk failure is an array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].messages(), Vec::<&str>::new());
    assert_eq!(items[1].messages(), vec!["Invalid record."]);
    assert_eq!(
        api.messages(),
        vec![("1.records".to_owned(), "Invalid record.")]
    );
}

#[tokio::test]
async fn listing_rrsets_sends_an_empty_cursor() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        // Omitting `cursor` is what turns a large zone's list into a 400.
        .and(query_param("cursor", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            rrset_json("example.com", "www", "A", 3600, &["127.0.0.1"]),
            rrset_json("example.com", "", "MX", 3600, &["10 mx.example.com."]),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .rrsets("example.com")
        .list()
        .send()
        .await
        .expect("the list succeeds");
    assert_eq!(page.items.len(), 2);
    assert!(!page.has_next());
}

#[tokio::test]
async fn a_subname_and_a_type_filter_ride_on_the_same_request() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param("subname", "www"))
        .and(query_param("type", "A"))
        .and(query_param("cursor", ""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([rrset_json(
                "example.com",
                "www",
                "A",
                3600,
                &["127.0.0.1"]
            )])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .rrsets("example.com")
        .list()
        .subname(&www())
        .record_type(&RecordType::A)
        .send()
        .await
        .expect("the filtered list succeeds");
    assert_eq!(page.items.len(), 1);
}

#[tokio::test]
async fn the_apex_subname_filter_is_the_empty_string() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        // `subname=@` would filter for a literal `@` label and match nothing.
        .and(query_param("subname", ""))
        .and(query_param("cursor", ""))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([rrset_json(
                "example.com",
                "",
                "MX",
                3600,
                &["10 mx.example.com."]
            )])),
        )
        .expect(1)
        .mount(&server)
        .await;

    let page = client
        .rrsets("example.com")
        .list()
        .subname(&Subname::apex())
        .send()
        .await
        .expect("the filtered list succeeds");
    assert_eq!(page.items.len(), 1);
    assert!(page.items[0].subname.is_apex());
}

#[tokio::test]
async fn fetching_one_rrset_addresses_it_by_subname_and_type() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
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

    let rrset = client
        .rrsets("example.com")
        .get(&www(), &RecordType::A)
        .await
        .expect("the RRset exists");
    assert_eq!(rrset.records, vec!["127.0.0.1"]);
}

#[tokio::test]
async fn the_apex_is_reached_through_an_at_sign_path_segment() {
    let (server, client) = mock().await;
    // An empty path segment collapses under HTTP normalization, so `/rrsets//A/` never
    // reaches the apex; `@` is the only spelling that does.
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/@/A/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .get(&Subname::apex(), &RecordType::A)
        .await
        .expect("the apex RRset exists");
    assert!(rrset.subname.is_apex());
    assert_eq!(rrset.name, "example.com.");
}

#[tokio::test]
async fn try_get_maps_an_absent_rrset_onto_none() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/www/AAAA/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({"detail": "Not found."})),
        )
        .expect(1)
        .mount(&server)
        .await;

    assert!(
        client
            .rrsets("example.com")
            .try_get(&www(), &RecordType::AAAA)
            .await
            .expect("a 404 is not an error here")
            .is_none()
    );
}

#[tokio::test]
async fn a_ttl_only_patch_never_mentions_records() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
        // `records: null` is a 400 upstream rather than "leave unchanged", so the key has
        // to be absent for a TTL-only update to work at all.
        .and(body_json(serde_json::json!({"ttl": 86400})))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            86400,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .patch(&www(), &RecordType::A, &RrsetPatch::new().ttl(86_400))
        .await
        .expect("the patch succeeds");
    assert_eq!(rrset.ttl, 86_400);
    assert_eq!(rrset.records, vec!["127.0.0.1"]);
}

#[tokio::test]
async fn a_records_only_patch_never_mentions_the_ttl() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({"records": ["1.2.3.4"]})))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            3600,
            &["1.2.3.4"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .patch(
            &www(),
            &RecordType::A,
            &RrsetPatch::new().records(["1.2.3.4"]),
        )
        .await
        .expect("the patch succeeds");
    assert_eq!(rrset.ttl, 3600);
    assert_eq!(rrset.records, vec!["1.2.3.4"]);
}

#[tokio::test]
async fn a_subname_read_from_the_api_can_be_written_straight_back() {
    let (server, client) = mock().await;
    // The API answers with `""` and the URL needs `@`. Feeding a response's `subname`
    // back into a write is exactly where a plain String loses the apex.
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/@/A/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/@/A/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({"ttl": 600})))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "",
            "A",
            600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrsets = client.rrsets("example.com");
    let existing = rrsets
        .get(&Subname::apex(), &RecordType::A)
        .await
        .expect("the apex RRset exists");
    assert_eq!(existing.subname.as_payload(), "");

    let updated = rrsets
        .patch(
            &existing.subname,
            &existing.record_type,
            &RrsetPatch::new().ttl(600),
        )
        .await
        .expect("the patch reaches the apex");
    assert_eq!(updated.ttl, 600);
}

#[tokio::test]
async fn an_empty_record_list_is_how_a_patch_deletes() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({"records": []})))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            3600,
            &[],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .patch(
            &www(),
            &RecordType::A,
            &RrsetPatch::new().records(Vec::<String>::new()),
        )
        .await
        .expect("the deletion succeeds");
    assert!(rrset.records.is_empty());
}

#[tokio::test]
async fn a_replacement_body_agrees_with_its_own_path() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
        // A body `subname` that disagrees with the path is a 400, so both come from the
        // same argument.
        .and(body_json(serde_json::json!({
            "subname": "www",
            "type": "A",
            "ttl": 3600,
            "records": ["1.2.3.4", "5.6.7.8"],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "www",
            "A",
            3600,
            &["1.2.3.4", "5.6.7.8"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .replace(&www(), &RecordType::A, 3600, ["1.2.3.4", "5.6.7.8"])
        .await
        .expect("the replacement succeeds");
    assert_eq!(rrset.subname.as_payload(), "www");
    assert_eq!(rrset.records.len(), 2);
}

#[tokio::test]
async fn an_apex_replacement_uses_at_sign_in_the_path_and_empty_in_the_body() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/domains/example.com/rrsets/@/A/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({
            "subname": "",
            "type": "A",
            "ttl": 3600,
            "records": ["127.0.0.1"],
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let rrset = client
        .rrsets("example.com")
        .replace(&Subname::apex(), &RecordType::A, 3600, ["127.0.0.1"])
        .await
        .expect("the replacement succeeds");
    assert!(rrset.subname.is_apex());
}

#[tokio::test]
async fn deleting_one_rrset_accepts_an_empty_204() {
    let (server, client) = mock().await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/domains/example.com/rrsets/www/A/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client
        .rrsets("example.com")
        .delete(&www(), &RecordType::A)
        .await
        .expect("deletion succeeds");
}

#[tokio::test]
async fn a_mixed_bulk_patch_identifies_every_item_it_touches() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        // Every item carries `subname` and `type`; without them the API cannot tell which
        // RRset an update refers to.
        .and(body_json(serde_json::json!([
            {"subname": "www", "type": "A", "ttl": 600},
            {"subname": "old", "type": "TXT", "records": []},
        ])))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            rrset_json("example.com", "www", "A", 600, &["127.0.0.1"]),
            rrset_json("example.com", "old", "TXT", 3600, &[]),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let rrsets = client
        .rrsets("example.com")
        .patch_bulk(&[
            BulkPatch::new(www(), RecordType::A).ttl(600),
            BulkPatch::delete("old".parse().expect("valid subname"), RecordType::TXT),
        ])
        .await
        .expect("the bulk patch succeeds");
    assert_eq!(rrsets.len(), 2);
    assert_eq!(rrsets[0].ttl, 600);
    assert!(rrsets[1].records.is_empty());
}

#[tokio::test]
async fn a_bulk_replacement_sends_every_field_of_every_item() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!([
            {"subname": "www", "type": "A", "ttl": 3600, "records": ["127.0.0.1"]},
            {"subname": "", "type": "MX", "ttl": 600, "records": ["10 mx.example.com."]},
        ])))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            rrset_json("example.com", "www", "A", 3600, &["127.0.0.1"]),
            rrset_json("example.com", "", "MX", 600, &["10 mx.example.com."]),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let rrsets = client
        .rrsets("example.com")
        .replace_bulk(&[
            BulkPut::new(www(), RecordType::A, 3600, ["127.0.0.1"]),
            BulkPut::new(Subname::apex(), RecordType::MX, 600, ["10 mx.example.com."]),
        ])
        .await
        .expect("the bulk replacement succeeds");
    assert_eq!(rrsets.len(), 2);
}

#[tokio::test]
async fn a_bulk_deletion_patches_rather_than_puts() {
    let (server, client) = mock().await;
    // PUT would reject the same batch for lacking a `ttl` on records it is removing.
    Mock::given(method("PATCH"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!([
            {"subname": "a", "type": "A", "records": []},
            {"subname": "", "type": "TXT", "records": []},
        ])))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let rrsets = client
        .rrsets("example.com")
        .delete_bulk([
            ("a".parse().expect("valid subname"), RecordType::A),
            (Subname::apex(), RecordType::TXT),
        ])
        .await
        .expect("the bulk deletion succeeds");
    assert!(rrsets.is_empty());
}

#[tokio::test]
async fn a_ttl_outside_the_accepted_range_never_reaches_the_network() {
    let (server, client) = mock().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let rrsets = client.rrsets("example.com");
    for ttl in [0, MAX_TTL + 1] {
        let err = rrsets
            .create(&NewRrset::new(www(), RecordType::A, ttl, ["127.0.0.1"]))
            .await
            .expect_err("the TTL is out of range");
        assert!(err.is_validation(), "ttl {ttl}: {err:?}");
        assert_eq!(err.status(), None, "ttl {ttl}: no response was involved");

        let err = rrsets
            .patch(&www(), &RecordType::A, &RrsetPatch::new().ttl(ttl))
            .await
            .expect_err("the TTL is out of range");
        assert!(err.is_validation(), "ttl {ttl}: {err:?}");
    }
}

#[tokio::test]
async fn a_wildcard_label_survives_both_the_path_and_the_body() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/domains/example.com/rrsets/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(serde_json::json!({
            "subname": "*.wild",
            "type": "A",
            "ttl": 3600,
            "records": ["127.0.0.1"],
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(rrset_json(
            "example.com",
            "*.wild",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/*.wild/A/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "*.wild",
            "A",
            3600,
            &["127.0.0.1"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let wildcard: Subname = "*.wild".parse().expect("a leftmost wildcard is valid");
    let rrsets = client.rrsets("example.com");
    let created = rrsets
        .create(&NewRrset::new(
            wildcard.clone(),
            RecordType::A,
            3600,
            ["127.0.0.1"],
        ))
        .await
        .expect("creation succeeds");
    assert_eq!(created.subname, wildcard);

    let fetched = rrsets
        .get(&wildcard, &RecordType::A)
        .await
        .expect("the RRset exists");
    assert_eq!(fetched.subname.as_path(), "*.wild");
}

#[tokio::test]
async fn a_record_type_this_crate_does_not_name_still_round_trips() {
    let (server, client) = mock().await;
    // A type added upstream must not break a client that has not been rebuilt.
    Mock::given(method("GET"))
        .and(path("/api/v1/domains/example.com/rrsets/pay/WALLET/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(rrset_json(
            "example.com",
            "pay",
            "WALLET",
            3600,
            &["bc1qexample"],
        )))
        .expect(1)
        .mount(&server)
        .await;

    let unknown = RecordType::Other("WALLET".to_owned());
    let rrset = client
        .rrsets("example.com")
        .get(&"pay".parse().expect("valid subname"), &unknown)
        .await
        .expect("an unknown type deserializes");
    assert_eq!(rrset.record_type, unknown);
    assert_eq!(rrset.record_type.as_str(), "WALLET");
    assert_eq!(
        serde_json::to_value(&rrset.record_type).expect("serializes"),
        serde_json::json!("WALLET")
    );
}
