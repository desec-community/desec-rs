//! Mocked tests for `/auth/tokens/` and its RRset scoping policies.
#![allow(clippy::unwrap_used)]

mod common;

use common::*;

use desec::api::tokens::{NewTokenPolicy, TokenPolicyPatch, TokenUpdate};
use desec::{DjangoDuration, RecordType, Secret, Subname};
use serde_json::json;
use uuid::Uuid;
use wiremock::matchers::{body_json, header, method, path, query_param, query_param_is_missing};
use wiremock::{Mock, ResponseTemplate};

const TOKEN_ID: &str = "3a6b94b5-d20e-40bd-a7cc-521f5c79fab3";
const OTHER_TOKEN_ID: &str = "f7ab039b-07b8-493d-ac61-4ddcf903d4de";
const POLICY_ID: &str = "7aed3f71-bc81-4f7e-90ae-8f0df0d1c211";
const OTHER_POLICY_ID: &str = "1b4a6f26-6f8d-4a25-9f3a-2a0dcb3e7c11";

fn token_id() -> Uuid {
    TOKEN_ID.parse().unwrap()
}

fn policy_id() -> Uuid {
    POLICY_ID.parse().unwrap()
}

fn tokens_path() -> String {
    "/api/v1/auth/tokens/".to_owned()
}

fn token_path() -> String {
    format!("/api/v1/auth/tokens/{TOKEN_ID}/")
}

fn policies_path() -> String {
    format!("/api/v1/auth/tokens/{TOKEN_ID}/policies/rrsets/")
}

fn policy_path() -> String {
    format!("/api/v1/auth/tokens/{TOKEN_ID}/policies/rrsets/{POLICY_ID}/")
}

#[tokio::test]
async fn creating_a_token_discloses_the_secret_but_keeps_it_out_of_debug() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"name": "my token"})))
        .respond_with(ResponseTemplate::new(201).set_body_json(token_json(
            TOKEN_ID,
            "my token",
            Some(TOKEN),
        )))
        .expect(1)
        .mount(&server)
        .await;

    let token = client
        .tokens()
        .create(&TokenUpdate::new().name("my token"))
        .await
        .unwrap();

    assert_eq!(token.token.as_ref().map(Secret::expose), Some(TOKEN));
    // Tokens get logged for auditing, so the one disclosure must not become two.
    assert!(!format!("{token:?}").contains(TOKEN));
}

#[tokio::test]
async fn a_provisioning_token_gets_its_domain_permissions_at_creation() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "name": "provisioning",
            "perm_create_domain": true,
            "perm_delete_domain": true,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(token_json(
            TOKEN_ID,
            "provisioning",
            Some(TOKEN),
        )))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .create(
            &TokenUpdate::new()
                .name("provisioning")
                .perm_create_domain(true)
                .perm_delete_domain(true),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn token_lifetimes_go_on_the_wire_as_django_durations() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "max_age": "7 00:00:00",
            "max_unused_period": "01:00:00",
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(token_json(
            TOKEN_ID,
            "",
            Some(TOKEN),
        )))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .create(
            &TokenUpdate::new()
                .max_age(DjangoDuration::days(7))
                .max_unused_period(DjangoDuration::hours(1)),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn creating_a_token_can_restrict_subnets_and_enable_auto_policy() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "allowed_subnets": ["203.0.113.0/24", "2001:db8::/32"],
            "auto_policy": true,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(token_json(
            TOKEN_ID,
            "",
            Some(TOKEN),
        )))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .create(
            &TokenUpdate::new()
                .allowed_subnets(["203.0.113.0/24", "2001:db8::/32"])
                .auto_policy(true),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn creating_a_token_without_any_settings_posts_an_empty_object() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(201).set_body_json(token_json(
            TOKEN_ID,
            "",
            Some(TOKEN),
        )))
        .expect(1)
        .mount(&server)
        .await;

    client.tokens().create(&TokenUpdate::new()).await.unwrap();
}

#[tokio::test]
async fn listing_tokens_sends_an_empty_cursor_and_yields_no_secrets() {
    let (server, client) = mock().await;
    // Omitting `cursor` is what makes the API answer `400 Pagination required`.
    Mock::given(method("GET"))
        .and(path(tokens_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param("cursor", ""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            token_json(TOKEN_ID, "one", None),
            token_json(OTHER_TOKEN_ID, "two", None),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let page = client.tokens().list().send().await.unwrap();

    assert_eq!(page.items.len(), 2);
    assert!(page.items.iter().all(|token| token.token.is_none()));
    assert!(!page.has_next());
}

#[tokio::test]
async fn getting_a_token_addresses_it_by_lowercase_hyphenated_uuid() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "my token", None)),
        )
        .expect(1)
        .mount(&server)
        .await;

    // Parsed from the uppercase spelling, to pin that the path is not built from Debug.
    let id: Uuid = TOKEN_ID.to_uppercase().parse().unwrap();
    let token = client.tokens().get(id).await.unwrap();

    assert_eq!(token.id, token_id());
    assert_eq!(token.name, "my token");
}

#[tokio::test]
async fn try_get_maps_a_missing_token_onto_none() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": "Not found."})))
        .expect(1)
        .mount(&server)
        .await;

    assert!(client.tokens().try_get(token_id()).await.unwrap().is_none());
}

#[tokio::test]
async fn renaming_a_token_leaves_its_permissions_untouched() {
    let (server, client) = mock().await;
    // An omitted field means "leave alone", so a rename must not carry permissions along.
    Mock::given(method("PATCH"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"name": "x"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "x", None)))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .patch(token_id(), &TokenUpdate::new().name("x"))
        .await
        .unwrap();
}

#[tokio::test]
async fn clearing_a_token_lifetime_sends_an_explicit_null() {
    let (server, client) = mock().await;
    // Without the null a lifetime could be set but never removed.
    Mock::given(method("PATCH"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"max_age": null})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "", None)))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .patch(token_id(), &TokenUpdate::new().clear_max_age())
        .await
        .unwrap();
}

#[tokio::test]
async fn patching_nothing_sends_an_empty_object() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "", None)))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .patch(token_id(), &TokenUpdate::new())
        .await
        .unwrap();
}

#[tokio::test]
async fn revoking_domain_creation_sends_false_rather_than_omitting_it() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"perm_create_domain": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "", None)))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .patch(token_id(), &TokenUpdate::new().perm_create_domain(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn replacing_a_token_uses_put() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"name": "reset"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json(TOKEN_ID, "reset", None)))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .replace(token_id(), &TokenUpdate::new().name("reset"))
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_a_token_accepts_a_204() {
    let (server, client) = mock().await;
    Mock::given(method("DELETE"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client.tokens().delete(token_id()).await.unwrap();
}

#[tokio::test]
async fn patching_without_permission_surfaces_as_forbidden() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path(token_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "detail": "You do not have permission to perform this action.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .tokens()
        .patch(token_id(), &TokenUpdate::new().name("x"))
        .await
        .unwrap_err();

    assert!(err.is_forbidden(), "{err:?}");
    assert_eq!(
        err.api_error().unwrap().detail(),
        Some("You do not have permission to perform this action.")
    );
}

#[tokio::test]
async fn listing_policies_sends_no_cursor_because_the_endpoint_is_unpaginated() {
    let (server, client) = mock().await;
    // Upstream sets `pagination_class = None` here, so a cursor would be a stray parameter.
    Mock::given(method("GET"))
        .and(path(policies_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(query_param_is_missing("cursor"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            policy_json(POLICY_ID, None, None, None, true),
            policy_json(
                OTHER_POLICY_ID,
                Some("example.com"),
                Some("www"),
                Some("A"),
                false,
            ),
        ])))
        .expect(1)
        .mount(&server)
        .await;

    let policies = client.tokens().policies(token_id()).list().await.unwrap();

    assert_eq!(policies.len(), 2);
    assert!(policies[0].is_default());
    assert!(!policies[1].is_default());
}

#[tokio::test]
async fn the_default_policy_posts_all_three_selectors_as_null() {
    let (server, client) = mock().await;
    // The all-null policy *is* the default one; dropping a null would scope it by accident.
    Mock::given(method("POST"))
        .and(path(policies_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "domain": null,
            "subname": null,
            "type": null,
            "perm_write": true,
        })))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(policy_json(POLICY_ID, None, None, None, true)),
        )
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .create(&NewTokenPolicy::default_policy(true))
        .await
        .unwrap();

    assert!(policy.is_default());
}

#[tokio::test]
async fn a_domain_scoped_policy_keeps_its_wildcard_selectors_on_the_wire() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(policies_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "domain": "example.com",
            "subname": null,
            "type": "TXT",
            "perm_write": true,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            None,
            Some("TXT"),
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .create(&NewTokenPolicy::for_domain("example.com", true).record_type(RecordType::TXT))
        .await
        .unwrap();

    assert_eq!(policy.record_type, Some(RecordType::TXT));
}

#[tokio::test]
async fn an_apex_scoped_policy_sends_the_apex_as_an_empty_string() {
    let (server, client) = mock().await;
    // The apex is `@` in a path but `""` in a body, and this is a body.
    Mock::given(method("POST"))
        .and(path(policies_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "domain": "example.com",
            "subname": "",
            "type": null,
            "perm_write": false,
        })))
        .respond_with(ResponseTemplate::new(201).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            Some(""),
            None,
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .create(&NewTokenPolicy::for_domain("example.com", false).subname(Subname::apex()))
        .await
        .unwrap();

    assert_eq!(policy.subname.as_ref().map(Subname::as_payload), Some(""));
}

#[tokio::test]
async fn a_second_default_policy_is_rejected_under_non_field_errors() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path(policies_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "non_field_errors": ["Cannot create multiple default policies."],
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .tokens()
        .policies(token_id())
        .create(&NewTokenPolicy::default_policy(true))
        .await
        .unwrap_err();

    assert!(err.is_validation(), "{err:?}");
    assert_eq!(
        err.api_error().unwrap().non_field_errors(),
        vec!["Cannot create multiple default policies."]
    );
}

#[tokio::test]
async fn getting_a_policy_addresses_it_below_its_token() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            None,
            None,
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .get(policy_id())
        .await
        .unwrap();

    assert_eq!(policy.id, policy_id());
    assert_eq!(policy.domain.as_deref(), Some("example.com"));
}

#[tokio::test]
async fn try_get_maps_a_missing_policy_onto_none() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": "Not found."})))
        .expect(1)
        .mount(&server)
        .await;

    assert!(
        client
            .tokens()
            .policies(token_id())
            .try_get(policy_id())
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn revoking_write_permission_on_a_policy_sends_only_perm_write_false() {
    let (server, client) = mock().await;
    // Omitting the field preserves the old value, so a dropped `false` never revokes.
    Mock::given(method("PATCH"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"perm_write": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            None,
            None,
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .patch(policy_id(), &TokenPolicyPatch::new().perm_write(false))
        .await
        .unwrap();

    assert!(!policy.perm_write);
}

#[tokio::test]
async fn rescoping_a_policy_does_not_resend_its_write_permission() {
    let (server, client) = mock().await;
    // Sending all four fields would turn this PATCH into a PUT and silently revoke write.
    Mock::given(method("PATCH"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"domain": "x"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_json(
            POLICY_ID,
            Some("x"),
            None,
            None,
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .patch(policy_id(), &TokenPolicyPatch::new().domain("x"))
        .await
        .unwrap();

    assert!(policy.perm_write);
}

#[tokio::test]
async fn widening_a_policy_to_any_domain_sends_a_null_domain() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"domain": null})))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(policy_json(POLICY_ID, None, None, None, true)),
        )
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .policies(token_id())
        .patch(policy_id(), &TokenPolicyPatch::new().any_domain())
        .await
        .unwrap();
}

#[tokio::test]
async fn replacing_a_policy_uses_put() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "domain": "example.com",
            "subname": null,
            "type": null,
            "perm_write": false,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            None,
            None,
            false,
        )))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .policies(token_id())
        .replace(
            policy_id(),
            &NewTokenPolicy::for_domain("example.com", false),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn deleting_a_policy_accepts_a_204() {
    let (server, client) = mock().await;
    Mock::given(method("DELETE"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    client
        .tokens()
        .policies(token_id())
        .delete(policy_id())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_policy_scoped_to_a_subname_with_any_type_round_trips() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(policy_json(
            POLICY_ID,
            Some("example.com"),
            Some("_acme-challenge"),
            None,
            true,
        )))
        .expect(1)
        .mount(&server)
        .await;

    let policy = client
        .tokens()
        .policies(token_id())
        .get(policy_id())
        .await
        .unwrap();

    assert_eq!(
        policy.subname.as_ref().map(Subname::as_payload),
        Some("_acme-challenge")
    );
    assert_eq!(policy.record_type, None);
    assert!(!policy.is_default());
}
