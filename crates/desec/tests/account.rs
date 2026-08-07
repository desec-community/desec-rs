//! Mocked tests for the account lifecycle: `/auth/`, `/captcha/` and the `/v/…/{code}/` steps.
#![allow(clippy::expect_used)]

mod common;

use common::*;

use desec::api::account::{AccountUpdate, CaptchaSolution, Registration};
use desec::{Client, DjangoDuration, Secret};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ACCOUNT_ID: &str = "9ab16e5c-805d-4ab1-9030-af3f5a541d47";
const LOGIN_TOKEN_ID: &str = "f7ab039b-07b8-493d-ac61-4ddcf903d4de";
const CAPTCHA_ID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const CODE: &str = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA6MWlyRXlLOnZBcnJHR0NB";
const PASSWORD: &str = "hunter2";

/// A mock server and a client with no credentials, for the endpoints that take none.
async fn anonymous_mock() -> (MockServer, Client) {
    let server = MockServer::start().await;
    let client = anonymous_client_for(&server);
    (server, client)
}

/// wiremock has no "header is absent" matcher, so this reads the recorded requests instead.
async fn assert_no_credentials_were_sent(server: &MockServer) {
    let requests = server.received_requests().await.expect("recorded requests");
    assert!(!requests.is_empty(), "no request reached the mock server");
    for request in &requests {
        assert!(
            !request.headers.contains_key("authorization"),
            "{} {} sent credentials to an unauthenticated endpoint",
            request.method,
            request.url.path()
        );
    }
}

fn captcha_json(kind: Option<&str>) -> serde_json::Value {
    let mut value = json!({
        "id": CAPTCHA_ID,
        "challenge": "iVBORw0KGgoAAAANSUhEUgAAAJgAAAA",
    });
    if let Some(kind) = kind {
        value["kind"] = json!(kind);
    }
    value
}

fn account_json(domains_under_management: Option<u32>) -> serde_json::Value {
    let mut value = json!({
        "created": "2019-10-16T18:09:17.715702Z",
        "email": "you@example.com",
        "id": ACCOUNT_ID,
        "limit_domains": 15,
        "outreach_preference": true,
    });
    if let Some(count) = domains_under_management {
        value["domains_under_management"] = json!(count);
    }
    value
}

/// A login token as `POST /auth/login/` renders one: it has an `mfa` flag and lifetimes.
fn login_token_json() -> serde_json::Value {
    let mut value = token_json(LOGIN_TOKEN_ID, "", Some(TOKEN));
    value["mfa"] = json!(false);
    value["max_age"] = json!("7 00:00:00");
    value["max_unused_period"] = json!("01:00:00");
    value
}

#[tokio::test]
async fn a_captcha_parses_from_the_201_the_api_actually_returns() {
    let (server, client) = anonymous_mock().await;
    // `/captcha/` is a plain DRF CreateAPIView, so it answers 201 despite the prose docs.
    Mock::given(method("POST"))
        .and(path("/api/v1/captcha/"))
        .respond_with(ResponseTemplate::new(201).set_body_json(captcha_json(Some("image"))))
        .expect(1)
        .mount(&server)
        .await;

    let captcha = client.account().captcha().await.expect("captcha");

    assert_eq!(captcha.id, CAPTCHA_ID);
    assert_eq!(captcha.kind.as_deref(), Some("image"));
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn a_captcha_parses_from_a_200_as_well() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/captcha/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(captcha_json(Some("audio"))))
        .expect(1)
        .mount(&server)
        .await;

    let captcha = client.account().captcha().await.expect("captcha");

    assert_eq!(captcha.kind.as_deref(), Some("audio"));
}

#[tokio::test]
async fn a_captcha_without_a_kind_still_parses() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/captcha/"))
        .respond_with(ResponseTemplate::new(201).set_body_json(captcha_json(None)))
        .expect(1)
        .mount(&server)
        .await;

    let captcha = client.account().captcha().await.expect("captcha");

    assert_eq!(captcha.kind, None);
    assert!(!captcha.challenge.is_empty());
}

#[tokio::test]
async fn registering_posts_only_the_email_and_gets_a_detail_back() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/"))
        .and(body_json(json!({"email": "you@example.com"})))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Welcome! Please check your mailbox.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let detail = client
        .account()
        .register(&Registration::new("you@example.com"))
        .await
        .expect("registers");

    assert_eq!(detail.detail, "Welcome! Please check your mailbox.");
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn registering_can_carry_a_password_captcha_domain_and_outreach_preference() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/"))
        .and(body_json(json!({
            "email": "you@example.com",
            "password": PASSWORD,
            "captcha": {"id": CAPTCHA_ID, "solution": "12H45"},
            "domain": "example.org",
            "outreach_preference": false,
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Welcome! Please check your mailbox.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .register(
            &Registration::new("you@example.com")
                .password(PASSWORD)
                .captcha(CaptchaSolution::new(CAPTCHA_ID, "12H45"))
                .domain("example.org")
                .outreach_preference(false),
        )
        .await
        .expect("registers");
}

#[tokio::test]
async fn activating_with_a_captcha_posts_it_nested_under_captcha() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/v/activate-account/{CODE}/")))
        .and(body_json(json!({
            "captcha": {"id": CAPTCHA_ID, "solution": "12H45"},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "Success! Your account has been activated.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let solution = CaptchaSolution::new(CAPTCHA_ID, "12H45");
    let detail = client
        .account()
        .activate(CODE, Some(&solution))
        .await
        .expect("activates");

    assert!(detail.detail.starts_with("Success!"));
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn activating_without_a_captcha_posts_an_empty_object() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/v/activate-account/{CODE}/")))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "Success! Your account has been activated.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .activate(CODE, None)
        .await
        .expect("activates");
}

#[tokio::test]
async fn logging_in_returns_a_login_token_with_its_secret_and_lifetimes() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login/"))
        .and(body_json(json!({
            "email": "you@example.com",
            "password": PASSWORD,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(login_token_json()))
        .expect(1)
        .mount(&server)
        .await;

    let token = client
        .account()
        .log_in("you@example.com", &Secret::new(PASSWORD))
        .await
        .expect("logs in");

    // A null `mfa` would mean an API token; a login token reports the flag.
    assert_eq!(token.mfa, Some(false));
    assert_eq!(token.max_age, Some(DjangoDuration::days(7)));
    assert_eq!(token.max_unused_period, Some(DjangoDuration::hours(1)));
    assert_eq!(token.token.as_ref().map(Secret::expose), Some(TOKEN));
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn logging_in_with_wrong_credentials_surfaces_as_forbidden() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/login/"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "detail": "No active account found with the given credentials",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .account()
        .log_in("you@example.com", &Secret::new("wrong"))
        .await
        .expect_err("the credentials are wrong");

    assert!(err.is_forbidden(), "{err:?}");
}

#[tokio::test]
async fn logging_out_sends_the_token_it_is_revoking() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/logout/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    client.account().log_out().await.expect("logs out");
}

#[tokio::test]
async fn reading_an_account_parses_both_limits() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/account/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(account_json(Some(3))))
        .expect(1)
        .mount(&server)
        .await;

    let account = client.account().get().await.expect("account");

    assert_eq!(account.email, "you@example.com");
    assert_eq!(account.limit_domains, Some(15));
    assert_eq!(account.domains_under_management, Some(3));
    assert!(account.outreach_preference);
}

#[tokio::test]
async fn an_account_without_domains_under_management_leaves_it_none() {
    let (server, client) = mock().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/auth/account/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(account_json(None)))
        .expect(1)
        .mount(&server)
        .await;

    let account = client.account().get().await.expect("account");

    assert_eq!(account.domains_under_management, None);
}

#[tokio::test]
async fn changing_the_outreach_preference_patches_only_that_field() {
    let (server, client) = mock().await;
    Mock::given(method("PATCH"))
        .and(path("/api/v1/auth/account/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"outreach_preference": false})))
        .respond_with(ResponseTemplate::new(200).set_body_json(account_json(Some(0))))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .update(&AccountUpdate::new().outreach_preference(false))
        .await
        .expect("updates");
}

#[tokio::test]
async fn replacing_account_settings_uses_put() {
    let (server, client) = mock().await;
    Mock::given(method("PUT"))
        .and(path("/api/v1/auth/account/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({"outreach_preference": true})))
        .respond_with(ResponseTemplate::new(200).set_body_json(account_json(Some(0))))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .replace(&AccountUpdate::new().outreach_preference(true))
        .await
        .expect("replaces");
}

#[tokio::test]
async fn requesting_a_password_reset_with_a_captcha_is_accepted() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/account/reset-password/"))
        .and(body_json(json!({
            "email": "you@example.com",
            "captcha": {"id": CAPTCHA_ID, "solution": "12H45"},
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Please check your mailbox for further password reset instructions.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let solution = CaptchaSolution::new(CAPTCHA_ID, "12H45");
    let detail = client
        .account()
        .request_password_reset("you@example.com", Some(&solution))
        .await
        .expect("requests reset");

    assert!(detail.detail.starts_with("Please check"));
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn requesting_a_password_reset_without_a_captcha_omits_the_key() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/account/reset-password/"))
        .and(body_json(json!({"email": "you@example.com"})))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Please check your mailbox for further password reset instructions.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .request_password_reset("you@example.com", None)
        .await
        .expect("requests reset");
}

#[tokio::test]
async fn confirming_a_password_reset_posts_under_the_v_prefix() {
    let (server, client) = anonymous_mock().await;
    // The confirmation lives at `/v/reset-password/{code}/`, not under `/auth/account/`,
    // and it answers 200 rather than the 202 of the request that produced the code.
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/v/reset-password/{CODE}/")))
        .and(body_json(json!({"new_password": PASSWORD})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "Success! Your password has been changed.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let detail = client
        .account()
        .confirm_password_reset(CODE, &Secret::new(PASSWORD))
        .await
        .expect("confirms reset");

    assert!(detail.detail.starts_with("Success!"));
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn requesting_an_email_change_yields_a_detail_not_an_account() {
    let (server, client) = mock().await;
    // The 202 body is a message; parsing it as an account can only ever fail.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/account/change-email/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "email": "you@example.com",
            "password": PASSWORD,
            "new_email": "new@example.com",
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Please check your mailbox to confirm email address change.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let detail = client
        .account()
        .request_email_change("you@example.com", &Secret::new(PASSWORD), "new@example.com")
        .await
        .expect("requests email change");

    assert!(detail.detail.contains("confirm email address change"));
}

#[tokio::test]
async fn confirming_an_email_change_posts_an_empty_object() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/v/change-email/{CODE}/")))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "Success! Your email address has been changed to new@example.com.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .confirm_email_change(CODE)
        .await
        .expect("confirms email change");
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn requesting_deletion_yields_a_detail() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/account/delete/"))
        .and(header("authorization", auth_header().as_str()))
        .and(body_json(json!({
            "email": "you@example.com",
            "password": PASSWORD,
        })))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({
            "detail": "Please check your mailbox for further account deletion instructions.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let detail = client
        .account()
        .request_deletion("you@example.com", &Secret::new(PASSWORD))
        .await
        .expect("requests deletion");

    assert!(detail.detail.contains("account deletion"));
}

#[tokio::test]
async fn requesting_deletion_with_domains_left_surfaces_as_a_conflict() {
    let (server, client) = mock().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/account/delete/"))
        .and(header("authorization", auth_header().as_str()))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "detail": "To delete your user account, first delete all of your domains.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    let err = client
        .account()
        .request_deletion("you@example.com", &Secret::new(PASSWORD))
        .await
        .expect_err("domains are left");

    assert_eq!(err.status().expect("status").as_u16(), 409);
    assert!(!err.is_validation(), "{err:?}");
}

#[tokio::test]
async fn confirming_deletion_posts_an_empty_object() {
    let (server, client) = anonymous_mock().await;
    Mock::given(method("POST"))
        .and(path(format!("/api/v1/v/delete-account/{CODE}/")))
        .and(body_json(json!({})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "All your data has been deleted. Bye bye, see you soon! <3",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .confirm_deletion(CODE)
        .await
        .expect("confirms deletion");
    assert_no_credentials_were_sent(&server).await;
}

#[tokio::test]
async fn a_confirmation_code_with_unsafe_characters_is_percent_encoded() {
    let (server, client) = anonymous_mock().await;
    // An unescaped `/` would silently address a different endpoint.
    Mock::given(method("POST"))
        .and(path("/api/v1/v/activate-account/a%20b%2Fc%25d%3Fe/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "detail": "Success! Your account has been activated.",
        })))
        .expect(1)
        .mount(&server)
        .await;

    client
        .account()
        .activate("a b/c%d?e", None)
        .await
        .expect("activates");
}
