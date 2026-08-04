//! Account lifecycle: `/auth/`, `/captcha/` and the `/v/…/{code}/` confirmations.
//!
//! The flows that touch email are two-step: a request returns `202` with a
//! [`Detail`] message and sends a mail, and the link in that mail carries a code which is
//! then posted to the matching `/v/…/{code}/` endpoint, which answers `200`. Neither step
//! ever returns an account object, so none of these methods pretend to.

use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::Detail;
use crate::api::tokens::Token;
use crate::client::{Client, Secret};
use crate::error::Result;
use crate::ratelimit::{Scope, ScopeSet};

/// Account settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Account {
    /// The account's identifier.
    pub id: Uuid,
    /// The registered email address.
    pub email: String,
    /// When the account was registered.
    pub created: DateTime<Utc>,
    /// How many domains this account may create.
    #[serde(default)]
    pub limit_domains: Option<u32>,
    /// Whether the account opted in to development announcements.
    pub outreach_preference: bool,
    /// Domains this account can manage, including ones reachable through token scoping.
    #[serde(default)]
    pub domains_under_management: Option<u32>,
}

/// A captcha challenge.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[non_exhaustive]
pub struct Captcha {
    /// Identifies the challenge when submitting a solution.
    pub id: String,
    /// The challenge itself: a base64 PNG for an image captcha, or base64 audio.
    pub challenge: String,
    /// Which kind of challenge this is, when the API says.
    #[serde(default)]
    pub kind: Option<String>,
}

/// A solved captcha, to accompany a registration or password reset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptchaSolution {
    /// The [`Captcha::id`] being answered.
    pub id: String,
    /// The solution as read from the challenge.
    pub solution: String,
}

impl CaptchaSolution {
    /// Pairs a challenge id with its solution.
    pub fn new(id: impl Into<String>, solution: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            solution: solution.into(),
        }
    }
}

/// A registration request.
#[derive(Debug, Clone, Serialize)]
pub struct Registration {
    email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    captcha: Option<CaptchaSolution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outreach_preference: Option<bool>,
}

impl Registration {
    /// Registers `email`, leaving the password unset.
    ///
    /// An account with no password can only be reached by setting one through the
    /// password reset flow, which is a legitimate way to register without ever handling a
    /// password.
    pub fn new(email: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: None,
            captcha: None,
            domain: None,
            outreach_preference: None,
        }
    }

    /// Sets the initial password. Surrounding whitespace is stripped by the server.
    pub fn password(mut self, password: impl Into<Secret>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Attaches a solved captcha. Required unless one is supplied at activation instead.
    pub fn captcha(mut self, captcha: CaptchaSolution) -> Self {
        self.captcha = Some(captcha);
        self
    }

    /// Creates a domain along with the account.
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Opts in or out of development announcements. Defaults to opted in.
    pub fn outreach_preference(mut self, opted_in: bool) -> Self {
        self.outreach_preference = Some(opted_in);
        self
    }
}

/// Changes to account settings.
///
/// `outreach_preference` is the only field the API lets an account change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AccountUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    outreach_preference: Option<bool>,
}

impl AccountUpdate {
    /// An update that changes nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Opts in or out of development announcements.
    pub fn outreach_preference(mut self, opted_in: bool) -> Self {
        self.outreach_preference = Some(opted_in);
        self
    }
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    email: &'a str,
    password: &'a Secret,
}

#[derive(Serialize)]
struct PasswordResetRequest<'a> {
    email: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    captcha: Option<&'a CaptchaSolution>,
}

#[derive(Serialize)]
struct NewPassword<'a> {
    new_password: &'a Secret,
}

#[derive(Serialize)]
struct EmailChangeRequest<'a> {
    email: &'a str,
    password: &'a Secret,
    new_email: &'a str,
}

#[derive(Serialize)]
struct Credentials<'a> {
    email: &'a str,
    password: &'a Secret,
}

#[derive(Serialize)]
struct CaptchaOnly<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    captcha: Option<&'a CaptchaSolution>,
}

/// Account endpoints.
#[derive(Debug, Clone, Copy)]
pub struct AccountApi<'a> {
    client: &'a Client,
}

impl<'a> AccountApi<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Scope for actions that send email.
    fn active() -> ScopeSet {
        ScopeSet::new(Scope::AccountManagementActive)
    }

    /// Scope for actions with effects only inside the API.
    fn passive() -> ScopeSet {
        ScopeSet::new(Scope::AccountManagementPassive)
    }

    /// `POST /captcha/` — obtains a captcha challenge.
    ///
    /// Needs no authentication. A challenge expires after 24 hours, and is consumed by
    /// the request it accompanies.
    pub async fn captcha(&self) -> Result<Captcha> {
        let url = self.client.url(&["captcha"]);
        let req = self.client.request(Method::POST, url, Self::passive());
        self.client.send_json(req).await
    }

    /// `POST /auth/` — registers an account.
    ///
    /// Answers `202` with a message; the account is not usable until the emailed link has
    /// been posted to [`activate`](Self::activate). Nothing is sent if the address already
    /// has an account, and the response looks the same either way.
    pub async fn register(&self, registration: &Registration) -> Result<Detail> {
        let url = self.client.url(&["auth"]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(registration)?;
        self.client.send_json(req).await
    }

    /// `POST /v/activate-account/{code}/` — completes a registration.
    ///
    /// The captcha is needed only when [`register`](Self::register) went without one. The
    /// link expires after 12 hours.
    pub async fn activate(&self, code: &str, captcha: Option<&CaptchaSolution>) -> Result<Detail> {
        let url = self.client.url(&["v", "activate-account", code]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&CaptchaOnly { captcha })?;
        self.client.send_json(req).await
    }

    /// `POST /auth/login/` — exchanges credentials for a login token.
    ///
    /// The token expires 7 days after creation, or after an hour unused. Feed it to
    /// [`Client::with_token`] to get a client that uses it.
    pub async fn log_in(&self, email: &str, password: &Secret) -> Result<Token> {
        let url = self.client.url(&["auth", "login"]);
        let req = self
            .client
            .request(Method::POST, url, Self::passive())
            .json(&LoginRequest { email, password })?;
        self.client.send_json(req).await
    }

    /// `POST /auth/logout/` — deletes the token the request was made with.
    pub async fn log_out(&self) -> Result<()> {
        let url = self.client.url(&["auth", "logout"]);
        let req = self.client.request(Method::POST, url, Self::passive());
        self.client.send_empty(req).await
    }

    /// `GET /auth/account/` — reads account settings.
    pub async fn get(&self) -> Result<Account> {
        let url = self.client.url(&["auth", "account"]);
        let req = self.client.request(Method::GET, url, Self::passive());
        self.client.send_json(req).await
    }

    /// `PATCH /auth/account/` — changes account settings.
    pub async fn update(&self, update: &AccountUpdate) -> Result<Account> {
        let url = self.client.url(&["auth", "account"]);
        let req = self
            .client
            .request(Method::PATCH, url, Self::passive())
            .json(update)?;
        self.client.send_json(req).await
    }

    /// `PUT /auth/account/` — replaces account settings.
    pub async fn replace(&self, update: &AccountUpdate) -> Result<Account> {
        let url = self.client.url(&["auth", "account"]);
        let req = self
            .client
            .request(Method::PUT, url, Self::passive())
            .json(update)?;
        self.client.send_json(req).await
    }

    /// `POST /auth/account/reset-password/` — starts a password reset.
    ///
    /// Needs no authentication, which makes it the way to set a password on an account
    /// registered without one.
    pub async fn request_password_reset(
        &self,
        email: &str,
        captcha: Option<&CaptchaSolution>,
    ) -> Result<Detail> {
        let url = self.client.url(&["auth", "account", "reset-password"]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&PasswordResetRequest { email, captcha })?;
        self.client.send_json(req).await
    }

    /// `POST /v/reset-password/{code}/` — sets the new password.
    ///
    /// The link expires after 12 hours.
    pub async fn confirm_password_reset(
        &self,
        code: &str,
        new_password: &Secret,
    ) -> Result<Detail> {
        let url = self.client.url(&["v", "reset-password", code]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&NewPassword { new_password })?;
        self.client.send_json(req).await
    }

    /// `POST /auth/account/change-email/` — starts an email address change.
    ///
    /// Confirmation goes to the *new* address.
    pub async fn request_email_change(
        &self,
        email: &str,
        password: &Secret,
        new_email: &str,
    ) -> Result<Detail> {
        let url = self.client.url(&["auth", "account", "change-email"]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&EmailChangeRequest {
                email,
                password,
                new_email,
            })?;
        self.client.send_json(req).await
    }

    /// `POST /v/change-email/{code}/` — completes an email address change.
    pub async fn confirm_email_change(&self, code: &str) -> Result<Detail> {
        let url = self.client.url(&["v", "change-email", code]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&serde_json::Map::new())?;
        self.client.send_json(req).await
    }

    /// `POST /auth/account/delete/` — starts account deletion.
    ///
    /// Fails with `409` while the account still holds domains; delete those first.
    pub async fn request_deletion(&self, email: &str, password: &Secret) -> Result<Detail> {
        let url = self.client.url(&["auth", "account", "delete"]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&Credentials { email, password })?;
        self.client.send_json(req).await
    }

    /// `POST /v/delete-account/{code}/` — completes account deletion.
    pub async fn confirm_deletion(&self, code: &str) -> Result<Detail> {
        let url = self.client.url(&["v", "delete-account", code]);
        let req = self
            .client
            .request(Method::POST, url, Self::active())
            .json(&serde_json::Map::new())?;
        self.client.send_json(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).expect("serializes")
    }

    #[test]
    fn a_minimal_registration_sends_only_the_email() {
        assert_eq!(
            json(&Registration::new("you@example.com")),
            r#"{"email":"you@example.com"}"#
        );
    }

    #[test]
    fn registration_can_carry_a_domain_and_a_captcha() {
        let registration = Registration::new("you@example.com")
            .password("hunter2")
            .captcha(CaptchaSolution::new(
                "00010203-0405-0607-0809-0a0b0c0d0e0f",
                "12H45",
            ))
            .domain("example.org")
            .outreach_preference(false);
        let body = json(&registration);
        assert!(body.contains(r#""domain":"example.org""#), "{body}");
        assert!(body.contains(r#""solution":"12H45""#), "{body}");
        assert!(body.contains(r#""outreach_preference":false"#), "{body}");
        assert!(body.contains(r#""password":"hunter2""#), "{body}");
    }

    #[test]
    fn activation_without_a_captcha_sends_an_empty_object() {
        assert_eq!(json(&CaptchaOnly { captcha: None }), "{}");
    }

    #[test]
    fn deserializes_an_account() {
        let body = r#"{
            "created": "2019-10-16T18:09:17.715702Z",
            "domains_under_management": 3,
            "email": "you@example.com",
            "id": "9ab16e5c-805d-4ab1-9030-af3f5a541d47",
            "limit_domains": 15,
            "outreach_preference": true
        }"#;
        let account: Account = serde_json::from_str(body).expect("valid account");
        assert_eq!(account.limit_domains, Some(15));
        assert_eq!(account.domains_under_management, Some(3));
    }

    /// The 202 flows return a message, never a resource.
    #[test]
    fn deserializes_a_detail_body() {
        let body =
            r#"{"detail":"Please check your mailbox for further account deletion instructions."}"#;
        let detail: Detail = serde_json::from_str(body).expect("valid detail");
        assert!(detail.detail.starts_with("Please check"));
    }

    #[test]
    fn deserializes_a_captcha_with_and_without_a_kind() {
        let with_kind = r#"{"id":"abc","challenge":"iVBOR","kind":"image"}"#;
        let captcha: Captcha = serde_json::from_str(with_kind).expect("valid captcha");
        assert_eq!(captcha.kind.as_deref(), Some("image"));

        let without = r#"{"id":"abc","challenge":"iVBOR"}"#;
        let captcha: Captcha = serde_json::from_str(without).expect("valid captcha");
        assert_eq!(captcha.kind, None);
    }
}
