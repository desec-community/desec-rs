//! The HTTP client: construction, authentication, retries and request execution.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tracing::Instrument;
use url::Url;

use crate::error::{ApiError, Error, InvalidValue, Result, truncate};
use crate::ratelimit::{Limiter, RateLimits, ScopeSet};

/// The public deSEC API.
pub const DEFAULT_BASE_URL: &str = "https://desec.io/api/v1";

/// `User-Agent` sent unless the builder overrides it.
pub const DEFAULT_USER_AGENT: &str = concat!("desec-rs/", env!("CARGO_PKG_VERSION"));

/// Ceiling applied to a `Retry-After` header.
///
/// No real throttle asks for longer than a day, and the value is used in `Instant`
/// arithmetic that panics on overflow, so an absurd header is clamped rather than
/// trusted.
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(86_400);

/// A credential that must not appear in logs.
///
/// `Debug` and `Display` both render a placeholder, which is what stops a token from
/// riding along in a `{:?}` of a [`Token`](crate::api::tokens::Token) or an error. Reach
/// for [`expose`](Secret::expose) at the point of use, so every place a secret escapes is
/// greppable.
///
/// `Serialize` is *not* redacted — request bodies for login and registration need the real
/// value — so do not put a `Secret` in a structure that gets serialized to a log sink.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// Wraps a secret value.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// The underlying value.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl<T: Into<String>> From<T> for Secret {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// How a client authenticates.
#[derive(Debug, Clone, Default)]
pub(crate) enum Auth {
    /// Unauthenticated, which only the registration and captcha endpoints allow.
    #[default]
    None,
    /// `Authorization: Token <secret>`, the scheme for the whole REST API.
    Token(Secret),
    /// HTTP Basic, which only the dynDNS update endpoint accepts.
    Basic { username: String, password: Secret },
}

impl Auth {
    fn header(&self) -> Option<Result<HeaderValue, InvalidValue>> {
        let value = match self {
            Self::None => return None,
            Self::Token(secret) => format!("Token {}", secret.expose()),
            Self::Basic { username, password } => {
                format!(
                    "Basic {}",
                    base64_standard(format!("{username}:{}", password.expose()).as_bytes())
                )
            }
        };
        Some(HeaderValue::from_str(&value).map_err(|_| {
            // A token holding a control character would otherwise fail deep inside
            // reqwest with no indication of which value was at fault.
            InvalidValue::new(
                "credential",
                "contains characters that cannot go in an HTTP header",
                "<redacted>",
            )
        }))
    }
}

/// Whether a request may be sent again after an unknown outcome.
///
/// This gates retries of `5xx` responses and mid-flight transport failures, where the
/// server may have processed the request before the failure. It deliberately does not
/// gate `429` retries: a throttled request was rejected before processing, so replaying
/// any method is safe.
///
/// `PATCH` is excluded because the API allows it to create RRsets, so it is not
/// idempotent in general even though most uses of it are.
fn is_replayable(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
    )
}

/// Minimal base64, so HTTP Basic for dynDNS does not need a dependency.
fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let bits = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (bits >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(ALPHABET[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Retry behaviour for throttled and transiently failed requests.
#[derive(Debug, Clone)]
pub(crate) struct RetryConfig {
    /// Retries after the first attempt. Zero disables retrying.
    pub(crate) max_retries: u32,
    /// Longest single sleep the client will accept, whether from `Retry-After` or
    /// backoff. A longer wait fails instead.
    pub(crate) max_delay: Duration,
    /// First backoff step for server errors; doubles per attempt.
    pub(crate) initial_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            max_delay: Duration::from_secs(60),
            initial_backoff: Duration::from_millis(500),
        }
    }
}

#[derive(Debug)]
struct Inner {
    http: reqwest::Client,
    base: Url,
    auth: Auth,
    /// Shared so that a client derived by [`Client::with_token`] paces itself against the
    /// same buckets: the account and the source address are what the server throttles, not
    /// the individual credential.
    limiter: Arc<Limiter>,
    retry: RetryConfig,
}

/// An asynchronous deSEC API client.
///
/// Cheap to clone: clones share one connection pool and one rate-limiter state, which is
/// what makes the client-side limits meaningful across concurrent tasks.
///
/// ```no_run
/// # async fn run() -> Result<(), desec::Error> {
/// let client = desec::Client::builder()
///     .token("i-T3b1h_OI-H9ab8tRS98stGtURe")
///     .build()?;
///
/// let domains = client.domains().list().all().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

impl Client {
    /// Starts building a client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// A client authenticated with an API token, with every default in place.
    pub fn new(token: impl Into<Secret>) -> Result<Self> {
        Self::builder().token(token).build()
    }

    /// The base URL requests are built against.
    pub fn base_url(&self) -> &Url {
        &self.inner.base
    }

    /// A client identical to this one but authenticating with a different token.
    ///
    /// Shares the connection pool and the rate-limiter state, so switching from an
    /// unauthenticated client to a login token does not reset the buckets:
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), desec::Error> {
    /// let anonymous = desec::Client::builder().build()?;
    /// let login = anonymous
    ///     .account()
    ///     .log_in("you@example.com", &desec::Secret::new("hunter2"))
    ///     .await?;
    /// let secret = login.token.expect("a login response carries the secret");
    /// let client = anonymous.with_token(secret);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_token(&self, token: impl Into<Secret>) -> Self {
        Self {
            inner: Arc::new(Inner {
                http: self.inner.http.clone(),
                base: self.inner.base.clone(),
                auth: Auth::Token(token.into()),
                limiter: Arc::clone(&self.inner.limiter),
                retry: self.inner.retry.clone(),
            }),
        }
    }

    /// Builds a request URL by appending percent-encoded path segments to the base,
    /// always with the trailing slash the API requires.
    pub(crate) fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.inner.base.clone();
        {
            // The builder rejects any base URL that cannot be a base, so this holds.
            #[expect(clippy::expect_used)]
            let mut path = url
                .path_segments_mut()
                .expect("base URL was validated as a base");
            for segment in segments {
                path.push(segment);
            }
            path.push("");
        }
        url
    }

    pub(crate) fn request(&self, method: Method, url: Url, scopes: ScopeSet) -> Req {
        Req {
            method,
            url,
            body: None,
            scopes,
        }
    }

    /// Sends a request, applying rate limits and retries, and maps an error status onto
    /// [`Error::Api`].
    pub(crate) async fn send(&self, req: Req) -> Result<Res> {
        let res = self.execute(req).await?;
        if res.status.is_client_error() || res.status.is_server_error() {
            let body = ApiError::parse(&res.text_lossy());
            return Err(Error::Api {
                status: res.status,
                method: res.method,
                path: res.path,
                detail: body.to_string(),
                body,
            });
        }
        Ok(res)
    }

    /// Sends a request and decodes a JSON body.
    pub(crate) async fn send_json<T: DeserializeOwned>(&self, req: Req) -> Result<T> {
        let res = self.send(req).await?;
        res.json()
    }

    /// Sends a request and decodes a JSON body, mapping `404` onto `None`.
    pub(crate) async fn send_json_opt<T: DeserializeOwned>(&self, req: Req) -> Result<Option<T>> {
        match self.send(req).await {
            Ok(res) => res.json().map(Some),
            Err(err) if err.is_not_found() => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Sends a request and discards the body.
    pub(crate) async fn send_empty(&self, req: Req) -> Result<()> {
        self.send(req).await.map(drop)
    }

    /// Sends a request and returns the body as text, for the zonefile endpoint.
    pub(crate) async fn send_text(&self, req: Req) -> Result<String> {
        Ok(self.send(req).await?.text_lossy())
    }

    /// One request, including rate limiting and retries. Status is not interpreted here.
    async fn execute(&self, req: Req) -> Result<Res> {
        let Req {
            method,
            url,
            body,
            scopes,
        } = req;
        let path = url.path().to_owned();

        let span = tracing::debug_span!(
            "desec.request",
            http.method = %method,
            url.path = %path,
        );

        async move {
            // Built before the first slot is claimed: a credential that cannot go in a
            // header fails locally, and there is no reason for that to cost quota.
            let auth = self.inner.auth.header().transpose()?;

            let mut attempt = 0u32;
            loop {
                attempt += 1;
                self.inner.limiter.acquire(&scopes).await?;

                let mut builder = self.inner.http.request(method.clone(), url.clone());
                if let Some(body) = &body {
                    builder = builder
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body.clone());
                }
                if let Some(auth) = &auth {
                    builder = builder.header(header::AUTHORIZATION, auth.clone());
                }

                let outcome = match builder.send().await {
                    Ok(response) => {
                        let status = response.status();
                        let headers = response.headers().clone();
                        match response.bytes().await {
                            Ok(bytes) => Ok(Res {
                                status,
                                headers,
                                body: bytes.to_vec(),
                                method: method.clone(),
                                path: path.clone(),
                                url: url.clone(),
                            }),
                            Err(err) => Err(err),
                        }
                    }
                    Err(err) => Err(err),
                };

                let res = match outcome {
                    Ok(res) => res,
                    Err(err) => {
                        // A connect or timeout failure may still have been processed by
                        // the server, so replaying it is only safe for an idempotent
                        // method. A malformed URL or a decode failure is never worth a
                        // second attempt.
                        let transient = err.is_timeout() || err.is_connect() || err.is_request();
                        let retryable = transient && is_replayable(&method);
                        // Scrubbed before logging, because the reqwest error's own
                        // rendering would otherwise carry the query string.
                        let err = Error::transport(err);
                        if retryable && attempt <= self.inner.retry.max_retries {
                            let delay = self.backoff(attempt);
                            tracing::warn!(
                                attempt,
                                delay_ms = delay.as_millis(),
                                error = %err,
                                "request failed, retrying"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(err);
                    }
                };

                tracing::debug!(
                    attempt,
                    http.status = res.status.as_u16(),
                    body_bytes = res.body.len(),
                    "response"
                );

                if res.status == StatusCode::TOO_MANY_REQUESTS {
                    let retry_after = res.retry_after();
                    self.inner.limiter.record_throttled(&scopes, retry_after);

                    let delay = retry_after.unwrap_or_else(|| self.backoff(attempt));
                    if attempt > self.inner.retry.max_retries || delay > self.inner.retry.max_delay
                    {
                        tracing::warn!(
                            attempt,
                            retry_after_s = retry_after.map(|d| d.as_secs()),
                            "giving up on a throttled request"
                        );
                        return Err(Error::RateLimited {
                            attempts: attempt,
                            retry_after,
                            body: ApiError::parse(&res.text_lossy()),
                        });
                    }
                    tracing::info!(
                        attempt,
                        delay_ms = delay.as_millis(),
                        "throttled by the server, waiting"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }

                // 5xx is worth a retry, but only where replaying is safe: the server may
                // have processed the request before failing, and re-POSTing would mint a
                // second token or send a second confirmation email. 4xx other than 429
                // will not change on its own.
                if res.status.is_server_error()
                    && is_replayable(&method)
                    && attempt <= self.inner.retry.max_retries
                {
                    let delay = self.backoff(attempt);
                    tracing::warn!(
                        attempt,
                        http.status = res.status.as_u16(),
                        delay_ms = delay.as_millis(),
                        "server error, retrying"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }

                return Ok(res);
            }
        }
        .instrument(span)
        .await
    }

    /// Exponential backoff, capped at the configured ceiling.
    fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1u32 << attempt.min(16).saturating_sub(1);
        self.inner
            .retry
            .initial_backoff
            .saturating_mul(factor)
            .min(self.inner.retry.max_delay)
    }
}

/// A request under construction.
pub(crate) struct Req {
    method: Method,
    url: Url,
    body: Option<Vec<u8>>,
    scopes: ScopeSet,
}

impl Req {
    /// Appends a query parameter, percent-encoding the value.
    pub(crate) fn query(mut self, key: &str, value: &str) -> Self {
        self.url.query_pairs_mut().append_pair(key, value);
        self
    }

    /// Serializes `body` as the JSON request body.
    pub(crate) fn json<T: Serialize + ?Sized>(mut self, body: &T) -> Result<Self> {
        self.body = Some(serde_json::to_vec(body).map_err(Error::Encode)?);
        Ok(self)
    }

    pub(crate) fn url_mut(&mut self) -> &mut Url {
        &mut self.url
    }
}

/// A response whose body has been read into memory.
pub(crate) struct Res {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Vec<u8>,
    pub(crate) method: Method,
    pub(crate) path: String,
    /// The URL that was requested, so `Link` headers can be resolved against it.
    pub(crate) url: Url,
}

impl Res {
    pub(crate) fn json<T: DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|source| Error::Decode {
            expected: std::any::type_name::<T>(),
            body: truncate(&self.text_lossy(), 2048),
            source,
        })
    }

    pub(crate) fn text_lossy(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub(crate) fn header(&self, name: header::HeaderName) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    /// `Retry-After` as a duration, accepting both forms the HTTP spec allows.
    fn retry_after(&self) -> Option<Duration> {
        let raw = self.header(header::RETRY_AFTER)?;
        parse_retry_after(raw, chrono::Utc::now())
    }
}

/// `Retry-After` as a duration, with the date form resolved against `now`.
///
/// Clamped to [`MAX_RETRY_AFTER`]. The header is attacker- or proxy-controlled and
/// otherwise unbounded, and the value reaches `Instant` arithmetic, which panics on
/// overflow. A deadline already in the past yields `None`, leaving the caller on its own
/// backoff.
///
/// `now` is a parameter rather than a call to the wall clock so the date form can be
/// pinned in tests.
fn parse_retry_after(raw: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let raw = raw.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER));
    }
    // An HTTP-date, which deSEC does not currently send but the spec permits.
    let deadline = chrono::DateTime::parse_from_rfc2822(raw).ok()?;
    let delta = deadline.signed_duration_since(now);
    Some(delta.to_std().ok()?.min(MAX_RETRY_AFTER))
}

/// Builds a [`Client`].
#[derive(Debug, Default)]
pub struct ClientBuilder {
    base: Option<String>,
    auth: Auth,
    user_agent: Option<String>,
    timeout: Option<Duration>,
    rate_limits: Option<RateLimits>,
    max_rate_limit_wait: Option<Duration>,
    retry: RetryConfig,
    http: Option<reqwest::Client>,
}

impl ClientBuilder {
    /// Authenticates with an API token, or a login token from
    /// [`log_in`](crate::api::AccountApi::log_in).
    pub fn token(mut self, token: impl Into<Secret>) -> Self {
        self.auth = Auth::Token(token.into());
        self
    }

    /// Authenticates with HTTP Basic.
    ///
    /// Only the dynDNS update endpoint accepts this; the REST API needs
    /// [`token`](Self::token).
    pub fn basic_auth(mut self, username: impl Into<String>, password: impl Into<Secret>) -> Self {
        self.auth = Auth::Basic {
            username: username.into(),
            password: password.into(),
        };
        self
    }

    /// Overrides the API root. Defaults to [`DEFAULT_BASE_URL`].
    ///
    /// Point this at a mock server in tests, or at a self-hosted desec-stack.
    pub fn base_url(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// Overrides the `User-Agent`.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Total timeout per attempt.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Replaces the client-side rate limits.
    ///
    /// Defaults to [`RateLimits::desec_defaults`]. Pass [`RateLimits::unlimited`] to send
    /// requests as fast as the caller asks and deal with `429`s reactively.
    pub fn rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate_limits = Some(limits);
        self
    }

    /// Longest the client-side limiter may sleep before giving up with
    /// [`Error::RateLimitWouldBlock`].
    ///
    /// Defaults to 60 seconds, which admits the per-second and per-minute buckets but
    /// fails fast when an hourly or daily bucket is exhausted, rather than parking a task
    /// for hours.
    pub fn max_rate_limit_wait(mut self, max_wait: Duration) -> Self {
        self.max_rate_limit_wait = Some(max_wait);
        self
    }

    /// Retries after the first attempt, for `429`s, `5xx`s and connection failures.
    /// Defaults to 3; zero disables retrying.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.retry.max_retries = retries;
        self
    }

    /// Longest single retry sleep to accept. Defaults to 60 seconds.
    ///
    /// A `Retry-After` longer than this fails with [`Error::RateLimited`] instead of
    /// blocking.
    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.retry.max_delay = delay;
        self
    }

    /// Supplies a preconfigured [`reqwest::Client`], for proxy or TLS settings this
    /// builder does not expose. Overrides [`timeout`](Self::timeout) and
    /// [`user_agent`](Self::user_agent).
    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    /// Finishes the client.
    pub fn build(self) -> Result<Client> {
        let raw = self.base.as_deref().unwrap_or(DEFAULT_BASE_URL);
        let mut base = Url::parse(raw)?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(InvalidValue::new("base_url", "must be http or https", raw).into());
        }
        {
            // Normalize away a trailing slash so appending segments cannot produce `//`.
            let mut segments = base
                .path_segments_mut()
                .map_err(|()| InvalidValue::new("base_url", "cannot be a base URL", raw))?;
            segments.pop_if_empty();
        }
        base.set_query(None);
        base.set_fragment(None);

        let http = match self.http {
            Some(http) => http,
            None => {
                let mut headers = HeaderMap::new();
                headers.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
                let mut builder = reqwest::Client::builder()
                    .user_agent(self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT))
                    .default_headers(headers);
                if let Some(timeout) = self.timeout {
                    builder = builder.timeout(timeout);
                }
                builder.build().map_err(Error::transport)?
            }
        };

        let limits = self.rate_limits.unwrap_or_default();
        let max_wait = self
            .max_rate_limit_wait
            .unwrap_or_else(|| Duration::from_secs(60));

        Ok(Client {
            inner: Arc::new(Inner {
                http,
                base,
                auth: self.auth,
                limiter: Arc::new(Limiter::new(limits, max_wait)),
                retry: self.retry,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn client() -> Client {
        Client::builder()
            .base_url("https://desec.example/api/v1")
            .token("secret")
            .build()
            .expect("valid configuration")
    }

    #[test]
    fn secrets_do_not_leak_through_debug_or_display() {
        let secret = Secret::new("i-T3b1h_OI-H9ab8tRS98stGtURe");
        assert_eq!(format!("{secret:?}"), "Secret(<redacted>)");
        assert_eq!(secret.to_string(), "<redacted>");
        assert!(!format!("{secret:?} {secret}").contains("T3b1h"));
    }

    #[test]
    fn client_debug_does_not_leak_the_token() {
        let rendered = format!("{:?}", client());
        assert!(!rendered.contains("secret"), "{rendered}");
    }

    #[test]
    fn urls_get_a_trailing_slash_and_no_double_slash() {
        let client = client();
        assert_eq!(
            client.url(&["domains"]).as_str(),
            "https://desec.example/api/v1/domains/"
        );
        assert_eq!(
            client.url(&["domains", "example.com", "rrsets"]).as_str(),
            "https://desec.example/api/v1/domains/example.com/rrsets/"
        );
    }

    #[test]
    fn a_trailing_slash_on_the_base_is_normalized_away() {
        let client = Client::builder()
            .base_url("https://desec.example/api/v1/")
            .build()
            .expect("valid");
        assert_eq!(
            client.url(&["domains"]).as_str(),
            "https://desec.example/api/v1/domains/"
        );
    }

    /// The apex path segment must survive as `@`, and a wildcard must not be mangled.
    #[test]
    fn path_segments_are_encoded_without_breaking_dns_syntax() {
        let client = client();
        assert_eq!(
            client
                .url(&["domains", "example.com", "rrsets", "@", "A"])
                .as_str(),
            "https://desec.example/api/v1/domains/example.com/rrsets/@/A/"
        );
        assert_eq!(
            client
                .url(&["domains", "example.com", "rrsets", "*.wild", "A"])
                .as_str(),
            "https://desec.example/api/v1/domains/example.com/rrsets/*.wild/A/"
        );
    }

    #[test]
    fn query_values_are_percent_encoded() {
        let client = client();
        let req = client
            .request(
                Method::GET,
                client.url(&["domains", "example.com", "rrsets"]),
                ScopeSet::default(),
            )
            .query("subname", "a b&c=d");
        assert_eq!(req.url.query(), Some("subname=a+b%26c%3Dd"));
    }

    #[test]
    fn rejects_a_non_http_base_url() {
        let err = Client::builder()
            .base_url("mailto:someone@example.com")
            .build()
            .expect_err("not an http URL");
        assert!(err.is_validation(), "{err:?}");
    }

    #[test]
    fn base64_matches_the_reference_vectors() {
        // RFC 4648 test vectors, which pin the padding cases.
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foob"), "Zm9vYg==");
        assert_eq!(base64_standard(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_standard(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn token_auth_uses_the_desec_scheme() {
        let auth = Auth::Token(Secret::new("abc"));
        let header = auth
            .header()
            .expect("token auth sends a header")
            .expect("valid header value");
        assert_eq!(header.to_str().expect("ascii"), "Token abc");
    }

    #[test]
    fn basic_auth_is_encoded() {
        let auth = Auth::Basic {
            username: "user".into(),
            password: Secret::new("pass"),
        };
        let header = auth
            .header()
            .expect("basic auth sends a header")
            .expect("valid header value");
        assert_eq!(header.to_str().expect("ascii"), "Basic dXNlcjpwYXNz");
    }

    fn utc(rfc2822: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc2822(rfc2822)
            .expect("a well-formed RFC 2822 date")
            .to_utc()
    }

    #[test]
    fn retry_after_resolves_an_http_date_against_the_given_now() {
        let now = utc("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 07:28:30 GMT", now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_retry_after("  Wed, 21 Oct 2015 08:28:00 GMT  ", now),
            Some(Duration::from_secs(3600))
        );
        assert_eq!(
            parse_retry_after("Mon, 21 Oct 2115 07:28:00 GMT", now),
            Some(MAX_RETRY_AFTER)
        );
    }

    #[test]
    fn retry_after_reads_the_seconds_form() {
        let now = utc("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(parse_retry_after("30", now), Some(Duration::from_secs(30)));
        assert_eq!(parse_retry_after(" 0 ", now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("999999999", now), Some(MAX_RETRY_AFTER));
    }

    /// A deadline that has already passed is no wait at all, not a zero and not a
    /// wrapped-around one, so the caller falls back to its own backoff.
    #[test]
    fn retry_after_rejects_a_date_in_the_past() {
        let now = utc("Wed, 21 Oct 2015 07:28:00 GMT");
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2015 06:28:00 GMT", now),
            None
        );
    }

    #[test]
    fn retry_after_rejects_a_malformed_value() {
        let now = utc("Wed, 21 Oct 2015 07:28:00 GMT");
        for raw in ["", "soon", "-30", "30s", "2015-10-21T07:28:30Z"] {
            assert_eq!(parse_retry_after(raw, now), None, "{raw:?}");
        }
    }

    #[test]
    fn backoff_doubles_and_saturates_at_the_ceiling() {
        let client = Client::builder()
            .base_url("https://desec.example/api/v1")
            .max_retry_delay(Duration::from_secs(4))
            .build()
            .expect("valid");
        assert_eq!(client.backoff(1), Duration::from_millis(500));
        assert_eq!(client.backoff(2), Duration::from_secs(1));
        assert_eq!(client.backoff(3), Duration::from_secs(2));
        assert_eq!(client.backoff(4), Duration::from_secs(4));
        assert_eq!(client.backoff(40), Duration::from_secs(4));
    }
}
