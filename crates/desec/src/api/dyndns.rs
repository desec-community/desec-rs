//! The dynDNS update protocol.
//!
//! A different host and a different shape from the REST API: `GET` with query parameters
//! against `update.dedyn.io`, answering `good` in a plain-text body. It gets its own
//! client because the base URL, the accepted authentication schemes and the throttling
//! scope all differ.
//!
//! ```no_run
//! use desec::dyndns::{DynDnsClient, IpUpdate};
//!
//! # async fn run() -> Result<(), desec::Error> {
//! let client = DynDnsClient::builder().token("i-T3b1h_OI-H9ab8tRS98stGtURe").build()?;
//!
//! // Let the server take the address from the connection.
//! client.update("example.dedyn.io").send().await?;
//!
//! // Or set both families explicitly, leaving the A record as it is.
//! client
//!     .update("example.dedyn.io")
//!     .ipv4(IpUpdate::Preserve)
//!     .ipv6(IpUpdate::set(["2001:db8::1"]))
//!     .send()
//!     .await?;
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use reqwest::Method;

use crate::client::{Client, ClientBuilder, Secret};
use crate::error::Result;
use crate::ratelimit::{RateLimits, Scope, ScopeSet};

/// The public dynDNS endpoint, reachable over IPv4 or IPv6.
pub const DEFAULT_UPDATE_URL: &str = "https://update.dedyn.io";

/// The IPv6-only endpoint, for making the server observe an IPv6 connection address.
pub const IPV6_UPDATE_URL: &str = "https://update6.dedyn.io";

/// What to do with the records of one address family.
///
/// Leaving a family unset omits its parameter, which lets the server decide from the
/// connection it received the request over. Use [`IpUpdate::Preserve`] to state that an
/// existing record should be kept regardless.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpUpdate {
    /// Set these addresses. CIDR notation is accepted and the host part ignored, which is
    /// how a router can pass a delegated prefix straight through.
    Set(Vec<String>),
    /// Keep whatever records exist.
    Preserve,
    /// Remove the records for this family.
    Remove,
}

impl IpUpdate {
    /// Sets one or more addresses.
    pub fn set(addresses: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Set(addresses.into_iter().map(Into::into).collect())
    }

    fn as_param(&self) -> String {
        match self {
            Self::Set(addresses) => addresses.join(","),
            Self::Preserve => "preserve".to_owned(),
            // An empty value is how the protocol spells "remove".
            Self::Remove => String::new(),
        }
    }
}

/// Which address family a per-hostname override applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// IPv4, the `myipv4` parameter.
    V4,
    /// IPv6, the `myipv6` parameter.
    V6,
}

impl Family {
    fn param(self) -> &'static str {
        match self {
            Self::V4 => "myipv4",
            Self::V6 => "myipv6",
        }
    }
}

/// A client for the dynDNS update endpoint.
#[derive(Debug, Clone)]
pub struct DynDnsClient {
    client: Client,
    query_credentials: Option<(String, Secret)>,
}

impl DynDnsClient {
    /// Starts building a dynDNS client.
    pub fn builder() -> DynDnsClientBuilder {
        DynDnsClientBuilder::default()
    }

    /// Builds an update for one or more hostnames.
    ///
    /// Several hostnames may be updated in one request as long as they belong to the same
    /// domain; pass them by chaining [`hostname`](UpdateRequest::hostname). Doing so is
    /// also kinder to the rate limit than one request each, since the `dyndns` scope
    /// permits only 2 requests per 2 minutes per domain.
    pub fn update(&self, hostname: impl Into<String>) -> UpdateRequest<'_> {
        UpdateRequest {
            client: self,
            hostnames: vec![hostname.into()],
            ipv4: None,
            ipv6: None,
            overrides: Vec::new(),
            rate_limit_key: None,
        }
    }
}

/// Builds a [`DynDnsClient`].
#[derive(Debug, Default)]
pub struct DynDnsClientBuilder {
    inner: ClientBuilder,
    base: Option<String>,
    query_credentials: Option<(String, Secret)>,
}

impl DynDnsClientBuilder {
    /// Authenticates with `Authorization: Token`.
    pub fn token(mut self, token: impl Into<Secret>) -> Self {
        self.inner = self.inner.token(token);
        self
    }

    /// Authenticates with HTTP Basic, the scheme deSEC recommends here.
    ///
    /// The username is the hostname being updated (or the account email), and the password
    /// is a token — never the account password.
    pub fn basic_auth(mut self, username: impl Into<String>, token: impl Into<Secret>) -> Self {
        self.inner = self.inner.basic_auth(username, token);
        self
    }

    /// Passes credentials as `username` and `password` query parameters.
    ///
    /// deSEC discourages this because it puts the token in server logs and in browser
    /// history. It exists for devices whose firmware cannot send an `Authorization`
    /// header.
    pub fn query_credentials(
        mut self,
        username: impl Into<String>,
        token: impl Into<Secret>,
    ) -> Self {
        self.query_credentials = Some((username.into(), token.into()));
        self
    }

    /// Overrides the endpoint. Defaults to [`DEFAULT_UPDATE_URL`].
    ///
    /// Set [`IPV6_UPDATE_URL`] to force the connection over IPv6, so the address the
    /// server observes is an IPv6 one.
    pub fn base_url(mut self, base: impl Into<String>) -> Self {
        self.base = Some(base.into());
        self
    }

    /// Total timeout per attempt.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Replaces the client-side rate limits.
    pub fn rate_limits(mut self, limits: RateLimits) -> Self {
        self.inner = self.inner.rate_limits(limits);
        self
    }

    /// Retries after the first attempt. Defaults to 3.
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.inner = self.inner.max_retries(retries);
        self
    }

    /// Longest single retry sleep to accept.
    pub fn max_retry_delay(mut self, delay: Duration) -> Self {
        self.inner = self.inner.max_retry_delay(delay);
        self
    }

    /// Longest the client-side limiter may sleep before giving up.
    ///
    /// The `dyndns` scope is 2 requests per 2 minutes, so a limiter that is allowed to
    /// wait will happily park an update for a minute or so.
    pub fn max_rate_limit_wait(mut self, max_wait: Duration) -> Self {
        self.inner = self.inner.max_rate_limit_wait(max_wait);
        self
    }

    /// Finishes the client.
    pub fn build(self) -> Result<DynDnsClient> {
        let base = self.base.unwrap_or_else(|| DEFAULT_UPDATE_URL.to_owned());
        Ok(DynDnsClient {
            client: self.inner.base_url(base).build()?,
            query_credentials: self.query_credentials,
        })
    }
}

/// A pending dynDNS update.
#[derive(Debug)]
pub struct UpdateRequest<'a> {
    client: &'a DynDnsClient,
    hostnames: Vec<String>,
    ipv4: Option<IpUpdate>,
    ipv6: Option<IpUpdate>,
    overrides: Vec<(String, Family, IpUpdate)>,
    rate_limit_key: Option<String>,
}

impl UpdateRequest<'_> {
    /// Adds another hostname to the same request. All must be in one domain.
    pub fn hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostnames.push(hostname.into());
        self
    }

    /// What to do with the `A` records.
    pub fn ipv4(mut self, update: IpUpdate) -> Self {
        self.ipv4 = Some(update);
        self
    }

    /// What to do with the `AAAA` records.
    pub fn ipv6(mut self, update: IpUpdate) -> Self {
        self.ipv6 = Some(update);
        self
    }

    /// Overrides one family for one hostname, via `myipv4:hostname=`.
    ///
    /// Takes precedence over [`ipv4`](Self::ipv4) and [`ipv6`](Self::ipv6) for that
    /// hostname.
    pub fn address_for(
        mut self,
        hostname: impl Into<String>,
        family: Family,
        update: IpUpdate,
    ) -> Self {
        self.overrides.push((hostname.into(), family, update));
        self
    }

    /// Sets the key the `dyndns` rate-limit bucket is tracked under.
    ///
    /// deSEC counts dynDNS updates per *domain*, but a hostname does not reveal where the
    /// zone cut is, so by default the bucket is keyed on the first hostname. When updating
    /// several subdomains of one zone from separate requests, name the zone here so they
    /// share one bucket instead of each getting a full allowance.
    pub fn rate_limit_domain(mut self, domain: impl Into<String>) -> Self {
        self.rate_limit_key = Some(domain.into());
        self
    }

    /// Sends the update, discarding the response body.
    pub async fn send(self) -> Result<()> {
        self.send_body().await.map(drop)
    }

    /// Sends the update and returns the response body, which is `good` on success.
    pub async fn send_body(self) -> Result<String> {
        let client = &self.client.client;
        let key = self
            .rate_limit_key
            .as_deref()
            .or_else(|| self.hostnames.first().map(String::as_str))
            .unwrap_or_default();

        let mut req = client.request(
            Method::GET,
            client.url(&[]),
            ScopeSet::per_domain(Scope::DynDns, key),
        );

        if !self.hostnames.is_empty() {
            req = req.query("hostname", &self.hostnames.join(","));
        }
        if let Some(ipv4) = &self.ipv4 {
            req = req.query("myipv4", &ipv4.as_param());
        }
        if let Some(ipv6) = &self.ipv6 {
            req = req.query("myipv6", &ipv6.as_param());
        }
        for (hostname, family, update) in &self.overrides {
            req = req.query(
                &format!("{}:{hostname}", family.param()),
                &update.as_param(),
            );
        }
        if let Some((username, token)) = &self.client.query_credentials {
            req = req
                .query("username", username)
                .query("password", token.expose());
        }

        client.send_text(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_protocol_values() {
        assert_eq!(IpUpdate::Preserve.as_param(), "preserve");
        assert_eq!(IpUpdate::Remove.as_param(), "");
        assert_eq!(IpUpdate::set(["1.2.3.4"]).as_param(), "1.2.3.4");
        assert_eq!(
            IpUpdate::set(["1.2.3.4", "5.6.7.8"]).as_param(),
            "1.2.3.4,5.6.7.8"
        );
        // A delegated prefix goes through as written; the server ignores the host part.
        assert_eq!(
            IpUpdate::set(["2a01:a:b:c::/64"]).as_param(),
            "2a01:a:b:c::/64"
        );
    }

    #[test]
    fn per_family_parameter_names_match_the_protocol() {
        assert_eq!(Family::V4.param(), "myipv4");
        assert_eq!(Family::V6.param(), "myipv6");
    }
}
