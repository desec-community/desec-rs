//! The API surface, grouped by resource.
//!
//! Each group is reached from [`Client`]: [`domains`](Client::domains),
//! [`rrsets`](Client::rrsets), [`tokens`](Client::tokens) and
//! [`account`](Client::account). The dynDNS update protocol lives on a different host and
//! has its own client, [`DynDnsClient`](crate::api::dyndns::DynDnsClient).

pub mod account;
pub mod domains;
pub mod dyndns;
pub mod rrsets;
pub mod tokens;

pub use account::AccountApi;
pub use domains::DomainsApi;
pub use rrsets::RrsetsApi;
pub use tokens::{TokenPoliciesApi, TokensApi};

use crate::client::Client;

impl Client {
    /// Domain management.
    pub fn domains(&self) -> DomainsApi<'_> {
        DomainsApi::new(self)
    }

    /// DNS record management within one domain.
    pub fn rrsets<'a>(&'a self, domain: &'a str) -> RrsetsApi<'a> {
        RrsetsApi::new(self, domain)
    }

    /// Token and token policy management.
    pub fn tokens(&self) -> TokensApi<'_> {
        TokensApi::new(self)
    }

    /// Registration, login, and account settings.
    pub fn account(&self) -> AccountApi<'_> {
        AccountApi::new(self)
    }
}

/// The body of a `202 Accepted`, and of the `/v/…/{code}/` confirmations.
///
/// The account flows that send email never return a resource — only this message. Both
/// existing community clients get this wrong in one direction or the other, so it is
/// modelled explicitly rather than being folded into an account type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Detail {
    /// Human-readable message, meant for showing to a user.
    pub detail: String,
}
