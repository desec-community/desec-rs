//! Domain management: `/domains/`.

use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::error::{Result, check_path_segment};
use crate::page::ListRequest;
use crate::ratelimit::{Scope, ScopeSet};

/// A zone held in the account.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Domain {
    /// The zone name, lowercase and in Punycode.
    pub name: String,
    /// When the domain was created.
    pub created: DateTime<Utc>,
    /// When the zone was last published, or `None` if it never has been.
    #[serde(default)]
    pub published: Option<DateTime<Utc>>,
    /// The later of `published` and the newest RRset's `touched`.
    #[serde(default)]
    pub touched: Option<DateTime<Utc>>,
    /// Smallest TTL any RRset in this zone may use. Set by the server.
    pub minimum_ttl: u32,
    /// DNSSEC public keys.
    ///
    /// Empty in list responses, where the API omits the field entirely — ask for a single
    /// domain with [`DomainsApi::get`] to see them.
    #[serde(default)]
    pub keys: Vec<DomainKey>,
}

/// A DNSSEC key of a zone, with the records needed to set up a delegation.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct DomainKey {
    /// `DNSKEY` record content.
    pub dnskey: String,
    /// `DS` records, computed with SHA-256 and SHA-384.
    ///
    /// Empty for keys that are not suitable for a delegation, such as a ZSK.
    #[serde(default)]
    pub ds: Vec<String>,
    /// Whether deSEC manages this key, as opposed to the account owner having added it.
    pub managed: bool,
}

/// The body of a domain creation request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewDomain {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    zonefile: Option<String>,
}

impl NewDomain {
    /// A domain with no initial records beyond the defaults deSEC installs.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            zonefile: None,
        }
    }

    /// Imports records from a zonefile as part of creation.
    ///
    /// Apex `NS` and `DNSKEY` records are replaced with deSEC's own, and the record types
    /// deSEC manages (`RRSIG`, `CDNSKEY`, `CDS`, …) are silently dropped.
    pub fn zonefile(mut self, zonefile: impl Into<String>) -> Self {
        self.zonefile = Some(zonefile.into());
        self
    }
}

/// Domain endpoints.
#[derive(Debug, Clone, Copy)]
pub struct DomainsApi<'a> {
    client: &'a Client,
}

impl<'a> DomainsApi<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// `POST /domains/` — creates a domain.
    ///
    /// Needs a token with `perm_create_domain`. Fails with [`Error::is_forbidden`] when
    /// the account is at its domain limit, and with [`Error::is_validation`] when the name
    /// is unavailable, on the Public Suffix List, or ends in `.internal`.
    ///
    /// [`Error::is_forbidden`]: crate::Error::is_forbidden
    /// [`Error::is_validation`]: crate::Error::is_validation
    pub async fn create(&self, domain: &NewDomain) -> Result<Domain> {
        let url = self.client.url(&["domains"]);
        let req = self
            .client
            .request(Method::POST, url, ScopeSet::new(Scope::DnsApiExpensive))
            .json(domain)?;
        self.client.send_json(req).await
    }

    /// `GET /domains/` — lists domains, without their DNSSEC keys.
    ///
    /// Filter to the zone responsible for a name with
    /// [`owns_qname`](ListRequest::owns_qname), or use [`owner_of`](Self::owner_of).
    pub fn list(&self) -> ListRequest<Domain> {
        ListRequest::new(
            self.client.clone(),
            self.client.url(&["domains"]),
            ScopeSet::new(Scope::DnsApiCheap),
        )
    }

    /// `GET /domains/{name}/` — retrieves one domain, with its DNSSEC keys.
    ///
    /// Answers `404` both for a domain that does not exist and for one owned by someone
    /// else, so a `404` is not evidence that the name is available.
    pub async fn get(&self, name: &str) -> Result<Domain> {
        check_path_segment("domain", name)?;
        let url = self.client.url(&["domains", name]);
        let req = self
            .client
            .request(Method::GET, url, ScopeSet::new(Scope::DnsApiCheap));
        self.client.send_json(req).await
    }

    /// As [`get`](Self::get), with `404` mapped onto `None`.
    pub async fn try_get(&self, name: &str) -> Result<Option<Domain>> {
        check_path_segment("domain", name)?;
        let url = self.client.url(&["domains", name]);
        let req = self
            .client
            .request(Method::GET, url, ScopeSet::new(Scope::DnsApiCheap));
        self.client.send_json_opt(req).await
    }

    /// The zone responsible for a DNS name, via `GET /domains/?owns_qname=`.
    ///
    /// This is how to find where to write an ACME challenge record without assuming
    /// anything about the zone cut. Returns `None` when the account holds no zone that
    /// covers `qname`.
    pub async fn owner_of(&self, qname: &str) -> Result<Option<Domain>> {
        let page = self.list().owns_qname(qname).send().await?;
        Ok(page.items.into_iter().next())
    }

    /// `GET /domains/{name}/zonefile/` — exports the zone as text.
    ///
    /// Excludes the DNSSEC types deSEC generates. Counts against the expensive scope, not
    /// the cheap read scope.
    pub async fn zonefile(&self, name: &str) -> Result<String> {
        check_path_segment("domain", name)?;
        let url = self.client.url(&["domains", name, "zonefile"]);
        let req = self
            .client
            .request(Method::GET, url, ScopeSet::new(Scope::DnsApiExpensive));
        self.client.send_text(req).await
    }

    /// `DELETE /domains/{name}/` — deletes a domain and everything in it.
    ///
    /// Needs a token with `perm_delete_domain`. Succeeds whether or not the domain
    /// existed, so this is idempotent.
    pub async fn delete(&self, name: &str) -> Result<()> {
        check_path_segment("domain", name)?;
        let url = self.client.url(&["domains", name]);
        let req = self
            .client
            .request(Method::DELETE, url, ScopeSet::new(Scope::DnsApiExpensive));
        self.client.send_empty(req).await
    }
}

impl ListRequest<Domain> {
    /// `?owns_qname=` — narrows the list to the zone responsible for a DNS name.
    ///
    /// Yields at most one domain.
    pub fn owns_qname(self, qname: &str) -> Self {
        self.with_filter("owns_qname", qname)
    }
}
