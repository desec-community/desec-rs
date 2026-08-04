//! DNS record management: `/domains/{name}/rrsets/`.
//!
//! Three of the API's sharper edges live here, and the types are shaped to make them
//! unreachable rather than merely documented:
//!
//! - The apex is `@` in a path and `""` in a body. [`Subname`] carries both spellings, so
//!   a value read from a response can be put straight into a URL.
//! - `records: null` is a `400`, not "leave unchanged". Omission is how `PATCH` skips a
//!   field, so [`RrsetPatch`] omits rather than nulls, and a TTL-only update is
//!   expressible.
//! - A body `subname` that disagrees with the path `subname` is a `400`. The write
//!   methods derive the body from the same arguments that build the path, so the two
//!   cannot drift apart.

use chrono::{DateTime, Utc};
use reqwest::Method;
use serde::{Deserialize, Serialize};

use crate::client::Client;
use crate::error::{InvalidValue, Result, check_path_segment};
use crate::page::ListRequest;
use crate::ratelimit::{Scope, ScopeSet};
use crate::types::{RecordType, Subname};

/// Largest TTL the API accepts.
pub const MAX_TTL: u32 = 86_400;

/// Most records one RRset may hold.
pub const MAX_RECORDS: usize = 4_091;

/// A resource record set: every record of one type at one name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[non_exhaustive]
pub struct Rrset {
    /// The zone this belongs to.
    pub domain: String,
    /// Label relative to the zone. Empty at the apex.
    pub subname: Subname,
    /// The record type.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Fully qualified name, with the trailing dot.
    pub name: String,
    /// Record contents in BIND presentation format.
    pub records: Vec<String>,
    /// Time to live, in seconds.
    pub ttl: u32,
    /// When the RRset was created.
    pub created: DateTime<Utc>,
    /// When the RRset was last modified.
    #[serde(default)]
    pub touched: Option<DateTime<Utc>>,
}

/// A complete RRset to create, for `POST`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NewRrset {
    /// Label relative to the zone; serializes to `""` at the apex.
    pub subname: Subname,
    /// The record type.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Time to live. Must be at least the domain's `minimum_ttl` and at most
    /// [`MAX_TTL`].
    pub ttl: u32,
    /// Record contents in BIND presentation format. Domain names need a trailing dot.
    pub records: Vec<String>,
}

impl NewRrset {
    /// A new RRset at `subname`.
    pub fn new(
        subname: Subname,
        record_type: RecordType,
        ttl: u32,
        records: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            subname,
            record_type,
            ttl,
            records: records.into_iter().map(Into::into).collect(),
        }
    }

    /// A new RRset at the zone apex.
    pub fn at_apex(
        record_type: RecordType,
        ttl: u32,
        records: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::new(Subname::apex(), record_type, ttl, records)
    }

    fn validate(&self) -> Result<(), InvalidValue> {
        validate_ttl(self.ttl)?;
        validate_records(&self.records)
    }
}

/// A partial update to one RRset, for `PATCH`.
///
/// Fields left unset are omitted from the body, which is what tells the API to leave them
/// alone. Nothing here can serialize to `null`, because `records: null` is a `400` rather
/// than a no-op.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RrsetPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<String>>,
}

impl RrsetPatch {
    /// An update that changes nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the TTL, leaving the records alone.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Replaces the records, leaving the TTL alone.
    ///
    /// An empty list deletes the RRset.
    pub fn records(mut self, records: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.records = Some(records.into_iter().map(Into::into).collect());
        self
    }

    /// Whether this update would change anything.
    pub fn is_empty(&self) -> bool {
        self.ttl.is_none() && self.records.is_none()
    }

    fn validate(&self) -> Result<(), InvalidValue> {
        if let Some(ttl) = self.ttl {
            validate_ttl(ttl)?;
        }
        if let Some(records) = &self.records {
            validate_records(records)?;
        }
        Ok(())
    }
}

/// One item of a bulk `PATCH`.
///
/// `subname` and `type` identify the RRset and are always sent; the rest are omitted when
/// unset. To create an RRset this way, every field except `subname` must be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkPatch {
    /// Which name to act on. Serializes to `""` at the apex, never `@`.
    pub subname: Subname,
    /// Which type to act on.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    records: Option<Vec<String>>,
}

impl BulkPatch {
    /// Targets one RRset without changing anything yet.
    pub fn new(subname: Subname, record_type: RecordType) -> Self {
        Self {
            subname,
            record_type,
            ttl: None,
            records: None,
        }
    }

    /// Sets the TTL.
    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Replaces the records. An empty list deletes the RRset.
    pub fn records(mut self, records: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.records = Some(records.into_iter().map(Into::into).collect());
        self
    }

    /// Marks the RRset for deletion, by sending an empty record list.
    ///
    /// `PATCH` is the right verb for this: `PUT` would additionally demand a `ttl` even
    /// though the records are being removed.
    pub fn delete(subname: Subname, record_type: RecordType) -> Self {
        Self::new(subname, record_type).records(Vec::<String>::new())
    }

    fn validate(&self) -> Result<(), InvalidValue> {
        if let Some(ttl) = self.ttl {
            validate_ttl(ttl)?;
        }
        if let Some(records) = &self.records {
            validate_records(records)?;
        }
        Ok(())
    }
}

/// One item of a bulk `PUT`, which requires every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkPut {
    /// Which name to act on. Serializes to `""` at the apex.
    pub subname: Subname,
    /// Which type to act on.
    #[serde(rename = "type")]
    pub record_type: RecordType,
    /// Time to live. Required even when `records` is empty.
    pub ttl: u32,
    /// Record contents. An empty list deletes the RRset.
    pub records: Vec<String>,
}

impl BulkPut {
    /// A full RRset specification.
    pub fn new(
        subname: Subname,
        record_type: RecordType,
        ttl: u32,
        records: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            subname,
            record_type,
            ttl,
            records: records.into_iter().map(Into::into).collect(),
        }
    }

    fn validate(&self) -> Result<(), InvalidValue> {
        validate_ttl(self.ttl)?;
        validate_records(&self.records)
    }
}

fn validate_ttl(ttl: u32) -> Result<(), InvalidValue> {
    if ttl == 0 || ttl > MAX_TTL {
        return Err(InvalidValue::new(
            "ttl",
            "must be between 1 and 86400 seconds",
            ttl.to_string(),
        ));
    }
    Ok(())
}

fn validate_records(records: &[String]) -> Result<(), InvalidValue> {
    if records.len() > MAX_RECORDS {
        return Err(InvalidValue::new(
            "records",
            "an RRset holds at most 4091 records",
            records.len().to_string(),
        ));
    }
    Ok(())
}

/// RRset endpoints, scoped to one domain.
#[derive(Debug, Clone, Copy)]
pub struct RrsetsApi<'a> {
    client: &'a Client,
    domain: &'a str,
}

impl<'a> RrsetsApi<'a> {
    pub(crate) fn new(client: &'a Client, domain: &'a str) -> Self {
        Self { client, domain }
    }

    /// The scope for a write, which deSEC counts per domain.
    fn write_scope(&self) -> ScopeSet {
        ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, self.domain)
    }

    fn collection_url(&self) -> Result<url::Url> {
        check_path_segment("domain", self.domain)?;
        Ok(self.client.url(&["domains", self.domain, "rrsets"]))
    }

    fn item_url(&self, subname: &Subname, record_type: &RecordType) -> Result<url::Url> {
        check_path_segment("domain", self.domain)?;
        // `as_path` is what keeps the apex reachable: an empty segment would collapse.
        Ok(self.client.url(&[
            "domains",
            self.domain,
            "rrsets",
            subname.as_path(),
            record_type.as_str(),
        ]))
    }

    /// `POST /domains/{name}/rrsets/` — creates one RRset.
    pub async fn create(&self, rrset: &NewRrset) -> Result<Rrset> {
        rrset.validate()?;
        let req = self
            .client
            .request(Method::POST, self.collection_url()?, self.write_scope())
            .json(rrset)?;
        self.client.send_json(req).await
    }

    /// `POST /domains/{name}/rrsets/` with an array — creates several RRsets atomically.
    ///
    /// All of them are published or none are. A validation failure comes back as a
    /// positional array; read it with
    /// [`ApiError::bulk_items`](crate::ApiError::bulk_items), whose indices line up with
    /// `rrsets`.
    pub async fn create_bulk(&self, rrsets: &[NewRrset]) -> Result<Vec<Rrset>> {
        for rrset in rrsets {
            rrset.validate()?;
        }
        let req = self
            .client
            .request(Method::POST, self.collection_url()?, self.write_scope())
            .json(rrsets)?;
        self.client.send_json(req).await
    }

    /// `GET /domains/{name}/rrsets/` — lists RRsets.
    ///
    /// Narrow with [`subname`](ListRequest::subname) and
    /// [`record_type`](ListRequest::record_type), which combine.
    pub fn list(&self) -> ListRequest<Rrset> {
        // Infallible so the filter builders chain freely; an unusable domain name simply
        // produces a request the server answers with 404.
        ListRequest::new(
            self.client.clone(),
            self.client.url(&["domains", self.domain, "rrsets"]),
            ScopeSet::new(Scope::DnsApiCheap),
        )
    }

    /// `GET /domains/{name}/rrsets/{subname}/{type}/` — retrieves one RRset.
    pub async fn get(&self, subname: &Subname, record_type: &RecordType) -> Result<Rrset> {
        let req = self.client.request(
            Method::GET,
            self.item_url(subname, record_type)?,
            ScopeSet::new(Scope::DnsApiCheap),
        );
        self.client.send_json(req).await
    }

    /// As [`get`](Self::get), with `404` mapped onto `None`.
    pub async fn try_get(
        &self,
        subname: &Subname,
        record_type: &RecordType,
    ) -> Result<Option<Rrset>> {
        let req = self.client.request(
            Method::GET,
            self.item_url(subname, record_type)?,
            ScopeSet::new(Scope::DnsApiCheap),
        );
        self.client.send_json_opt(req).await
    }

    /// `PATCH …/{subname}/{type}/` — updates the fields the patch sets.
    ///
    /// Works at the apex, and a TTL-only patch leaves the records untouched.
    pub async fn patch(
        &self,
        subname: &Subname,
        record_type: &RecordType,
        patch: &RrsetPatch,
    ) -> Result<Rrset> {
        patch.validate()?;
        let req = self
            .client
            .request(
                Method::PATCH,
                self.item_url(subname, record_type)?,
                self.write_scope(),
            )
            .json(patch)?;
        self.client.send_json(req).await
    }

    /// `PUT …/{subname}/{type}/` — replaces one RRset outright.
    ///
    /// The body's `subname` and `type` are taken from the same arguments that build the
    /// path, so they cannot disagree with it.
    pub async fn replace(
        &self,
        subname: &Subname,
        record_type: &RecordType,
        ttl: u32,
        records: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Rrset> {
        let body = BulkPut::new(subname.clone(), record_type.clone(), ttl, records);
        body.validate()?;
        let req = self
            .client
            .request(
                Method::PUT,
                self.item_url(subname, record_type)?,
                self.write_scope(),
            )
            .json(&body)?;
        self.client.send_json(req).await
    }

    /// `DELETE …/{subname}/{type}/` — deletes one RRset.
    ///
    /// Idempotent: succeeds whether or not the RRset was there.
    pub async fn delete(&self, subname: &Subname, record_type: &RecordType) -> Result<()> {
        let req = self.client.request(
            Method::DELETE,
            self.item_url(subname, record_type)?,
            self.write_scope(),
        );
        self.client.send_empty(req).await
    }

    /// `PATCH /domains/{name}/rrsets/` — creates, updates and deletes atomically.
    ///
    /// The verb of choice for a mixed batch, and the only one that can delete without
    /// also supplying a TTL.
    pub async fn patch_bulk(&self, patches: &[BulkPatch]) -> Result<Vec<Rrset>> {
        for patch in patches {
            patch.validate()?;
        }
        let req = self
            .client
            .request(Method::PATCH, self.collection_url()?, self.write_scope())
            .json(patches)?;
        self.client.send_json(req).await
    }

    /// `PUT /domains/{name}/rrsets/` — replaces RRsets atomically, creating what is
    /// missing.
    ///
    /// Every item needs every field, including a `ttl` on an item whose `records` is
    /// empty. Prefer [`patch_bulk`](Self::patch_bulk) for deletions.
    pub async fn replace_bulk(&self, rrsets: &[BulkPut]) -> Result<Vec<Rrset>> {
        for rrset in rrsets {
            rrset.validate()?;
        }
        let req = self
            .client
            .request(Method::PUT, self.collection_url()?, self.write_scope())
            .json(rrsets)?;
        self.client.send_json(req).await
    }

    /// Deletes several RRsets in one atomic request.
    ///
    /// Sends a bulk `PATCH` with empty record lists. `PUT` would reject the same request
    /// for lacking a `ttl`.
    pub async fn delete_bulk(
        &self,
        rrsets: impl IntoIterator<Item = (Subname, RecordType)>,
    ) -> Result<Vec<Rrset>> {
        let patches: Vec<_> = rrsets
            .into_iter()
            .map(|(subname, record_type)| BulkPatch::delete(subname, record_type))
            .collect();
        self.patch_bulk(&patches).await
    }
}

impl ListRequest<Rrset> {
    /// `?subname=` — only RRsets at this name.
    pub fn subname(self, subname: &Subname) -> Self {
        // The filter is a payload-position value, so the apex is the empty string.
        self.with_filter("subname", subname.as_payload())
    }

    /// `?type=` — only RRsets of this type. Combines with
    /// [`subname`](ListRequest::subname).
    pub fn record_type(self, record_type: &RecordType) -> Self {
        self.with_filter("type", record_type.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json<T: Serialize>(value: &T) -> String {
        serde_json::to_string(value).expect("serializes")
    }

    /// The whole point of `RrsetPatch`: a TTL-only update must not mention `records`.
    #[test]
    fn a_ttl_only_patch_omits_records() {
        assert_eq!(json(&RrsetPatch::new().ttl(3600)), r#"{"ttl":3600}"#);
    }

    #[test]
    fn a_records_only_patch_omits_ttl() {
        assert_eq!(
            json(&RrsetPatch::new().records(["127.0.0.1"])),
            r#"{"records":["127.0.0.1"]}"#
        );
    }

    /// `records: null` is a 400 upstream, so no combination may produce it.
    #[test]
    fn no_patch_can_serialize_a_null() {
        for patch in [
            RrsetPatch::new(),
            RrsetPatch::new().ttl(60),
            RrsetPatch::new().records(Vec::<String>::new()),
        ] {
            assert!(!json(&patch).contains("null"), "{}", json(&patch));
        }
    }

    #[test]
    fn an_empty_record_list_is_the_deletion_signal() {
        assert_eq!(
            json(&RrsetPatch::new().records(Vec::<String>::new())),
            r#"{"records":[]}"#
        );
    }

    #[test]
    fn the_apex_serializes_as_an_empty_string_in_a_bulk_body() {
        let patch = BulkPatch::delete(Subname::apex(), RecordType::A);
        assert_eq!(json(&patch), r#"{"subname":"","type":"A","records":[]}"#);
    }

    #[test]
    fn bulk_patch_always_sends_the_identifying_fields() {
        let patch = BulkPatch::new("www".parse().expect("valid"), RecordType::AAAA);
        assert_eq!(json(&patch), r#"{"subname":"www","type":"AAAA"}"#);
    }

    #[test]
    fn bulk_put_sends_every_field() {
        let put = BulkPut::new(
            Subname::apex(),
            RecordType::MX,
            3600,
            ["10 mx.example.com."],
        );
        assert_eq!(
            json(&put),
            r#"{"subname":"","type":"MX","ttl":3600,"records":["10 mx.example.com."]}"#
        );
    }

    #[test]
    fn rejects_a_ttl_outside_the_documented_range() {
        assert!(
            NewRrset::at_apex(RecordType::A, 0, ["127.0.0.1"])
                .validate()
                .is_err()
        );
        assert!(
            NewRrset::at_apex(RecordType::A, MAX_TTL + 1, ["127.0.0.1"])
                .validate()
                .is_err()
        );
        assert!(
            NewRrset::at_apex(RecordType::A, MAX_TTL, ["127.0.0.1"])
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn rejects_too_many_records() {
        let records = vec!["127.0.0.1".to_owned(); MAX_RECORDS + 1];
        assert!(
            NewRrset::at_apex(RecordType::A, 3600, records)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn an_rrset_from_the_api_round_trips_to_a_path_and_back() {
        // The apex comes back as `""`; it has to go out as `@`.
        let body = r#"{
            "domain": "example.com",
            "subname": "",
            "type": "A",
            "name": "example.com.",
            "records": ["127.0.0.1"],
            "ttl": 3600,
            "created": "2019-09-18T16:32:16.510368Z",
            "touched": "2019-09-18T16:32:16.510368Z"
        }"#;
        let rrset: Rrset = serde_json::from_str(body).expect("valid RRset");
        assert!(rrset.subname.is_apex());
        assert_eq!(rrset.subname.as_path(), "@");
        assert_eq!(rrset.record_type, RecordType::A);
    }
}
