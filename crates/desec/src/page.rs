//! Cursor pagination.
//!
//! deSEC paginates `GET /domains/`, `GET /domains/{name}/rrsets/` and
//! `GET /auth/tokens/` at 500 items, advertising cursors in a `Link` header. Token
//! policy lists are not paginated and are returned as plain vectors instead.
//!
//! One detail governs the design: *omitting* the `cursor` parameter is what makes the
//! API answer `400 Pagination required` once a collection exceeds a page, while
//! `?cursor=` with an empty value is the valid first page. So [`ListRequest`] always
//! sends the parameter, and a deliberately single-page read cannot turn into a `400` as
//! a collection grows.

use std::marker::PhantomData;
use std::pin::Pin;

use futures_core::Stream;
use reqwest::{Method, header};
use serde::de::DeserializeOwned;
use url::Url;

use crate::client::{Client, Res};
use crate::error::{Error, Result};
use crate::ratelimit::ScopeSet;

/// A lazy stream of items across pages, as returned by [`ListRequest::stream`].
///
/// Boxed so that it is `Unpin`, which is what lets `try_next().await` be called directly.
pub type ItemStream<T> = Pin<Box<dyn Stream<Item = Result<T>> + Send>>;

/// An opaque position in a paginated collection.
///
/// Safe to persist and pass back via [`ListRequest::cursor`] to resume, though deSEC
/// makes no promise about how long one stays valid.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cursor(String);

impl Cursor {
    /// The cursor's wire value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Cursor {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Cursor {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// One page of a paginated collection.
#[derive(Debug, Clone)]
pub struct Page<T> {
    /// The items on this page, at most 500.
    pub items: Vec<T>,
    /// Cursor for the first page, when the server advertised one.
    pub first: Option<Cursor>,
    /// Cursor for the previous page, absent on the first page.
    pub prev: Option<Cursor>,
    /// Cursor for the next page, absent on the last page.
    pub next: Option<Cursor>,
}

impl<T> Page<T> {
    /// Whether another page follows.
    pub fn has_next(&self) -> bool {
        self.next.is_some()
    }
}

/// A pending request for a paginated collection.
///
/// Three ways to consume it, in increasing eagerness:
///
/// - [`send`](Self::send) fetches exactly one page and hands back its cursors.
/// - [`stream`](Self::stream) yields items across pages, fetching page *n+1* only when
///   the consumer asks for an item on it. Stopping early costs nothing.
/// - [`all`](Self::all) walks every page and collects. Convenient when the collection is
///   known to be small; on a large zone it is a lot of requests.
pub struct ListRequest<T> {
    client: Client,
    url: Url,
    scopes: ScopeSet,
    cursor: Option<Cursor>,
    marker: PhantomData<fn() -> T>,
}

impl<T> Clone for ListRequest<T> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            url: self.url.clone(),
            scopes: self.scopes.clone(),
            cursor: self.cursor.clone(),
            marker: PhantomData,
        }
    }
}

impl<T> std::fmt::Debug for ListRequest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListRequest")
            .field("url", &self.url.as_str())
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<T> ListRequest<T> {
    pub(crate) fn new(client: Client, url: Url, scopes: ScopeSet) -> Self {
        Self {
            client,
            url,
            scopes,
            cursor: None,
            marker: PhantomData,
        }
    }

    /// Starts from a saved cursor rather than the first page.
    pub fn cursor(mut self, cursor: impl Into<Cursor>) -> Self {
        self.cursor = Some(cursor.into());
        self
    }

    /// Adds an arbitrary query parameter.
    ///
    /// The typed filters are the ones the API documents; this is the escape hatch for a
    /// parameter added upstream before this crate models it.
    pub fn filter(mut self, key: &str, value: &str) -> Self {
        self.url.query_pairs_mut().append_pair(key, value);
        self
    }

    pub(crate) fn with_filter(self, key: &str, value: &str) -> Self {
        self.filter(key, value)
    }
}

impl<T: DeserializeOwned> ListRequest<T> {
    /// Fetches a single page.
    pub async fn send(self) -> Result<Page<T>> {
        let mut req = self
            .client
            .request(Method::GET, self.url, self.scopes.clone());
        // Always present, empty for the first page. See the module docs.
        req.url_mut()
            .query_pairs_mut()
            .append_pair("cursor", self.cursor.as_ref().map_or("", Cursor::as_str));

        let res = self.client.send(req).await?;
        let links = parse_link_header(&res)?;
        Ok(Page {
            items: res.json()?,
            first: links.first,
            prev: links.prev,
            next: links.next,
        })
    }

    /// Fetches every remaining page and collects the items.
    pub async fn all(self) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut request = self;
        loop {
            let next = request.clone();
            let current = request.cursor.clone();
            let page = request.send().await?;
            out.extend(page.items);
            match page.next {
                // A next cursor equal to the current one would loop forever. The API does
                // not do this, but a `Link` header pointing at the request's own URL would
                // produce it, and an infinite loop is a worse failure than a short list.
                Some(cursor) if Some(&cursor) == current.as_ref() => return Ok(out),
                Some(cursor) => request = next.cursor(cursor),
                None => return Ok(out),
            }
        }
    }
}

impl<T: DeserializeOwned + Send + 'static> ListRequest<T> {
    /// Streams items across pages, fetching lazily.
    ///
    /// Only the pages actually consumed are requested, so `stream().take(10)` costs one
    /// request no matter how large the collection is.
    ///
    /// ```no_run
    /// use futures_util::TryStreamExt;
    ///
    /// # async fn run(client: desec::Client) -> Result<(), desec::Error> {
    /// let mut rrsets = client.rrsets("example.com").list().stream();
    /// while let Some(rrset) = rrsets.try_next().await? {
    ///     println!("{} {}", rrset.name, rrset.record_type);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn stream(self) -> ItemStream<T> {
        // Boxed rather than `impl Stream`, because a generator is not `Unpin` and callers
        // would otherwise have to pin it before every `try_next`.
        Box::pin(async_stream::try_stream! {
            let mut request = Some(self);
            while let Some(current) = request.take() {
                let resume = current.clone();
                let previous = current.cursor.clone();
                let page = current.send().await?;
                for item in page.items {
                    yield item;
                }
                // Stopping on a repeated cursor, for the same reason as `all`.
                if let Some(cursor) = page.next {
                    if Some(&cursor) != previous.as_ref() {
                        request = Some(resume.cursor(cursor));
                    }
                }
            }
        })
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Links {
    first: Option<Cursor>,
    prev: Option<Cursor>,
    next: Option<Cursor>,
}

/// Extracts cursors from every `Link` header on a response.
///
/// The cursor value is taken from the link URL's `cursor` parameter rather than the URL
/// being followed verbatim, so a caller can store one and resume later.
fn parse_link_header(res: &Res) -> Result<Links> {
    let mut links = Links::default();
    for value in res.headers.get_all(header::LINK) {
        let raw = value
            .to_str()
            .map_err(|_| Error::MalformedLink("header is not valid text".to_owned()))?;
        for (url, rel) in split_links(raw) {
            // Link URLs are absolute, but parse relatively to the request URL so a
            // relative one would still resolve.
            let base = Url::parse(res.url.as_str()).ok();
            let parsed = match base
                .as_ref()
                .map_or_else(|| Url::parse(url), |b| b.join(url))
            {
                Ok(parsed) => parsed,
                Err(_) => return Err(Error::MalformedLink(url.to_owned())),
            };
            let cursor = parsed
                .query_pairs()
                .find(|(key, _)| key == "cursor")
                .map(|(_, value)| Cursor(value.into_owned()));
            let Some(cursor) = cursor else { continue };
            match rel {
                "first" => links.first = Some(cursor),
                "prev" | "previous" => links.prev = Some(cursor),
                "next" => links.next = Some(cursor),
                _ => {}
            }
        }
    }
    Ok(links)
}

/// Splits a `Link` header into `(url, rel)` pairs.
///
/// Commas only separate entries outside the angle brackets, because a percent-encoded
/// cursor can contain one.
fn split_links(raw: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = raw;
    while let Some(open) = rest.find('<') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('>') else {
            break;
        };
        let url = &after_open[..close];
        let mut params = &after_open[close + 1..];

        // Parameters run up to the comma that introduces the next entry.
        match params.find('<') {
            Some(next_open) => {
                let boundary = params[..next_open].rfind(',').unwrap_or(next_open);
                rest = &params[boundary..];
                params = &params[..boundary];
            }
            None => rest = "",
        }

        for param in params.split(';') {
            let Some((key, value)) = param.split_once('=') else {
                continue;
            };
            if key.trim().eq_ignore_ascii_case("rel") {
                out.push((url, value.trim().trim_matches('"')));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use reqwest::StatusCode;
    use reqwest::header::HeaderMap;

    fn response(link: &str) -> Res {
        let mut headers = HeaderMap::new();
        if !link.is_empty() {
            headers.insert(
                header::LINK,
                link.parse().expect("test header value is valid"),
            );
        }
        Res {
            status: StatusCode::OK,
            headers,
            body: b"[]".to_vec(),
            method: Method::GET,
            path: "/api/v1/domains/".to_owned(),
            url: Url::parse("https://desec.io/api/v1/domains/").expect("valid"),
        }
    }

    #[test]
    fn extracts_next_and_prev_cursors() {
        let res = response(
            r#"<https://desec.io/api/v1/domains/?cursor=b2Zmc2V0PTUwMA%3D%3D>; rel="next", <https://desec.io/api/v1/domains/?cursor=>; rel="first""#,
        );
        let links = parse_link_header(&res).expect("well-formed");
        assert_eq!(
            links.next.as_ref().map(Cursor::as_str),
            Some("b2Zmc2V0PTUwMA==")
        );
        assert_eq!(links.first.as_ref().map(Cursor::as_str), Some(""));
        assert_eq!(links.prev, None);
    }

    #[test]
    fn accepts_both_prev_spellings() {
        for rel in ["prev", "previous"] {
            let res = response(&format!(
                r#"<https://desec.io/api/v1/domains/?cursor=abc>; rel="{rel}""#
            ));
            let links = parse_link_header(&res).expect("well-formed");
            assert_eq!(
                links.prev.as_ref().map(Cursor::as_str),
                Some("abc"),
                "{rel}"
            );
        }
    }

    /// A cursor is base64 with percent-encoding, so a comma inside the URL must not be
    /// mistaken for an entry separator.
    #[test]
    fn a_comma_inside_a_url_does_not_split_the_header() {
        let res =
            response(r#"<https://desec.io/api/v1/domains/?cursor=a%2Cb&subname=x>; rel="next""#);
        let links = parse_link_header(&res).expect("well-formed");
        assert_eq!(links.next.as_ref().map(Cursor::as_str), Some("a,b"));
    }

    #[test]
    fn no_link_header_means_a_single_page() {
        let links = parse_link_header(&response("")).expect("well-formed");
        assert_eq!(links, Links::default());
    }

    #[test]
    fn links_without_a_cursor_are_ignored() {
        let res = response(r#"<https://desec.io/api/v1/domains/>; rel="next""#);
        let links = parse_link_header(&res).expect("well-formed");
        assert_eq!(links.next, None);
    }

    #[test]
    fn preserves_filters_when_resuming() {
        // A resumed request keeps its filters, because the cursor is layered onto the
        // same URL rather than replacing it.
        let client = Client::builder()
            .base_url("https://desec.example/api/v1")
            .build()
            .expect("valid");
        let url = client.url(&["domains", "example.com", "rrsets"]);
        let request: ListRequest<()> = ListRequest::new(client, url, ScopeSet::default())
            .filter("type", "A")
            .cursor("abc");
        assert_eq!(request.url.query(), Some("type=A"));
        assert_eq!(request.cursor.as_ref().map(Cursor::as_str), Some("abc"));
    }
}
