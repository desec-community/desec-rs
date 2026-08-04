//! Error types.
//!
//! [`Error`] is the crate-wide error. The interesting variant is [`Error::Api`], which
//! keeps the server's error document intact as an [`ErrorDetail`] tree rather than
//! flattening it to a string.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use reqwest::StatusCode;

use crate::ratelimit::Scope;

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Anything that can go wrong talking to the deSEC API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The request never produced a response, or the body could not be read.
    ///
    /// The URL carried by the underlying error has had its query string stripped, because
    /// the dynDNS update protocol can put the token there and `reqwest::Error` renders the
    /// URL in both `Debug` and `Display`. There is deliberately no `From` impl for
    /// `reqwest::Error`, so a stray `?` cannot smuggle an unscrubbed URL in.
    #[error("HTTP transport error")]
    Transport(#[source] reqwest::Error),

    /// A URL could not be constructed from the supplied path segments.
    #[error("could not build request URL")]
    Url(#[from] url::ParseError),

    /// The server answered with a status the client treats as an error.
    #[error("{method} {path} failed with HTTP {status}: {detail}")]
    Api {
        /// Status code of the response.
        status: StatusCode,
        /// Request method, for context in logs.
        method: reqwest::Method,
        /// Request path, for context in logs. Query strings are stripped.
        path: String,
        /// One-line rendering of `detail`, so the `Display` impl stays useful.
        detail: String,
        /// The server's error document, structure preserved.
        #[source]
        body: ApiError,
    },

    /// The response body did not match the expected shape.
    #[error("could not decode response body as {expected}")]
    Decode {
        /// Name of the Rust type the body was being decoded into.
        expected: &'static str,
        /// The raw body, truncated to a sane length for diagnostics.
        body: String,
        /// The underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// Serializing a request body failed.
    #[error("could not encode request body")]
    Encode(#[source] serde_json::Error),

    /// The client's own rate limiter would have to wait longer than
    /// [`max_wait`](crate::ClientBuilder::max_rate_limit_wait) allows.
    ///
    /// No request was sent. Retrying later is the only remedy.
    #[error(
        "local rate limit for scope {scope} would block for {wait:.1?}, over the limit of {max_wait:.1?}"
    )]
    RateLimitWouldBlock {
        /// The scope whose bucket is exhausted.
        scope: Scope,
        /// How long the limiter wanted to sleep.
        wait: Duration,
        /// The configured ceiling.
        max_wait: Duration,
    },

    /// The server kept answering `429` until the retry budget ran out.
    #[error("still rate limited after {attempts} attempts")]
    RateLimited {
        /// Number of attempts made, including the first.
        attempts: u32,
        /// `Retry-After` from the final response, if it had one.
        retry_after: Option<Duration>,
        /// The final `429` body.
        #[source]
        body: ApiError,
    },

    /// A value failed client-side validation, so no request was sent.
    ///
    /// These are the constraints the API documents and would reject anyway; checking
    /// them locally saves a round trip and a rate-limit slot.
    #[error("{0}")]
    Invalid(#[from] InvalidValue),

    /// A paginated list returned a `Link` header the client could not parse.
    #[error("malformed Link header: {0}")]
    MalformedLink(String),
}

impl Error {
    /// Wraps a transport failure, dropping the URL's query string on the way in.
    ///
    /// `reqwest::Error` renders the URL it was working on in both `Debug` and
    /// `Display`, and the dynDNS update protocol can carry the token as a query
    /// parameter. Host and path are kept, since those are what makes a transport
    /// failure diagnosable.
    pub(crate) fn transport(mut err: reqwest::Error) -> Self {
        if let Some(url) = err.url_mut() {
            url.set_query(None);
            url.set_fragment(None);
        }
        Self::Transport(err)
    }

    /// The HTTP status, when the error came from a response.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Api { status, .. } => Some(*status),
            Self::RateLimited { .. } => Some(StatusCode::TOO_MANY_REQUESTS),
            _ => None,
        }
    }

    /// True when the API said the resource does not exist, or is not ours.
    ///
    /// deSEC returns `404` for domains owned by someone else, so this does not
    /// distinguish "absent" from "not yours".
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(StatusCode::NOT_FOUND)
    }

    /// True when the token was missing, malformed, or expired.
    pub fn is_unauthorized(&self) -> bool {
        self.status() == Some(StatusCode::UNAUTHORIZED)
    }

    /// True when the token authenticated but lacks the permission for this call.
    ///
    /// Also covers a failed login and a domain-limit rejection, both of which the API
    /// reports as `403`.
    pub fn is_forbidden(&self) -> bool {
        self.status() == Some(StatusCode::FORBIDDEN)
    }

    /// True when the request was rejected by validation, whether locally or by the API.
    pub fn is_validation(&self) -> bool {
        matches!(self, Self::Invalid(_)) || self.status() == Some(StatusCode::BAD_REQUEST)
    }

    /// True for both local and remote rate limiting.
    pub fn is_rate_limited(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::RateLimitWouldBlock { .. }
        )
    }

    /// The server's error document, when there was one.
    pub fn api_error(&self) -> Option<&ApiError> {
        match self {
            Self::Api { body, .. } | Self::RateLimited { body, .. } => Some(body),
            _ => None,
        }
    }
}

/// A value rejected by client-side validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {field}: {reason} (got {value:?})")]
pub struct InvalidValue {
    /// Which field or type rejected the value.
    pub field: &'static str,
    /// Why it was rejected.
    pub reason: &'static str,
    /// The offending value.
    pub value: String,
}

/// Rejects the values that `url` collapses instead of encoding as a path segment.
///
/// `url::PathSegmentsMut::push` silently drops `.` and `..`, and an empty segment folds
/// away too, so `domains().delete("..")` would address the collection rather than an
/// item. Nothing else needs escaping: `push` percent-encodes `/` and `%`.
pub(crate) fn check_path_segment(field: &'static str, value: &str) -> Result<(), InvalidValue> {
    if matches!(value, "" | "." | "..") {
        return Err(InvalidValue::new(
            field,
            "is not addressable as a path segment",
            value,
        ));
    }
    Ok(())
}

impl InvalidValue {
    pub(crate) fn new(field: &'static str, reason: &'static str, value: impl Into<String>) -> Self {
        Self {
            field,
            reason,
            value: value.into(),
        }
    }
}

/// The body of an error response, with its structure preserved.
///
/// deSEC is a Django REST Framework application, so an error body is one of a handful
/// of shapes: a bare `detail` message, a map from field name to messages, a map nested
/// one or more levels deep, or — for bulk RRset writes — a positional array with one
/// entry per submitted item and an empty object where that item validated.
///
/// Keeping the tree means a caller can ask which field of which bulk item failed, which
/// is exactly what gets lost when an error body is flattened to a `String`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct ApiError(pub ErrorDetail);

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Indices are meaningful at the root, where a list is the positional bulk array.
        self.0.render(f, true)
    }
}

impl ApiError {
    /// Parses an error body, falling back to the raw text when it is not JSON.
    ///
    /// Public so that an error document obtained some other way — a log line, a webhook
    /// payload — can be inspected with the same accessors.
    pub fn parse(body: &str) -> Self {
        match serde_json::from_str::<ErrorDetail>(body) {
            Ok(detail) => Self(detail),
            // Django's own 500 pages and any proxy in front of the API answer with HTML.
            Err(_) if body.trim().is_empty() => Self(ErrorDetail::Message(String::new())),
            Err(_) => Self(ErrorDetail::Message(truncate(body, 2048))),
        }
    }

    /// The `detail` message, for the shape DRF uses for non-field errors.
    pub fn detail(&self) -> Option<&str> {
        match &self.0 {
            ErrorDetail::Message(m) => Some(m),
            ErrorDetail::Map(m) => match m.get("detail")? {
                ErrorDetail::Message(m) => Some(m),
                _ => None,
            },
            ErrorDetail::List(_) => None,
        }
    }

    /// Messages recorded against `non_field_errors`.
    ///
    /// This is where the API reports constraints that span fields, such as trying to
    /// create a second default token policy.
    pub fn non_field_errors(&self) -> Vec<&str> {
        self.field("non_field_errors")
            .map(ErrorDetail::messages)
            .unwrap_or_default()
    }

    /// The sub-tree recorded against one field name.
    pub fn field(&self, name: &str) -> Option<&ErrorDetail> {
        match &self.0 {
            ErrorDetail::Map(m) => m.get(name),
            _ => None,
        }
    }

    /// The per-item error documents of a failed bulk RRset write, in submission order.
    ///
    /// Items that validated are present as empty maps, so the indices line up with the
    /// request. Returns `None` when the body was not an array.
    pub fn bulk_items(&self) -> Option<&[ErrorDetail]> {
        match &self.0 {
            ErrorDetail::List(items) => Some(items),
            _ => None,
        }
    }

    /// Every message in the document, each paired with its dotted path.
    ///
    /// Paths look like `records`, `captcha.solution`, or `1.ttl` for the second item of
    /// a bulk write. A bare `detail` message has the path `detail`.
    pub fn messages(&self) -> Vec<(String, &str)> {
        let mut out = Vec::new();
        self.0.walk(&mut String::new(), &mut out, true);
        out
    }
}

/// One node of an error document.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(untagged)]
pub enum ErrorDetail {
    /// A single message.
    Message(String),
    /// An ordered list: DRF's per-field message arrays, and bulk positional arrays.
    List(Vec<ErrorDetail>),
    /// A map from field name to nested detail.
    Map(BTreeMap<String, ErrorDetail>),
}

impl ErrorDetail {
    /// The leaf messages under this node, depth first.
    pub fn messages(&self) -> Vec<&str> {
        match self {
            Self::Message(m) => vec![m.as_str()],
            Self::List(items) => items.iter().flat_map(Self::messages).collect(),
            Self::Map(m) => m.values().flat_map(Self::messages).collect(),
        }
    }

    /// Collects `(path, message)` pairs.
    ///
    /// `index_list` distinguishes the two kinds of array DRF produces. At the root, a list
    /// is the positional bulk array and its index identifies which submitted item failed,
    /// so it belongs in the path. Anywhere else a list is just a field's message array,
    /// where the index carries no information and only adds noise.
    fn walk<'a>(&'a self, path: &mut String, out: &mut Vec<(String, &'a str)>, index_list: bool) {
        match self {
            Self::Message(m) => out.push((path.clone(), m.as_str())),
            Self::List(items) => {
                for (i, item) in items.iter().enumerate() {
                    if index_list {
                        let restore = push_segment(path, &i.to_string());
                        item.walk(path, out, false);
                        path.truncate(restore);
                    } else {
                        item.walk(path, out, false);
                    }
                }
            }
            Self::Map(map) => {
                for (key, value) in map {
                    let restore = push_segment(path, key);
                    value.walk(path, out, false);
                    path.truncate(restore);
                }
            }
        }
    }

    fn render(&self, f: &mut fmt::Formatter<'_>, index_list: bool) -> fmt::Result {
        let mut messages = Vec::new();
        self.walk(&mut String::new(), &mut messages, index_list);
        match messages.as_slice() {
            [] => f.write_str("(no detail)"),
            [(path, msg)] if path.is_empty() || path == "detail" => f.write_str(msg),
            _ => {
                let mut first = true;
                for (path, msg) in &messages {
                    if !first {
                        f.write_str("; ")?;
                    }
                    first = false;
                    if path.is_empty() {
                        f.write_str(msg)?;
                    } else {
                        write!(f, "{path}: {msg}")?;
                    }
                }
                Ok(())
            }
        }
    }
}

impl fmt::Display for ErrorDetail {
    /// Renders a sub-tree. Unlike [`ApiError`], list indices are left out: a node reached
    /// through [`ApiError::field`] is below the root, so any list under it is a message
    /// array rather than the positional bulk array.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.render(f, false)
    }
}

/// Appends `segment` to a dotted path, returning the length to truncate back to.
fn push_segment(path: &mut String, segment: &str) -> usize {
    let restore = path.len();
    if !path.is_empty() {
        path.push('.');
    }
    path.push_str(segment);
    restore
}

/// Truncates on a character boundary, so error text from an unexpected body cannot
/// panic the formatter.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_detail_body() {
        let err = ApiError::parse(r#"{"detail":"Not found."}"#);
        assert_eq!(err.detail(), Some("Not found."));
        assert_eq!(err.to_string(), "Not found.");
    }

    #[test]
    fn parses_field_keyed_errors() {
        let err = ApiError::parse(r#"{"ttl":["Ensure this value is greater than 3600."]}"#);
        assert_eq!(
            err.field("ttl").map(ErrorDetail::messages),
            Some(vec!["Ensure this value is greater than 3600."])
        );
    }

    #[test]
    fn parses_nested_field_errors() {
        let err = ApiError::parse(r#"{"captcha":{"solution":["Invalid captcha."]}}"#);
        assert_eq!(
            err.messages(),
            vec![("captcha.solution".to_owned(), "Invalid captcha.")]
        );
    }

    #[test]
    fn parses_non_field_errors() {
        let body = r#"{"non_field_errors":["Cannot create multiple default policies."]}"#;
        let err = ApiError::parse(body);
        assert_eq!(
            err.non_field_errors(),
            vec!["Cannot create multiple default policies."]
        );
    }

    #[test]
    fn keeps_bulk_item_positions() {
        let err = ApiError::parse(r#"[{},{"records":["Invalid record."]},{}]"#);
        let items = err.bulk_items().expect("body is an array");
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].messages(), Vec::<&str>::new());
        assert_eq!(items[1].messages(), vec!["Invalid record."]);
        assert_eq!(
            err.messages(),
            vec![("1.records".to_owned(), "Invalid record.")]
        );
    }

    #[test]
    fn falls_back_to_raw_text_for_non_json() {
        let err = ApiError::parse("<html>502 Bad Gateway</html>");
        assert_eq!(err.detail(), Some("<html>502 Bad Gateway</html>"));
    }

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate("æææ", 3), "æ…");
    }
}
