//! Types shared across the API surface.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::InvalidValue;

/// The label part of an RRset name, relative to the zone.
///
/// The API spells the zone apex two different ways: `""` in a JSON payload, and `@` in a
/// URL path. They are not interchangeable — an empty path segment collapses under HTTP
/// path normalization, so `/rrsets//A/` does not reach the apex — and since the API
/// *returns* `""`, code that round-trips an RRset has to translate rather than
/// substitute. That translation is this type's whole reason for existing:
/// [`as_payload`](Self::as_payload) for bodies, [`as_path`](Self::as_path) for URLs.
///
/// ```
/// use desec::Subname;
///
/// let apex = Subname::apex();
/// assert_eq!(apex.as_payload(), "");
/// assert_eq!(apex.as_path(), "@");
///
/// let www: Subname = "www".parse()?;
/// assert_eq!(www.as_payload(), "www");
/// assert_eq!(www.as_path(), "www");
/// # Ok::<_, desec::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Subname(String);

impl Subname {
    /// Longest subname the API accepts.
    pub const MAX_LEN: usize = 178;

    /// The zone apex.
    pub const fn apex() -> Self {
        Self(String::new())
    }

    /// Validates and wraps a subname.
    ///
    /// Accepts `""` and `"@"` as the apex, so a value read from either a payload or a
    /// path can be passed straight in.
    pub fn new(subname: impl Into<String>) -> Result<Self, InvalidValue> {
        let subname = subname.into();
        if subname.is_empty() || subname == "@" {
            return Ok(Self::apex());
        }

        let invalid = |reason| Err(InvalidValue::new("subname", reason, subname.clone()));

        if subname.len() > Self::MAX_LEN {
            return invalid("longer than 178 characters");
        }

        // A wildcard is only meaningful as the leftmost label.
        let labels = subname.strip_prefix("*.").unwrap_or(&subname);
        if subname == "*" {
            return Ok(Self(subname));
        }
        if labels.contains('*') {
            return invalid("wildcard `*` is only allowed as the leftmost label");
        }
        if labels.is_empty() {
            return invalid("empty label");
        }
        if !labels
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return invalid("may only contain letters, digits, `-`, `_` and `.`");
        }
        if labels.starts_with('.') || labels.ends_with('.') || labels.contains("..") {
            return invalid("empty label");
        }

        Ok(Self(subname))
    }

    /// The spelling to put in a JSON body: `""` at the apex.
    pub fn as_payload(&self) -> &str {
        &self.0
    }

    /// The spelling to put in a URL path segment: `@` at the apex.
    pub fn as_path(&self) -> &str {
        if self.0.is_empty() { "@" } else { &self.0 }
    }

    /// Whether this is the zone apex.
    pub fn is_apex(&self) -> bool {
        self.0.is_empty()
    }
}

impl FromStr for Subname {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl fmt::Display for Subname {
    /// Renders the payload spelling, so the apex formats as the empty string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Subname {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_payload())
    }
}

impl<'de> Deserialize<'de> for Subname {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// A DNS record type.
///
/// Deliberately non-exhaustive over the wire: unknown mnemonics deserialize into
/// [`RecordType::Other`] rather than failing, so a record type added upstream does not
/// break a client that has not been rebuilt.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
#[allow(missing_docs, clippy::upper_case_acronyms)]
pub enum RecordType {
    A,
    AAAA,
    AFSDB,
    APL,
    CAA,
    CDNSKEY,
    CDS,
    CERT,
    CNAME,
    DHCID,
    DLV,
    DNAME,
    DNSKEY,
    DS,
    EUI48,
    EUI64,
    HINFO,
    HTTPS,
    KX,
    L32,
    L64,
    LOC,
    LP,
    MX,
    NAPTR,
    NID,
    NS,
    NSEC3PARAM,
    OPENPGPKEY,
    PTR,
    RP,
    RRSIG,
    SMIMEA,
    SOA,
    SPF,
    SRV,
    SSHFP,
    SVCB,
    TLSA,
    TXT,
    URI,
    /// A type this crate does not name. Held uppercased, as the API requires.
    Other(String),
}

impl RecordType {
    /// The mnemonic, uppercase.
    pub fn as_str(&self) -> &str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::AFSDB => "AFSDB",
            Self::APL => "APL",
            Self::CAA => "CAA",
            Self::CDNSKEY => "CDNSKEY",
            Self::CDS => "CDS",
            Self::CERT => "CERT",
            Self::CNAME => "CNAME",
            Self::DHCID => "DHCID",
            Self::DLV => "DLV",
            Self::DNAME => "DNAME",
            Self::DNSKEY => "DNSKEY",
            Self::DS => "DS",
            Self::EUI48 => "EUI48",
            Self::EUI64 => "EUI64",
            Self::HINFO => "HINFO",
            Self::HTTPS => "HTTPS",
            Self::KX => "KX",
            Self::L32 => "L32",
            Self::L64 => "L64",
            Self::LOC => "LOC",
            Self::LP => "LP",
            Self::MX => "MX",
            Self::NAPTR => "NAPTR",
            Self::NID => "NID",
            Self::NS => "NS",
            Self::NSEC3PARAM => "NSEC3PARAM",
            Self::OPENPGPKEY => "OPENPGPKEY",
            Self::PTR => "PTR",
            Self::RP => "RP",
            Self::RRSIG => "RRSIG",
            Self::SMIMEA => "SMIMEA",
            Self::SOA => "SOA",
            Self::SPF => "SPF",
            Self::SRV => "SRV",
            Self::SSHFP => "SSHFP",
            Self::SVCB => "SVCB",
            Self::TLSA => "TLSA",
            Self::TXT => "TXT",
            Self::URI => "URI",
            Self::Other(s) => s,
        }
    }

    /// Whether deSEC signs and serves this type itself, making it read-only *at the zone
    /// apex*.
    ///
    /// `DS` is the reason this is qualified: at the apex it belongs to the parent zone
    /// and deSEC manages it, but at a subname it is an ordinary delegation record that
    /// callers write. `DNSKEY`, `CDNSKEY` and `CDS` may additionally be written by hand
    /// to support multi-signer setups. So this is a hint for surfacing a likely mistake
    /// early, not a rule the client enforces.
    pub fn is_dnssec_managed(&self) -> bool {
        matches!(
            self,
            Self::CDNSKEY
                | Self::CDS
                | Self::DNSKEY
                | Self::DS
                | Self::NSEC3PARAM
                | Self::RRSIG
                | Self::SOA
        )
    }
}

impl FromStr for RecordType {
    type Err = InvalidValue;

    /// Parses a mnemonic case-insensitively. Unknown mnemonics become
    /// [`RecordType::Other`]; only a non-alphanumeric mnemonic is rejected.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.to_ascii_uppercase();
        Ok(match upper.as_str() {
            "A" => Self::A,
            "AAAA" => Self::AAAA,
            "AFSDB" => Self::AFSDB,
            "APL" => Self::APL,
            "CAA" => Self::CAA,
            "CDNSKEY" => Self::CDNSKEY,
            "CDS" => Self::CDS,
            "CERT" => Self::CERT,
            "CNAME" => Self::CNAME,
            "DHCID" => Self::DHCID,
            "DLV" => Self::DLV,
            "DNAME" => Self::DNAME,
            "DNSKEY" => Self::DNSKEY,
            "DS" => Self::DS,
            "EUI48" => Self::EUI48,
            "EUI64" => Self::EUI64,
            "HINFO" => Self::HINFO,
            "HTTPS" => Self::HTTPS,
            "KX" => Self::KX,
            "L32" => Self::L32,
            "L64" => Self::L64,
            "LOC" => Self::LOC,
            "LP" => Self::LP,
            "MX" => Self::MX,
            "NAPTR" => Self::NAPTR,
            "NID" => Self::NID,
            "NS" => Self::NS,
            "NSEC3PARAM" => Self::NSEC3PARAM,
            "OPENPGPKEY" => Self::OPENPGPKEY,
            "PTR" => Self::PTR,
            "RP" => Self::RP,
            "RRSIG" => Self::RRSIG,
            "SMIMEA" => Self::SMIMEA,
            "SOA" => Self::SOA,
            "SPF" => Self::SPF,
            "SRV" => Self::SRV,
            "SSHFP" => Self::SSHFP,
            "SVCB" => Self::SVCB,
            "TLSA" => Self::TLSA,
            "TXT" => Self::TXT,
            "URI" => Self::URI,
            "" => {
                return Err(InvalidValue::new(
                    "type",
                    "record type must not be empty",
                    s,
                ));
            }
            other => {
                if !other.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return Err(InvalidValue::new(
                        "type",
                        "record type must be alphanumeric",
                        s,
                    ));
                }
                Self::Other(upper)
            }
        })
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for RecordType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RecordType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

/// A duration in the format Django serializes, used by a token's `max_age` and
/// `max_unused_period`.
///
/// The wire format is `[DD ][HH:[MM:]]ss[.uuuuuu]`, so `7 00:00:00` is a week and
/// `01:00:00` is an hour. Sub-second precision is microseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DjangoDuration(Duration);

impl DjangoDuration {
    /// Wraps a [`Duration`].
    pub const fn new(duration: Duration) -> Self {
        Self(duration)
    }

    /// The wrapped [`Duration`].
    pub const fn get(self) -> Duration {
        self.0
    }

    /// Convenience for whole days.
    pub const fn days(days: u64) -> Self {
        Self(Duration::from_secs(days * 86_400))
    }

    /// Convenience for whole hours.
    pub const fn hours(hours: u64) -> Self {
        Self(Duration::from_secs(hours * 3_600))
    }
}

impl From<Duration> for DjangoDuration {
    fn from(duration: Duration) -> Self {
        Self(duration)
    }
}

impl From<DjangoDuration> for Duration {
    fn from(duration: DjangoDuration) -> Self {
        duration.0
    }
}

impl FromStr for DjangoDuration {
    type Err = InvalidValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidValue::new("duration", "expected `[DD ][HH:[MM:]]ss[.uuuuuu]`", s);

        let (days, clock) = match s.trim().split_once(' ') {
            Some((days, rest)) => (days.trim().parse::<u64>().map_err(|_| invalid())?, rest),
            None => (0, s.trim()),
        };

        // Right-to-left, so a bare `ss` and a full `HH:MM:SS` share one path.
        let mut secs = 0u64;
        let mut nanos = 0u32;
        for (i, part) in clock.rsplit(':').enumerate() {
            let scale = match i {
                0 => 1,
                1 => 60,
                2 => 3_600,
                _ => return Err(invalid()),
            };
            let value: u64 = if i == 0 {
                let (whole, frac) = match part.split_once('.') {
                    Some((whole, frac)) => (whole, Some(frac)),
                    None => (part, None),
                };
                if let Some(frac) = frac {
                    // Django emits exactly six digits, but pad or clip so any precision
                    // round-trips rather than erroring.
                    let mut digits = frac.to_owned();
                    digits.truncate(9);
                    while digits.len() < 9 {
                        digits.push('0');
                    }
                    nanos = digits.parse().map_err(|_| invalid())?;
                }
                whole.parse().map_err(|_| invalid())?
            } else {
                part.parse().map_err(|_| invalid())?
            };
            // Checked throughout: this parses a server response, so an absurd value must
            // be an error rather than a debug panic and a release wraparound.
            secs = value
                .checked_mul(scale)
                .and_then(|scaled| secs.checked_add(scaled))
                .ok_or_else(invalid)?;
        }

        let total = days
            .checked_mul(86_400)
            .and_then(|days| secs.checked_add(days))
            .ok_or_else(invalid)?;
        Ok(Self(Duration::new(total, nanos)))
    }
}

impl fmt::Display for DjangoDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total = self.0.as_secs();
        let (days, rest) = (total / 86_400, total % 86_400);
        let (hours, minutes, seconds) = (rest / 3_600, (rest % 3_600) / 60, rest % 60);

        if days > 0 {
            write!(f, "{days} ")?;
        }
        write!(f, "{hours:02}:{minutes:02}:{seconds:02}")?;

        let micros = self.0.subsec_micros();
        if micros > 0 {
            write!(f, ".{micros:06}")?;
        }
        Ok(())
    }
}

impl Serialize for DjangoDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DjangoDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apex_uses_a_different_spelling_per_position() {
        let apex = Subname::apex();
        assert_eq!(apex.as_payload(), "");
        assert_eq!(apex.as_path(), "@");
        assert!(apex.is_apex());
    }

    /// The bug this type exists to prevent: the API returns `""`, the URL needs `@`.
    #[test]
    fn apex_round_trips_from_a_payload_to_a_path() {
        let from_api: Subname = serde_json::from_str(r#""""#).expect("empty string is the apex");
        assert!(from_api.is_apex());
        assert_eq!(from_api.as_path(), "@");
        assert_eq!(
            serde_json::to_string(&from_api).expect("serializes"),
            r#""""#
        );
    }

    #[test]
    fn accepts_at_sign_as_the_apex() {
        assert!(Subname::new("@").expect("@ is the apex").is_apex());
    }

    #[test]
    fn accepts_valid_subnames() {
        for name in [
            "www",
            "a-b",
            "_dmarc",
            "deep.sub.name",
            "*",
            "*.wild",
            "_443._tcp.www",
        ] {
            assert!(Subname::new(name).is_ok(), "{name} should be valid");
        }
    }

    #[test]
    fn rejects_invalid_subnames() {
        for name in [
            "wild*", "a*.b", "a..b", ".lead", "trail.", "sp ace", "sla/sh",
        ] {
            assert!(Subname::new(name).is_err(), "{name} should be rejected");
        }
        assert!(Subname::new("a".repeat(179)).is_err(), "too long");
        assert!(Subname::new("a".repeat(178)).is_ok(), "at the limit");
    }

    #[test]
    fn record_types_round_trip() {
        for name in ["A", "AAAA", "TXT", "SSHFP", "OPENPGPKEY", "SVCB"] {
            let parsed: RecordType = name.parse().expect("known type");
            assert_eq!(parsed.as_str(), name);
        }
    }

    #[test]
    fn record_types_are_case_insensitive_and_normalize_up() {
        assert_eq!(
            "aaaa".parse::<RecordType>().expect("parses"),
            RecordType::AAAA
        );
    }

    /// A type added upstream must not break deserialization of an existing zone.
    #[test]
    fn unknown_record_types_survive() {
        let parsed: RecordType = "WALLET".parse().expect("unknown but well-formed");
        assert_eq!(parsed, RecordType::Other("WALLET".to_owned()));
        assert_eq!(parsed.as_str(), "WALLET");
    }

    #[test]
    fn rejects_nonsense_record_types() {
        assert!("".parse::<RecordType>().is_err());
        assert!("A/B".parse::<RecordType>().is_err());
    }

    #[test]
    fn ds_is_writable_at_a_subname_but_flagged_as_managed() {
        // The flag is apex-scoped advice; the crate must not block delegation records.
        assert!(RecordType::DS.is_dnssec_managed());
        assert!(!RecordType::A.is_dnssec_managed());
    }

    #[test]
    fn parses_django_durations() {
        let week: DjangoDuration = "7 00:00:00".parse().expect("a week");
        assert_eq!(week.get(), Duration::from_secs(7 * 86_400));

        let hour: DjangoDuration = "01:00:00".parse().expect("an hour");
        assert_eq!(hour.get(), Duration::from_secs(3_600));

        let fractional: DjangoDuration = "00:00:01.500000".parse().expect("with micros");
        assert_eq!(fractional.get(), Duration::from_millis(1_500));

        let bare: DjangoDuration = "30".parse().expect("bare seconds");
        assert_eq!(bare.get(), Duration::from_secs(30));
    }

    #[test]
    fn django_durations_round_trip_through_display() {
        for spec in ["7 00:00:00", "01:00:00", "00:00:30", "1 02:03:04"] {
            let parsed: DjangoDuration = spec.parse().expect("parses");
            assert_eq!(parsed.to_string(), spec);
        }
    }

    #[test]
    fn rejects_malformed_durations() {
        for spec in ["", "abc", "1:2:3:4", "x 00:00:00"] {
            assert!(spec.parse::<DjangoDuration>().is_err(), "{spec}");
        }
    }

    /// Reachable from a server response, so an out-of-range value has to be an error
    /// rather than a debug panic and a silent release wraparound.
    #[test]
    fn rejects_durations_that_overflow_rather_than_wrapping() {
        for spec in [
            "999999999999999999 00:00:00",
            "18446744073709551615:00:00",
            "1:18446744073709551615:00",
        ] {
            assert!(spec.parse::<DjangoDuration>().is_err(), "{spec}");
        }
        // A bare second count that fits in u64 is a valid, if absurd, duration; it never
        // reaches the clock arithmetic that would make it dangerous.
        assert!("18446744073709551615".parse::<DjangoDuration>().is_ok());
    }
}
