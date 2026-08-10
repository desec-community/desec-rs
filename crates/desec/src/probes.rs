//! Probe values for characterizing deSEC's record canonicalization.
//!
//! deSEC rewrites record values on storage, per type:
//!
//! > Record values that are not given in canonical form, such as `0:0000::1` for an IPv6
//! > address, will be converted by the API into canonical form (here: `::1`). [...] exact
//! > validation and canonicalization depend on the record type.
//!
//! Which values, and into what, is not documented beyond that example. This table is the
//! question, and [`Expect`] is where the answer gets written down once a live run has
//! produced it. `tests/live.rs` sends every probe to a scratch zone, reads it back, and
//! reports; a human promotes each row from [`Expect::Unknown`] and commits.
//!
//! It lives in `src/` rather than `tests/` because a second consumer needs it: the
//! external-dns webhook compares desired records against stored records byte for byte, so
//! every axis deSEC rewrites and the webhook does not is a write that repeats every
//! reconcile cycle. Hidden and feature-gated, because it is shared research data rather
//! than API surface.
//!
//! Enable with the `probes` feature. Deliberately not part of `default`.
//!
//! # What deSEC turned out to rewrite
//!
//! From the first full run, 2026-08-10. Every value in the table was accepted; nothing was
//! refused, including `SPF`, and including a `DS` at a subname with no delegation beside it.
//!
//! - **Domain names keep their case.** `CNAME`, `MX`, `SRV`, `NS`, `PTR`, `NAPTR` and
//!   `HTTPS` all store `Example.ORG.` unchanged, and no field is respaced.
//! - **Hex digests lowercase.** `DS`, `TLSA` and `SSHFP`.
//! - **`AAAA` recompresses, and diverges from a stock renderer on exactly one form.** An
//!   ordinary address matches Rust's `Ipv6Addr::to_string()` — `2001:0DB8:…:0001` becomes
//!   `2001:db8::1` on both sides — and so does the deprecated IPv4-*compatible* form, which
//!   Rust also renders as hex (`::192.0.2.1` → `::c000:201`). The IPv4-*mapped* form is the
//!   exception: deSEC stores `::ffff:192.0.2.1` as `::ffff:c000:201`, where both Rust and
//!   Go's `netip.Addr` keep the dotted quad. So a normalizer built on either would be right
//!   everywhere except the one embedded-IPv4 form anything modern actually emits.
//! - **`TXT` splits at 255, and preserves chunking it was given.** A 300-character value
//!   comes back as two character-strings inside one presentation value; `"already"
//!   "chunked"` comes back exactly as sent. Escapes, including `\DDD`, survive.
//! - **`CAA` keeps its tag case.** `0 ISSUE "…"` is not folded to `issue`.
//! - **`LOC` is lossy.** Seconds gain `.000`, minutes lose a leading zero, and every
//!   distance gains `.00` — but size is a mantissa-and-exponent byte, so `33m` becomes
//!   `30.00m`. `loc-format` and `loc-quantized` differ only in that field and come back
//!   identical. No string rewriting can reproduce that; only the server knows.
//! - **`SVCB` and `HTTPS` reorder parameters into key order and drop quoting.**
//!   `port=443 alpn=h2,h3` becomes `alpn=h2,h3 port=443`, `alpn="h3,h2"` loses its quotes,
//!   and an `ipv6hint` is compressed like an `AAAA`.
//!
//! Which of these actually cost a consumer anything depends on what sits between it and the
//! source. For the external-dns webhook, hex case and `AAAA` are absorbed by external-dns's
//! own `Targets.Same` (case-insensitive, with a `netip.ParseAddr` fallback), and the `TXT`
//! split is absorbed by rejoining chunks on egress. `LOC`, `SVCB` and `HTTPS` are not
//! absorbed by anything, and `LOC` cannot be, which is what makes remembering the value that
//! was written the general answer rather than reproducing the server's rules.

/// What deSEC does with a probe's value.
///
/// Every probe starts as [`Unknown`](Expect::Unknown). The live run reports those and
/// passes; promoting one is a source change with a commit message, which is the point.
/// There is deliberately no `UPDATE_GOLDEN=1`: auto-accepting a snapshot of a live
/// third-party service blesses whatever it returned during a bad deploy, with no review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Stored byte for byte as submitted.
    Verbatim,
    /// Rewritten, to exactly this.
    Canonical(&'static str),
    /// Refused. The string is deSEC's own message, which is the evidence.
    Rejected(&'static str),
    /// Not yet run against the API.
    Unknown,
}

/// One value to send, and what is known about what comes back.
#[derive(Debug, Clone)]
pub struct Probe {
    /// Stable identifier, shared with downstream consumers' own tables so the two can be
    /// compared by name. Never reuse one for a different value.
    pub id: &'static str,

    /// Where to put it. Every probe gets its own subname, so that no probe can invalidate
    /// another through a whole-zone rule such as CNAME coexistence — which matters because
    /// a bulk write is atomic, and only per-item failures are positional and therefore
    /// attributable. `NS` and `DS` are the one exception, below.
    pub subname: &'static str,

    /// Record type mnemonic. A `&str` rather than a [`RecordType`](crate::RecordType) so
    /// the table can be a `const`: `RecordType::Other` holds a `String`, which has drop
    /// glue, and a `const` slice of values with drop glue cannot be promoted to `'static`.
    pub record_type: &'static str,

    /// The value to submit, in deSEC's presentation format: domain names qualified, text
    /// types quoted.
    pub wire: &'static str,

    /// What the API is known to do with `wire`.
    pub expect: Expect,

    /// Why this probe exists, and what the run found. Printed in the live run's report.
    pub note: &'static str,
}

/// 300 characters, past the 255-byte limit on a single character-string, so deSEC has to
/// split it. Written as five 60-character runs of a repeating decade, which makes the split
/// point legible in the report: it lands 25 groups and a half in.
const TXT_300: &str = concat!(
    '"',
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    '"',
);

/// What [`TXT_300`] comes back as: the same 300 characters, cut at exactly 255 into two
/// character-strings, both inside a single presentation value. One record, not two.
const TXT_300_SPLIT: &str = concat!(
    '"',
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234567890123456789012345678901234567890123456789",
    "012345678901234",
    "\" \"",
    "567890123456789012345678901234567890123456789",
    '"',
);

/// Every probe.
///
/// Nothing here sits at the zone apex: `SOA`, apex `NS`, `DNSKEY`, `RRSIG`, `NSEC3PARAM`,
/// `CDS` and `CDNSKEY` are deSEC's to write and it refuses ours. `NS` and `DS` **at a
/// subname** are the opposite case — ordinary delegation records a caller owns — and they
/// share the subname `deleg` on purpose, because that is the shape a real delegation has.
/// A `DS` there turned out not to need the `NS` beside it, but the pairing is still the
/// realistic shape.
///
/// Values use the documentation ranges: `192.0.2.0/24`, `2001:db8::/32`, `example.org`.
pub const PROBES: &[Probe] = &[
    Probe {
        id: "a-control",
        subname: "a",
        record_type: "A",
        wire: "192.0.2.1",
        expect: Expect::Verbatim,
        note: "The control. A difference here means the harness is wrong, not deSEC.",
    },
    Probe {
        id: "aaaa-expanded",
        subname: "aaaa",
        record_type: "AAAA",
        wire: "2001:0DB8:0000:0000:0000:0000:0000:0001",
        expect: Expect::Canonical("2001:db8::1"),
        note: "Zero-compression and hex case, the axis deSEC's own docs give as the example. \
               Compressed and lowercased, as documented.",
    },
    Probe {
        id: "aaaa-v4mapped-dotted",
        subname: "aaaa-v4m",
        record_type: "AAAA",
        wire: "::ffff:192.0.2.1",
        expect: Expect::Canonical("::ffff:c000:201"),
        note: "The surprise of the set. deSEC renders an embedded IPv4 address as hex, where \
               Rust's Ipv6Addr, Go's netip.Addr and dnspython all render it dotted — so a \
               consumer normalizing with any of the three still disagrees with storage.",
    },
    Probe {
        id: "aaaa-v4mapped-hex",
        subname: "aaaa-v4h",
        record_type: "AAAA",
        wire: "::ffff:c000:0201",
        expect: Expect::Canonical("::ffff:c000:201"),
        note: "The same address as aaaa-v4mapped-dotted, written as hex. Both come back \
               identical, which is what makes the hex form the server's choice rather than \
               an inference from one sample.",
    },
    Probe {
        id: "aaaa-v4compat-dotted",
        subname: "aaaa-v4c",
        record_type: "AAAA",
        wire: "::192.0.2.1",
        expect: Expect::Canonical("::c000:201"),
        note: "IPv4-compatible, deprecated by RFC 4291. Accepted, and rendered as hex — which \
               is also what Rust's Ipv6Addr does, so this form is the one embedded-IPv4 case \
               where a stock renderer already agrees with storage.",
    },
    Probe {
        id: "cname-case",
        subname: "cname",
        record_type: "CNAME",
        wire: "Alias.Example.ORG.",
        expect: Expect::Verbatim,
        note: "Names are stored with the case they were given. Nothing case-folds them, so a \
               consumer that lowercases on both sides of its own comparison is doing the \
               right thing for its own reasons, not matching the server.",
    },
    Probe {
        id: "mx-case",
        subname: "mx",
        record_type: "MX",
        wire: "10 Mail.Example.ORG.",
        expect: Expect::Verbatim,
        note: "Name case survives and the preference field is not respaced.",
    },
    Probe {
        id: "srv-name",
        subname: "_sip._tcp.srv",
        record_type: "SRV",
        wire: "10 20 5060 Sip.Example.ORG.",
        expect: Expect::Verbatim,
        note: "The name is field 3, so a consumer that dots field 0 corrupts this. Untouched.",
    },
    Probe {
        id: "ns-sub",
        subname: "deleg",
        record_type: "NS",
        wire: "Ns1.Example.ORG.",
        expect: Expect::Verbatim,
        note: "A delegation at a subname, which a caller owns. Only apex NS is deSEC's.",
    },
    Probe {
        id: "ds-sub",
        subname: "deleg",
        record_type: "DS",
        // Key tag, algorithm 13 (ECDSAP256SHA256), digest type 2 (SHA-256), 64 hex.
        wire: "12345 13 2 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B",
        expect: Expect::Canonical(
            "12345 13 2 3a5b7c9d1e2f4a6b8c0d2e4f6a8b0c1d3e5f7a9b1c3d5e7f9a0b2c4d6e8f0a1b",
        ),
        note: "Digests lowercase. A byte-for-byte comparison differs; a case-insensitive one \
               does not, which is why this costs external-dns consumers nothing.",
    },
    Probe {
        id: "ptr-case",
        subname: "ptr",
        record_type: "PTR",
        wire: "Host.Example.ORG.",
        expect: Expect::Verbatim,
        note: "Name at field 0. Untouched.",
    },
    Probe {
        id: "txt-long",
        subname: "txt-long",
        record_type: "TXT",
        wire: TXT_300,
        expect: Expect::Canonical(TXT_300_SPLIT),
        note: "Split at exactly 255, into two character-strings inside one presentation value \
               — one record, not two. A consumer that rejoins chunks when reading sees the \
               value it sent; one that compares presentation forms does not.",
    },
    Probe {
        id: "txt-escapes",
        subname: "txt-esc",
        record_type: "TXT",
        wire: r#""has \"quotes\" and \\ backslash and unicode: \195\188""#,
        expect: Expect::Verbatim,
        note: "Escapes survive exactly, including \\DDD octets. Nothing re-escapes or \
               re-encodes, so a consumer's own escaping is the only thing that has to agree \
               with itself.",
    },
    Probe {
        id: "txt-prechunked",
        subname: "txt-multi",
        record_type: "TXT",
        wire: r#""already" "chunked""#,
        expect: Expect::Verbatim,
        note: "An author's own chunking survives untouched. Combined with txt-long: deSEC \
               splits only when it has to, and never re-chunks what already fits.",
    },
    Probe {
        id: "spf-quoted",
        subname: "spf",
        record_type: "SPF",
        wire: r#""v=spf1 include:_spf.example.org -all""#,
        expect: Expect::Verbatim,
        note: "Accepted despite the type being obsolete, and stored as given.",
    },
    Probe {
        id: "caa-tag-case",
        subname: "caa",
        record_type: "CAA",
        wire: r#"0 ISSUE "letsencrypt.org""#,
        expect: Expect::Verbatim,
        note: "The tag keeps its case; it is not folded to `issue`. Nothing to reproduce.",
    },
    Probe {
        id: "naptr-flag-case",
        subname: "naptr",
        record_type: "NAPTR",
        wire: r#"100 10 "S" "SIP+D2U" "" _sip._udp.Example.ORG."#,
        expect: Expect::Verbatim,
        note: "Flags, service and the name at field 5 all survive. Note the index only holds \
               while the earlier fields contain no whitespace, which this value respects.",
    },
    Probe {
        id: "tlsa-hex-case",
        subname: "_443._tcp.tlsa",
        record_type: "TLSA",
        // Usage 3, selector 1, matching type 1 (SHA-256), 64 hex.
        wire: "3 1 1 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B1C3D5E7F9A0B2C4D6E8F0A1B",
        expect: Expect::Canonical(
            "3 1 1 3a5b7c9d1e2f4a6b8c0d2e4f6a8b0c1d3e5f7a9b1c3d5e7f9a0b2c4d6e8f0a1b",
        ),
        note: "Lowercased, as ds-sub.",
    },
    Probe {
        id: "sshfp-hex-case",
        subname: "sshfp",
        record_type: "SSHFP",
        // Algorithm 2 (DSA), fingerprint type 1 (SHA-1), 40 hex.
        wire: "2 1 3A5B7C9D1E2F4A6B8C0D2E4F6A8B0C1D3E5F7A9B",
        expect: Expect::Canonical("2 1 3a5b7c9d1e2f4a6b8c0d2e4f6a8b0c1d3e5f7a9b"),
        note: "Lowercased, as ds-sub.",
    },
    Probe {
        id: "uri-target",
        subname: "_http._tcp.uri",
        record_type: "URI",
        wire: r#"10 1 "https://Example.ORG/Path""#,
        expect: Expect::Verbatim,
        note: "Case survives, as it must: a URI path is case-sensitive. Quotes are echoed.",
    },
    Probe {
        id: "loc-format",
        subname: "loc",
        record_type: "LOC",
        wire: "42 21 54 N 71 06 18 W 24m 30m 10m 10m",
        expect: Expect::Canonical("42 21 54.000 N 71 6 18.000 W 24.00m 30.00m 10.00m 10.00m"),
        note: "Reformatted on three axes at once: seconds gain .000, minutes lose a leading \
               zero, distances gain .00. All four defaults are spelled out rather than \
               omitted.",
    },
    Probe {
        id: "loc-quantized",
        subname: "loc2",
        record_type: "LOC",
        wire: "42 21 54 N 71 06 18 W 24m 33m 10m 10m",
        expect: Expect::Canonical("42 21 54.000 N 71 6 18.000 W 24.00m 30.00m 10.00m 10.00m"),
        note: "The strongest result in the table. 33m is not representable — size is a \
               mantissa-and-exponent byte — so it lands on 30.00m, and this row and \
               loc-format come back identical despite differing on input. The rewrite is \
               lossy, so no amount of string normalization can predict it. A consumer has to \
               remember what it wrote, or write again forever.",
    },
    Probe {
        id: "svcb-param-order",
        subname: "svcb",
        record_type: "SVCB",
        wire: "1 svc.Example.ORG. port=443 alpn=h2,h3 ipv6hint=2001:0DB8::1",
        expect: Expect::Canonical("1 svc.Example.ORG. alpn=h2,h3 port=443 ipv6hint=2001:db8::1"),
        note: "Parameters are sorted into key order (alpn=1, port=3, ipv6hint=6) and the hint \
               is compressed like an AAAA. The target name keeps its case. Reproducible in \
               principle, but only by implementing the parameter registry.",
    },
    Probe {
        id: "https-alias",
        subname: "https",
        record_type: "HTTPS",
        wire: "0 Svc.Example.ORG.",
        expect: Expect::Verbatim,
        note: "AliasMode: priority 0, no parameters, nothing to reorder. The control that \
               isolates svcb-param-order's difference to the parameters.",
    },
    Probe {
        id: "https-params",
        subname: "https2",
        record_type: "HTTPS",
        wire: r#"1 . alpn="h3,h2" no-default-alpn ipv4hint=192.0.2.1,192.0.2.2"#,
        expect: Expect::Canonical("1 . alpn=h3,h2 no-default-alpn ipv4hint=192.0.2.1,192.0.2.2"),
        note: "Quoting is dropped from alpn, the valueless parameter is echoed, and the IPv4 \
               hints are left alone. Already in key order, so this isolates the quoting.",
    },
];

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::collections::HashSet;

    fn probe(id: &str) -> &'static Probe {
        PROBES.iter().find(|p| p.id == id).expect("probe exists")
    }

    /// Identifiers are how a consumer's table is matched against this one, so a duplicate
    /// would silently make one of the two unreachable.
    #[test]
    fn probe_ids_are_unique() {
        let mut seen = HashSet::new();
        for probe in PROBES {
            assert!(seen.insert(probe.id), "duplicate probe id {}", probe.id);
        }
    }

    /// A bulk write is atomic, so a probe sharing a subname with another can be refused for
    /// the other's sake and the failure is no longer attributable. `deleg` is the one
    /// deliberate exception, where the pairing is the point.
    #[test]
    fn only_the_delegation_probes_share_a_subname() {
        let mut seen = HashSet::new();
        for probe in PROBES {
            if !seen.insert(probe.subname) {
                assert_eq!(
                    probe.subname, "deleg",
                    "{} shares a subname, which makes bulk failures unattributable",
                    probe.id
                );
            }
        }
    }

    /// Every mnemonic has to round-trip through the type this crate sends on the wire.
    #[test]
    fn every_record_type_parses() {
        for probe in PROBES {
            let parsed: crate::RecordType = probe
                .record_type
                .parse()
                .expect("probe record type is a mnemonic");
            assert_eq!(parsed.as_str(), probe.record_type, "{}", probe.id);
        }
    }

    /// Nothing may sit at the apex: those types are deSEC's own and it refuses ours, which
    /// would fail the whole atomic batch rather than one probe.
    #[test]
    fn no_probe_sits_at_the_apex() {
        for probe in PROBES {
            assert!(!probe.subname.is_empty(), "{} is at the apex", probe.id);
        }
    }

    /// The long TXT probe is only interesting if it is actually over the limit.
    #[test]
    fn the_long_txt_probe_is_past_the_character_string_limit() {
        let payload = TXT_300.trim_matches('"');
        assert_eq!(payload.len(), 300);
        assert!(payload.len() > 255);
    }

    /// The recorded split has to be the same 300 characters, cut rather than altered — and
    /// cut at exactly the limit, which is the fact the probe exists to pin.
    #[test]
    fn the_recorded_split_preserves_the_payload() {
        let sent = TXT_300.trim_matches('"');
        let chunks: Vec<&str> = TXT_300_SPLIT.trim_matches('"').split("\" \"").collect();

        assert_eq!(chunks.len(), 2, "{TXT_300_SPLIT}");
        assert_eq!(
            chunks[0].len(),
            255,
            "deSEC cuts at the character-string limit"
        );
        assert_eq!(
            chunks.concat(),
            sent,
            "the split must not alter the payload"
        );
    }

    /// A digest of the wrong length is refused by the API, and in an atomic bulk write that
    /// takes every other probe down with it.
    #[test]
    fn the_digest_probes_carry_a_digest_of_the_right_length() {
        for (id, field, expected) in [
            ("ds-sub", 3, 64),
            ("tlsa-hex-case", 3, 64),
            ("sshfp-hex-case", 2, 40),
        ] {
            let digest = probe(id)
                .wire
                .split_whitespace()
                .nth(field)
                .expect("digest field is present");
            assert_eq!(digest.len(), expected, "{id}");
            assert!(digest.chars().all(|c| c.is_ascii_hexdigit()), "{id}");
        }
    }

    /// The mapped pair must be the same address, or the comparison it exists for is
    /// meaningless.
    #[test]
    fn the_ipv4_mapped_pair_is_one_address_written_two_ways() {
        let dotted: std::net::Ipv6Addr = probe("aaaa-v4mapped-dotted")
            .wire
            .parse()
            .expect("dotted form parses");
        let hex: std::net::Ipv6Addr = probe("aaaa-v4mapped-hex")
            .wire
            .parse()
            .expect("hex form parses");
        assert_eq!(dotted, hex);
        assert_eq!(
            probe("aaaa-v4mapped-dotted").expect,
            probe("aaaa-v4mapped-hex").expect,
            "one address stored two ways would make the pairing meaningless"
        );
    }

    /// How far a stock Rust renderer would get on `AAAA`, pinned in both directions.
    ///
    /// It agrees with deSEC on an ordinary address and on the deprecated IPv4-compatible
    /// form, and disagrees on the IPv4-mapped one — which is the only embedded-IPv4 form
    /// anything modern emits. Worth pinning rather than asserting in prose, because it is
    /// the whole case for and against normalizing this type, and because Rust's rendering of
    /// these forms is a std detail that could move.
    #[test]
    fn rust_matches_desec_on_every_ipv6_form_but_the_mapped_one() {
        let rendered = |id: &str| {
            probe(id)
                .wire
                .parse::<std::net::Ipv6Addr>()
                .expect("probe parses as an address")
                .to_string()
        };
        let stored = |id: &str| match &probe(id).expect {
            Expect::Canonical(stored) => *stored,
            other => panic!("{id} is expected to be rewritten, not {other:?}"),
        };

        assert_eq!(rendered("aaaa-expanded"), stored("aaaa-expanded"));
        assert_eq!(
            rendered("aaaa-v4compat-dotted"),
            stored("aaaa-v4compat-dotted")
        );

        // The one divergence, spelled out on both sides so a change to either is legible.
        assert_eq!(rendered("aaaa-v4mapped-dotted"), "::ffff:192.0.2.1");
        assert_eq!(stored("aaaa-v4mapped-dotted"), "::ffff:c000:201");
    }

    /// `LOC` loses information, so two inputs differing only in a size field come back the
    /// same. Nothing that rewrites strings can reproduce that.
    #[test]
    fn loc_is_lossy() {
        assert_ne!(probe("loc-format").wire, probe("loc-quantized").wire);
        assert_eq!(probe("loc-format").expect, probe("loc-quantized").expect);
    }
}
