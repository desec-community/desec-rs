# desec

An async client for the [deSEC.io] DNS API, covering the whole documented surface:
domains, DNS records, tokens with their scoping policies, the account lifecycle, and
the dynDNS update protocol.

## Getting started

```rust
use desec::{Client, RecordType, Subname};
use desec::api::rrsets::NewRrset;

let client = Client::new("i-T3b1h_OI-H9ab8tRS98stGtURe")?;

client
    .rrsets("example.com")
    .create(&NewRrset::new(
        "www".parse()?,
        RecordType::A,
        3600,
        ["127.0.0.1"],
    ))
    .await?;

let apex = client
    .rrsets("example.com")
    .get(&Subname::apex(), &RecordType::MX)
    .await?;
println!("{:?}", apex.records);
```

## Rate limiting

deSEC throttles per scope, and most scopes carry several limits at once — RRset writes
on one domain are capped at 2/s, 15/min, 100/h and 300/day simultaneously. The client
enforces the documented rates itself, so it paces requests rather than collecting
`429`s, and a `429` that does arrive is honoured via `Retry-After` and retried.

```rust
use std::time::Duration;
use desec::{Client, Rate, RateLimits, Scope};

let client = Client::builder()
    .token("i-T3b1h_OI-H9ab8tRS98stGtURe")
    // Halve the per-domain write rate, because something else shares this account.
    .rate_limits(RateLimits::desec_defaults().with_scope(
        Scope::DnsApiPerDomainExpensive,
        [
            Rate::new(1, Duration::from_secs(1))?,
            Rate::new(7, Duration::from_secs(60))?,
        ],
    ))
    // Wait out a per-minute bucket, but fail fast on an hourly one.
    .max_rate_limit_wait(Duration::from_secs(90))
    .build()?;
```

Pass \[`RateLimits::unlimited`\] to opt out and handle `429`s reactively only. Clones of
a \[`Client`\] share one limiter, so concurrent tasks pace against the same buckets.

## Pagination

`GET /domains/`, `GET /domains/{name}/rrsets/` and `GET /auth/tokens/` are paginated at
500 items. Of these only the RRset list routinely exceeds a page. Three ways to read
one, in increasing eagerness:

```rust
use futures_util::TryStreamExt;

// One page, with cursors, for full control.
let page = client.rrsets("example.com").list().send().await?;

// Lazy across pages: `.take(10)` costs one request no matter how large the zone.
let mut stream = client.rrsets("example.com").list().stream();
while let Some(rrset) = stream.try_next().await? {
    println!("{}", rrset.name);
}

// Eager, for collections known to be small.
let domains = client.domains().list().all().await?;
```

Filters are what keep the write path off the rate limiter: an ACME challenge should
find its zone with [`owner_of`](api::DomainsApi::owner_of) and address one RRset
directly, never list a zone.

```rust
use desec::{RecordType, Subname};

let qname = "_acme-challenge.foo.example.com";

// Ask the server where the zone cut is rather than guessing at the registrable name.
let Some(zone) = client.domains().owner_of(qname).await? else {
    return Ok(());
};

// What is left of the zone name is the subname, and nothing is left at the apex.
let subname: Subname = qname
    .strip_suffix(&zone.name)
    .and_then(|rest| rest.strip_suffix('.'))
    .unwrap_or("")
    .parse()?;

// `PUT` is idempotent, so a retried challenge needs no read to decide what to send,
// and the TTL floor came along with the domain.
client
    .rrsets(&zone.name)
    .replace(&subname, &RecordType::TXT, zone.minimum_ttl, [format!("\"{token}\"")])
    .await?;
```

This would cost two requests regardless of the size of the zone.

## Errors

\[`Error`\] is a `thiserror` enum. A rejected request keeps the server's error document
intact as an \[`ErrorDetail`\] tree rather than flattening it to a string, so the field
that failed — and, for a bulk RRset write, *which item's* field — is still there:

```rust
// A bulk write reports errors positionally, with an empty object per item that passed.
let err = ApiError::parse(r#"[{}, {"records": ["Invalid record."]}, {}]"#);
assert_eq!(err.messages(), vec![("1.records".to_owned(), "Invalid record.")]);
```

## Tracing

Every request runs in a `desec.request` span carrying the method and path, with events
for the response status, local rate-limit waits, server throttling and retries.
Credentials are never recorded: \[`Secret`\] redacts itself in `Debug` and `Display`.

## API semantics the types enforce

Several of the API's rules are easy to get wrong, and each has already cost a shipped
client a bug. Where possible the mistake is unrepresentable rather than merely
documented:

- The zone apex is `@` in a URL path but `""` in a JSON body, and the API returns the
  latter. \[`Subname`\] carries both spellings, so an RRset read from the API can be
  written back without a translation step to forget.
- `records: null` is a `400`, not "leave unchanged". Nothing in
  [`RrsetPatch`](api::rrsets::RrsetPatch) can serialize to `null`, and a TTL-only
  update is expressible.
- `perm_write: false` must be sent, not omitted, or write permission can be granted but
  never revoked. [`TokenPolicyPatch`](api::tokens::TokenPolicyPatch) sends it.
- `PUT` needs every field even when deleting, so
  [`delete_bulk`](api::RrsetsApi::delete_bulk) uses `PATCH`.
- A body `subname` disagreeing with the path `subname` is a `400`; the write methods
  derive one from the other.
- `max_age` and `max_unused_period` must be clearable, which takes an explicit `null` —
  see [`TokenUpdate::clear_max_age`](api::tokens::TokenUpdate::clear_max_age).
- Omitting `cursor` is what triggers `400 Pagination required`; the client always sends
  it.

## Not covered

`/auth/totp/` (2FA), which the API documents only as "interface subject to change" and
gives no field reference for, and `PATCH /domains/{name}/`, which is deprecated
upstream.

## License

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

[desec.io]: https://desec.io
