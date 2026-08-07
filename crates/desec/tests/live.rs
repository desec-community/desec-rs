//! Tests against the real deSEC API.
//!
//! Every test here is `#[ignore]`d, so `cargo test` — including the `--all-features` run
//! CI does — skips them and reports them as ignored. A cargo feature would not work for
//! this: `--all-features` would switch it on. Run them deliberately:
//!
//! ```text
//! DESEC_TOKEN=… just live-test
//! ```
//!
//! Each test that needs a zone creates its own throwaway domain and deletes it again, so
//! tests do not share per-domain rate-limit budget and a failure cannot strand another
//! test's records. Nothing needs to resolve: the API neither verifies ownership of a name
//! nor that it is delegated, so a name that exists only inside deSEC exercises every code
//! path a real one would.
//!
//! Interrupted runs leak a domain. The first scratch creation in a process sweeps anything
//! left over from a previous one, so leakage is self-correcting rather than cumulative.
//!
//! The client here runs with deSEC's real rate limits enabled, which paces the suite and
//! doubles as a check that the limiter's numbers match what the server enforces.
//!
//! Account operations with side effects outside the API — password reset, email change,
//! account deletion — are deliberately absent. They cannot be undone by a test.
#![allow(clippy::expect_used)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use desec::api::domains::NewDomain;
use desec::api::rrsets::{BulkPatch, BulkPut, NewRrset, RrsetPatch};
use desec::api::tokens::{NewTokenPolicy, TokenPolicyPatch, TokenUpdate};
use desec::dyndns::{DynDnsClient, IpUpdate};
use desec::{Client, DjangoDuration, RecordType, Subname};
use tokio::sync::OnceCell;

/// Prefix every scratch domain shares, so the sweep can recognise its own leftovers.
const SCRATCH_PREFIX: &str = "desec-rs-test";

/// Reads an environment variable, treating an empty value as absent.
///
/// An unset GitHub Actions variable or secret expands to the empty string rather than
/// vanishing, so `env::var` returns `Ok("")` and a plain `unwrap_or` would take it.
fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Parent zone for scratch domains, overridable for accounts that would rather not create
/// names under `dedyn.io`.
fn parent_zone() -> String {
    env("DESEC_TEST_PARENT").unwrap_or_else(|| "dedyn.io".to_owned())
}

/// One client for the whole binary, so every test shares one rate limiter and the suite
/// paces itself against the account's real budget rather than racing itself into `429`s.
async fn client() -> &'static Client {
    static CLIENT: OnceCell<Client> = OnceCell::const_new();
    CLIENT
        .get_or_init(|| async {
            let token = env("DESEC_TOKEN").unwrap_or_else(|| {
                panic!(
                    "DESEC_TOKEN is not set.\n\
                     These tests talk to the real API, so they need a token from a test \
                     account with perm_create_domain, perm_delete_domain and \
                     perm_manage_tokens.\n\
                     Run them with: DESEC_TOKEN=… just live-test"
                )
            });
            Client::builder()
                .token(token)
                // Long enough to wait out a per-minute bucket, short enough that an
                // exhausted hourly bucket fails the run instead of hanging it.
                .max_rate_limit_wait(Duration::from_secs(180))
                .timeout(Duration::from_secs(30))
                .build()
                .expect("client configuration is valid")
        })
        .await
}

/// A throwaway zone, deleted by [`Scratch::destroy`].
struct Scratch {
    name: String,
    minimum_ttl: u32,
}

impl Scratch {
    async fn create(label: &str) -> Self {
        sweep_leftovers().await;

        // Unique per test and per run without pulling in a random number generator: the
        // label separates concurrent tests, the timestamp separates successive runs.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock is after the epoch")
            .as_nanos();
        let name = format!("{SCRATCH_PREFIX}-{label}-{stamp:x}.{}", parent_zone());

        let domain = client()
            .await
            .domains()
            .create(&NewDomain::new(&name))
            .await
            .unwrap_or_else(|err| panic!("could not create scratch domain {name}: {err}"));

        assert_eq!(domain.name, name);
        Self {
            name,
            minimum_ttl: domain.minimum_ttl,
        }
    }

    async fn destroy(self) {
        client()
            .await
            .domains()
            .delete(&self.name)
            .await
            .unwrap_or_else(|err| panic!("could not delete scratch domain {}: {err}", self.name));
    }
}

/// Deletes scratch domains left behind by an interrupted run. Runs once per process.
async fn sweep_leftovers() {
    static SWEPT: OnceCell<()> = OnceCell::const_new();
    SWEPT
        .get_or_init(|| async {
            let client = client().await;
            let stale: Vec<_> = client
                .domains()
                .list()
                .all()
                .await
                .expect("could not list domains")
                .into_iter()
                .filter(|domain| domain.name.starts_with(SCRATCH_PREFIX))
                .map(|domain| domain.name)
                .collect();

            for name in stale {
                eprintln!("sweeping leftover scratch domain {name}");
                if let Err(err) = client.domains().delete(&name).await {
                    eprintln!("  could not delete {name}: {err}");
                }
            }
        })
        .await;
}

fn sub(label: &str) -> Subname {
    label.parse().expect("test subname is valid")
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn account_information_deserializes() {
    let account = client().await.account().get().await.expect("read account");

    assert!(account.email.contains('@'), "{:?}", account.email);
    // The field the existing Rust client omits entirely; assert the server really sends it.
    assert!(
        account.domains_under_management.is_some(),
        "domains_under_management was absent: {account:?}"
    );
    assert!(account.limit_domains.is_some(), "{account:?}");
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn domain_lifecycle() {
    let client = client().await;
    let scratch = Scratch::create("domain").await;

    let fetched = client.domains().get(&scratch.name).await.expect("get");
    // Keys are omitted from list responses but present here, and a fresh zone is signed.
    assert!(!fetched.keys.is_empty(), "no DNSSEC keys: {fetched:?}");
    assert!(
        fetched.keys.iter().any(|key| key.managed),
        "no managed key: {:?}",
        fetched.keys
    );
    assert!(fetched.minimum_ttl > 0);

    let owner = client
        .domains()
        .owner_of(&format!("_acme-challenge.{}", scratch.name))
        .await
        .expect("owns_qname query");
    assert_eq!(
        owner.map(|domain| domain.name).as_deref(),
        Some(scratch.name.as_str())
    );

    let zonefile = client
        .domains()
        .zonefile(&scratch.name)
        .await
        .expect("export");
    assert!(zonefile.contains(&scratch.name), "{zonefile}");
    assert!(zonefile.contains("SOA"), "{zonefile}");

    scratch.destroy().await;
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn a_deleted_domain_is_gone() {
    let client = client().await;
    let scratch = Scratch::create("gone").await;
    let name = scratch.name.clone();

    scratch.destroy().await;

    assert!(
        client
            .domains()
            .try_get(&name)
            .await
            .expect("query")
            .is_none(),
        "domain still readable after deletion"
    );
    // Deletion is documented as idempotent, so a second attempt must still succeed.
    client.domains().delete(&name).await.expect("second delete");
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn a_zonefile_can_be_imported_on_creation() {
    let client = client().await;
    sweep_leftovers().await;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let name = format!("{SCRATCH_PREFIX}-import-{stamp:x}.{}", parent_zone());

    let zonefile = format!("www.{name}. 3600 IN A 127.0.0.1\n");
    let domain = client
        .domains()
        .create(&NewDomain::new(&name).zonefile(zonefile))
        .await
        .expect("create with zonefile");

    let imported = client
        .rrsets(&domain.name)
        .get(&sub("www"), &RecordType::A)
        .await
        .expect("imported record");
    assert_eq!(imported.records, ["127.0.0.1"]);

    client.domains().delete(&name).await.expect("cleanup");
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn rrset_lifecycle() {
    let client = client().await;
    let scratch = Scratch::create("rrset").await;
    let rrsets = client.rrsets(&scratch.name);
    let ttl = scratch.minimum_ttl;

    let created = rrsets
        .create(&NewRrset::new(
            sub("www"),
            RecordType::A,
            ttl,
            ["127.0.0.1"],
        ))
        .await
        .expect("create");
    assert_eq!(created.records, ["127.0.0.1"]);
    assert_eq!(created.name, format!("www.{}.", scratch.name));

    // Both filters on one request, which the existing Rust client cannot express.
    let filtered = rrsets
        .list()
        .subname(&sub("www"))
        .record_type(&RecordType::A)
        .all()
        .await
        .expect("filtered list");
    assert_eq!(filtered.len(), 1, "{filtered:?}");

    // A TTL-only patch has to leave the records alone. Sending `records: null` here would
    // be a 400, and sending the old records back would make the operation a no-op by luck.
    let doubled = ttl * 2;
    let patched = rrsets
        .patch(&sub("www"), &RecordType::A, &RrsetPatch::new().ttl(doubled))
        .await
        .expect("ttl-only patch");
    assert_eq!(patched.ttl, doubled);
    assert_eq!(patched.records, ["127.0.0.1"], "records were disturbed");

    let replaced = rrsets
        .replace(&sub("www"), &RecordType::A, ttl, ["10.0.0.1", "10.0.0.2"])
        .await
        .expect("put");
    let mut records = replaced.records.clone();
    records.sort();
    assert_eq!(records, ["10.0.0.1", "10.0.0.2"]);

    rrsets
        .delete(&sub("www"), &RecordType::A)
        .await
        .expect("delete");
    assert!(
        rrsets
            .try_get(&sub("www"), &RecordType::A)
            .await
            .expect("query")
            .is_none()
    );

    scratch.destroy().await;
}

/// The bug that breaks the existing Rust client: the API returns the apex subname as `""`,
/// and feeding that back into a URL needs `@`, not an empty path segment.
#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn an_apex_rrset_survives_a_read_modify_write() {
    let client = client().await;
    let scratch = Scratch::create("apex").await;
    let rrsets = client.rrsets(&scratch.name);
    let ttl = scratch.minimum_ttl;

    rrsets
        .create(&NewRrset::at_apex(RecordType::TXT, ttl, [r#""one""#]))
        .await
        .expect("create at apex");

    let read = rrsets
        .get(&Subname::apex(), &RecordType::TXT)
        .await
        .expect("read apex");
    assert!(
        read.subname.is_apex(),
        "apex came back as {:?}",
        read.subname
    );
    assert_eq!(read.name, format!("{}.", scratch.name));

    // The subname goes back out exactly as it came in. Substituting rather than
    // translating produces `/rrsets//TXT/`, which does not survive path normalization.
    let patched = rrsets
        .patch(
            &read.subname,
            &read.record_type,
            &RrsetPatch::new().records([r#""two""#]),
        )
        .await
        .expect("patch at apex after reading it back");
    assert_eq!(patched.records, [r#""two""#]);

    rrsets
        .delete(&read.subname, &RecordType::TXT)
        .await
        .expect("delete at apex");

    scratch.destroy().await;
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn bulk_rrset_operations() {
    let client = client().await;
    let scratch = Scratch::create("bulk").await;
    let rrsets = client.rrsets(&scratch.name);
    let ttl = scratch.minimum_ttl;

    let created = rrsets
        .create_bulk(&[
            NewRrset::new(sub("a"), RecordType::A, ttl, ["127.0.0.1"]),
            NewRrset::new(sub("b"), RecordType::TXT, ttl, [r#""b""#]),
        ])
        .await
        .expect("bulk create");
    assert_eq!(created.len(), 2);

    // A mixed batch: retune one, replace another's records, create a third.
    rrsets
        .patch_bulk(&[
            BulkPatch::new(sub("a"), RecordType::A).ttl(ttl * 2),
            BulkPatch::new(sub("b"), RecordType::TXT).records([r#""changed""#]),
            BulkPatch::new(sub("c"), RecordType::AAAA)
                .ttl(ttl)
                .records(["2001:db8::1"]),
        ])
        .await
        .expect("bulk patch");

    let all = rrsets.list().all().await.expect("list");
    let a = all
        .iter()
        .find(|rrset| rrset.subname == sub("a") && rrset.record_type == RecordType::A)
        .expect("a still present");
    assert_eq!(a.ttl, ttl * 2);
    assert_eq!(
        a.records,
        ["127.0.0.1"],
        "a TTL-only bulk patch changed records"
    );

    rrsets
        .replace_bulk(&[BulkPut::new(sub("a"), RecordType::A, ttl, ["192.0.2.1"])])
        .await
        .expect("bulk put");

    // PATCH with empty record lists, because PUT would demand a ttl for a deletion.
    rrsets
        .delete_bulk([
            (sub("a"), RecordType::A),
            (sub("b"), RecordType::TXT),
            (sub("c"), RecordType::AAAA),
        ])
        .await
        .expect("bulk delete");

    let remaining = rrsets.list().all().await.expect("list");
    for (subname, record_type) in [
        (sub("a"), RecordType::A),
        (sub("b"), RecordType::TXT),
        (sub("c"), RecordType::AAAA),
    ] {
        assert!(
            !remaining
                .iter()
                .any(|rrset| rrset.subname == subname && rrset.record_type == record_type),
            "{subname}/{record_type} survived the bulk delete"
        );
    }

    scratch.destroy().await;
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn validation_errors_keep_their_field_names() {
    let client = client().await;
    let scratch = Scratch::create("errors").await;
    let rrsets = client.rrsets(&scratch.name);

    // Below the zone's minimum, which only the server can judge, so this also proves the
    // client's own TTL check is not over-eager.
    let err = rrsets
        .create(&NewRrset::new(sub("low"), RecordType::A, 1, ["127.0.0.1"]))
        .await
        .expect_err("a TTL under the minimum is rejected");
    assert!(err.is_validation(), "{err:?}");
    let body = err.api_error().expect("an error document");
    assert!(
        body.field("ttl").is_some(),
        "expected a ttl field error, got {body}"
    );

    // A CNAME at the apex is forbidden, and the message arrives under a different key.
    let err = rrsets
        .create(&NewRrset::at_apex(
            RecordType::CNAME,
            scratch.minimum_ttl,
            ["example.com."],
        ))
        .await
        .expect_err("a CNAME at the apex is rejected");
    assert!(err.is_validation(), "{err:?}");
    assert!(
        !err.api_error().expect("document").messages().is_empty(),
        "no messages in {err:?}"
    );

    scratch.destroy().await;
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn an_unknown_domain_is_not_found() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let absent = format!("{SCRATCH_PREFIX}-absent-{stamp:x}.{}", parent_zone());

    let err = client()
        .await
        .domains()
        .get(&absent)
        .await
        .expect_err("an unowned domain is not readable");
    assert!(err.is_not_found(), "{err:?}");
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn token_lifecycle() {
    let client = client().await;

    // The permissions the existing Rust client cannot set at creation, which is what makes
    // a token usable for provisioning.
    let created = client
        .tokens()
        .create(
            &TokenUpdate::new()
                .name("desec-rs live test")
                .perm_create_domain(true)
                .perm_delete_domain(true)
                .max_age(DjangoDuration::hours(1)),
        )
        .await
        .expect("create token");

    assert!(created.perm_create_domain, "{created:?}");
    assert!(created.perm_delete_domain, "{created:?}");
    assert_eq!(created.max_age, Some(DjangoDuration::hours(1)));
    assert!(created.token.is_some(), "the secret is disclosed once");
    assert_eq!(created.mfa, None, "an API token has a null mfa");

    let fetched = client.tokens().get(created.id).await.expect("get token");
    assert!(
        fetched.token.is_none(),
        "the secret must not be re-disclosed"
    );

    // Clearing a duration needs an explicit null; omission would leave it in place.
    let cleared = client
        .tokens()
        .patch(
            created.id,
            &TokenUpdate::new().clear_max_age().perm_delete_domain(false),
        )
        .await
        .expect("patch token");
    assert_eq!(cleared.max_age, None, "max_age was not cleared");
    assert!(
        !cleared.perm_delete_domain,
        "a false permission was dropped"
    );
    assert!(
        cleared.perm_create_domain,
        "an omitted field was not preserved"
    );

    let listed = client.tokens().list().all().await.expect("list tokens");
    assert!(listed.iter().any(|token| token.id == created.id));

    client
        .tokens()
        .delete(created.id)
        .await
        .expect("delete token");
    assert!(
        client
            .tokens()
            .try_get(created.id)
            .await
            .expect("query")
            .is_none()
    );
}

#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn token_policies_can_revoke_write_permission() {
    let client = client().await;
    let scratch = Scratch::create("policy").await;

    let token = client
        .tokens()
        .create(&TokenUpdate::new().name("desec-rs live policy test"))
        .await
        .expect("create token");
    let policies = client.tokens().policies(token.id);

    // A default policy has to exist before any narrower one is accepted.
    let default = policies
        .create(&NewTokenPolicy::default_policy(false))
        .await
        .expect("create default policy");
    assert!(default.is_default(), "{default:?}");

    let scoped = policies
        .create(&NewTokenPolicy::for_domain(&scratch.name, true).record_type(RecordType::TXT))
        .await
        .expect("create scoped policy");
    assert!(scoped.perm_write);
    assert_eq!(scoped.domain.as_deref(), Some(scratch.name.as_str()));

    // The bug in both community clients: omitting `perm_write` preserves it, so a client
    // that drops falsy booleans can grant write permission but never take it back.
    let revoked = policies
        .patch(scoped.id, &TokenPolicyPatch::new().perm_write(false))
        .await
        .expect("revoke write");
    assert!(!revoked.perm_write, "write permission was not revoked");

    // A patch that touches only the selector must leave the permission alone.
    let renamed = policies
        .patch(scoped.id, &TokenPolicyPatch::new().any_record_type())
        .await
        .expect("widen the selector");
    assert!(!renamed.perm_write, "an untouched permission changed");
    assert_eq!(renamed.record_type, None);

    let listed = policies.list().await.expect("list policies");
    assert_eq!(listed.len(), 2, "{listed:?}");

    policies.delete(scoped.id).await.expect("delete scoped");
    policies.delete(default.id).await.expect("delete default");
    client
        .tokens()
        .delete(token.id)
        .await
        .expect("delete token");
    scratch.destroy().await;
}

/// Needs the scratch domain to be one the dynDNS endpoint will accept, which is why the
/// parent defaults to `dedyn.io`.
#[tokio::test]
#[ignore = "talks to the real API; run with `just live-test`"]
async fn a_dyndns_update_sets_the_address_records() {
    let token = env("DESEC_TOKEN").expect("DESEC_TOKEN is set");
    let scratch = Scratch::create("dyndns").await;

    let dyndns = DynDnsClient::builder()
        .token(token)
        .max_rate_limit_wait(Duration::from_secs(180))
        .build()
        .expect("dyndns client configuration is valid");

    let body = dyndns
        .update(&scratch.name)
        .ipv4(IpUpdate::set(["192.0.2.4"]))
        .ipv6(IpUpdate::Remove)
        .send_body()
        .await
        .expect("dyndns update");
    assert_eq!(body.trim(), "good", "unexpected dynDNS response: {body}");

    let a = client()
        .await
        .rrsets(&scratch.name)
        .get(&Subname::apex(), &RecordType::A)
        .await
        .expect("the A record the update wrote");
    assert_eq!(a.records, ["192.0.2.4"]);

    scratch.destroy().await;
}
