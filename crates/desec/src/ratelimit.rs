//! Client-side rate limiting.
//!
//! deSEC throttles per *scope*, and most scopes carry several limits at once: RRset
//! writes on one domain are capped at 2/s, 15/min, 100/h and 300/day simultaneously.
//! The limiter mirrors that structure — a [`Scope`] maps to a list of [`Rate`]s, each
//! backed by its own sliding window, and a request may only proceed once every window
//! that applies to it has a free slot.
//!
//! Enabled by default with [`RateLimits::desec_defaults`], so a client waits locally
//! instead of collecting `429`s. Use [`RateLimits::unlimited`] to opt out.
//!
//! Timing goes through [`tokio::time`], so tests can drive the limiter with
//! `#[tokio::test(start_paused = true)]` instead of sleeping for real.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

use crate::error::{Error, InvalidValue, Result};

/// A throttling scope, named as deSEC names it.
///
/// Every request counts against [`Scope::User`] as well as whichever specific scope
/// covers the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Scope {
    /// Account actions with effects outside the API, which means sending email:
    /// registration, password reset, email change, account deletion.
    AccountManagementActive,
    /// Account actions with internal effects only: reading the account, login, logout,
    /// and everything under `/auth/tokens/`.
    AccountManagementPassive,
    /// DNS reads, other than zonefile export.
    DnsApiCheap,
    /// Domain creation and deletion, and zonefile export.
    DnsApiExpensive,
    /// RRset writes. Counted per domain.
    DnsApiPerDomainExpensive,
    /// dynDNS updates. Counted per domain.
    DynDns,
    /// The catch-all daily cap on all activity.
    User,
}

impl Scope {
    /// Whether this scope is counted separately for each domain.
    pub fn is_per_domain(self) -> bool {
        matches!(self, Self::DnsApiPerDomainExpensive | Self::DynDns)
    }

    /// The scope name as it appears in deSEC's documentation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccountManagementActive => "account_management_active",
            Self::AccountManagementPassive => "account_management_passive",
            Self::DnsApiCheap => "dns_api_cheap",
            Self::DnsApiExpensive => "dns_api_expensive",
            Self::DnsApiPerDomainExpensive => "dns_api_per_domain_expensive",
            Self::DynDns => "dyndns",
            Self::User => "user",
        }
    }

    /// Every scope, for iterating configuration.
    pub const ALL: [Scope; 7] = [
        Self::AccountManagementActive,
        Self::AccountManagementPassive,
        Self::DnsApiCheap,
        Self::DnsApiExpensive,
        Self::DnsApiPerDomainExpensive,
        Self::DynDns,
        Self::User,
    ];
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Longest window [`Rate::new`] accepts.
const MAX_PERIOD: Duration = Duration::from_secs(366 * 86_400);

/// A limit of `limit` requests per `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    limit: u32,
    period: Duration,
}

impl Rate {
    /// Builds a rate, rejecting a zero limit or period since neither could ever admit a
    /// request.
    pub fn new(limit: u32, period: Duration) -> Result<Self, InvalidValue> {
        if limit == 0 {
            return Err(InvalidValue::new(
                "rate",
                "limit must be greater than zero",
                limit.to_string(),
            ));
        }
        if period.is_zero() {
            return Err(InvalidValue::new(
                "rate",
                "period must be greater than zero",
                "0",
            ));
        }
        // Bounded because the period is added to an `Instant` to find the next free slot,
        // and that panics on overflow. No throttling window is longer than a year.
        if period > MAX_PERIOD {
            return Err(InvalidValue::new(
                "rate",
                "period must be at most 366 days",
                format!("{period:?}"),
            ));
        }
        Ok(Self { limit, period })
    }

    /// Requests permitted per period.
    pub fn limit(self) -> u32 {
        self.limit
    }

    /// Length of the sliding window.
    pub fn period(self) -> Duration {
        self.period
    }
}

impl FromStr for Rate {
    type Err = InvalidValue;

    /// Parses deSEC's notation: `10/s`, `50/min`, `600/h`, `2/2min`, `300/day`.
    ///
    /// The period may carry a multiplier, which plain Django REST Framework rates do
    /// not — deSEC's `dyndns` scope is `2/2min`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidValue::new("rate", "expected a rate like `10/s` or `2/2min`", s);

        let (limit, period) = s.split_once('/').ok_or_else(invalid)?;
        let limit: u32 = limit.trim().parse().map_err(|_| invalid())?;

        let period = period.trim();
        let split = period
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(invalid)?;
        let (count, unit) = period.split_at(split);
        let count: u32 = if count.is_empty() {
            1
        } else {
            count.parse().map_err(|_| invalid())?
        };

        let unit = match unit {
            "s" | "sec" | "second" | "seconds" => Duration::from_secs(1),
            "m" | "min" | "minute" | "minutes" => Duration::from_secs(60),
            "h" | "hour" | "hours" => Duration::from_secs(3600),
            "d" | "day" | "days" => Duration::from_secs(86_400),
            _ => return Err(invalid()),
        };

        Self::new(limit, unit * count)
    }
}

impl fmt::Display for Rate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.period.as_secs();
        let (count, unit) = match secs {
            0 => (self.period.as_millis(), "ms"),
            s if s % 86_400 == 0 => ((s / 86_400).into(), "day"),
            s if s % 3600 == 0 => ((s / 3600).into(), "h"),
            s if s % 60 == 0 => ((s / 60).into(), "min"),
            s => (s.into(), "s"),
        };
        if count == 1 {
            write!(f, "{}/{unit}", self.limit)
        } else {
            write!(f, "{}/{count}{unit}", self.limit)
        }
    }
}

/// The rates to enforce for each scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimits {
    scopes: HashMap<Scope, Vec<Rate>>,
}

impl Default for RateLimits {
    fn default() -> Self {
        Self::desec_defaults()
    }
}

impl RateLimits {
    /// The rates deSEC documents, as of the API version this crate targets.
    ///
    /// These are what the server enforces, so a client configured with them should
    /// rarely see a `429` — only when another client shares the account.
    pub fn desec_defaults() -> Self {
        // Parsing string literals keeps these readable against the documentation table;
        // the expects cannot fire because every literal is well-formed, and the unit
        // test below pins that.
        fn rates(specs: &[&str]) -> Vec<Rate> {
            specs
                .iter()
                .map(|s| s.parse().expect("built-in rate literal is well-formed"))
                .collect()
        }

        let scopes = [
            (Scope::AccountManagementActive, rates(&["3/min"])),
            (Scope::AccountManagementPassive, rates(&["50/min", "600/h"])),
            (Scope::DnsApiCheap, rates(&["10/s", "50/min"])),
            (
                Scope::DnsApiExpensive,
                rates(&["10/s", "300/min", "1000/h"]),
            ),
            (
                Scope::DnsApiPerDomainExpensive,
                rates(&["2/s", "15/min", "100/h", "300/day"]),
            ),
            (Scope::DynDns, rates(&["2/2min"])),
            (Scope::User, rates(&["2000/day"])),
        ];

        Self {
            scopes: scopes.into_iter().collect(),
        }
    }

    /// No client-side limiting at all.
    ///
    /// `429` responses are still honoured by the retry layer; this only stops the client
    /// from pacing itself in advance.
    pub fn unlimited() -> Self {
        Self {
            scopes: HashMap::new(),
        }
    }

    /// Replaces the rates for one scope. An empty slice removes the limit.
    pub fn with_scope(mut self, scope: Scope, rates: impl IntoIterator<Item = Rate>) -> Self {
        let rates: Vec<_> = rates.into_iter().collect();
        if rates.is_empty() {
            self.scopes.remove(&scope);
        } else {
            self.scopes.insert(scope, rates);
        }
        self
    }

    /// The rates configured for one scope.
    pub fn rates(&self, scope: Scope) -> &[Rate] {
        self.scopes.get(&scope).map_or(&[], Vec::as_slice)
    }

    /// True when no scope has any rate configured.
    pub fn is_unlimited(&self) -> bool {
        self.scopes.is_empty()
    }
}

/// The scopes one request counts against.
///
/// Small by construction: an operation belongs to at most one specific scope plus
/// [`Scope::User`].
#[derive(Debug, Clone, Default)]
pub(crate) struct ScopeSet {
    entries: Vec<(Scope, Option<Arc<str>>)>,
}

impl ScopeSet {
    /// The scopes for an operation: its own scope plus the account-wide daily cap.
    pub(crate) fn new(scope: Scope) -> Self {
        // Deduplicated, because the record pass walks entries and a repeated key would
        // charge the same window twice for one request.
        let mut entries = vec![(scope, None)];
        if scope != Scope::User {
            entries.push((Scope::User, None));
        }
        Self { entries }
    }

    /// As [`ScopeSet::new`], for a scope counted per domain.
    pub(crate) fn per_domain(scope: Scope, domain: &str) -> Self {
        debug_assert!(scope.is_per_domain(), "{scope} is not counted per domain");
        Self {
            entries: vec![(scope, Some(Arc::from(domain))), (Scope::User, None)],
        }
    }

    fn keys(&self) -> impl Iterator<Item = BucketKey> + '_ {
        self.entries.iter().cloned()
    }
}

/// One sliding window: the timestamps of the requests still inside `rate.period`.
///
/// A sliding log rather than a token bucket, because that is what Django REST
/// Framework's throttles do — a bucket would refuse the bursts the server permits.
#[derive(Debug)]
struct Window {
    rate: Rate,
    hits: VecDeque<Instant>,
}

impl Window {
    fn new(rate: Rate) -> Self {
        Self {
            rate,
            hits: VecDeque::with_capacity(rate.limit.min(64) as usize),
        }
    }

    /// Drops hits that have aged out, then reports when the next slot frees up.
    ///
    /// `None` means a slot is free now.
    fn wait_until(&mut self, now: Instant) -> Option<Instant> {
        while self
            .hits
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= self.rate.period)
        {
            self.hits.pop_front();
        }

        if (self.hits.len() as u32) < self.rate.limit {
            None
        } else {
            // The window frees a slot once its oldest hit ages out. `limit` is non-zero,
            // so a full window always has a front element. `Rate::new` bounds the period,
            // so the addition cannot overflow the clock.
            self.hits
                .front()
                .and_then(|t| t.checked_add(self.rate.period))
        }
    }

    fn record(&mut self, now: Instant) {
        self.hits.push_back(now);
    }
}

/// Identifies a bucket: a scope, plus the domain for the scopes counted per domain.
type BucketKey = (Scope, Option<Arc<str>>);

/// Per-scope state: one window per configured rate, plus any server-imposed backoff.
#[derive(Debug)]
struct ScopeState {
    windows: Vec<Window>,
    /// Set from a `429`'s `Retry-After`, so concurrent tasks back off too rather than
    /// each discovering the throttle for themselves.
    penalty_until: Option<Instant>,
}

impl ScopeState {
    fn new(rates: &[Rate]) -> Self {
        Self {
            windows: rates.iter().copied().map(Window::new).collect(),
            penalty_until: None,
        }
    }

    fn wait_until(&mut self, now: Instant) -> Option<Instant> {
        let penalty = self.penalty_until.filter(|t| *t > now);
        self.windows
            .iter_mut()
            .filter_map(|w| w.wait_until(now))
            .chain(penalty)
            .max()
    }

    fn record(&mut self, now: Instant) {
        for window in &mut self.windows {
            window.record(now);
        }
    }

    /// Whether this bucket still constrains anything, so eviction can drop the rest.
    fn is_idle(&mut self, now: Instant) -> bool {
        self.penalty_until.is_none_or(|t| t <= now)
            && self.windows.iter_mut().all(|w| {
                w.wait_until(now);
                w.hits.is_empty()
            })
    }
}

/// Bucket count at which [`Limiter::acquire`] sweeps out the idle ones.
///
/// The per-domain scopes key on the domain name, so a process that touches many zones —
/// an external-dns provider syncing thousands of them — would otherwise accumulate a
/// bucket per zone for the life of the process. Sweeping only when the map is already
/// large keeps the common case free.
const EVICTION_THRESHOLD: usize = 512;

/// Enforces [`RateLimits`] across all requests made through one client.
#[derive(Debug)]
pub(crate) struct Limiter {
    limits: RateLimits,
    max_wait: Duration,
    state: Mutex<HashMap<BucketKey, ScopeState>>,
}

impl Limiter {
    pub(crate) fn new(limits: RateLimits, max_wait: Duration) -> Self {
        Self {
            limits,
            max_wait,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Waits until every scope in `scopes` has a free slot, then claims one in each.
    ///
    /// All-or-nothing: slots are claimed under a single lock hold, so a request never
    /// consumes part of its quota and then blocks. Waiters re-check after sleeping
    /// rather than being handed a reservation, which means wake-ups are not ordered —
    /// under heavy contention a request may be overtaken. Correctness does not depend on
    /// the order, only on the re-check.
    pub(crate) async fn acquire(&self, scopes: &ScopeSet) -> Result<()> {
        // A budget for the whole call, not per sleep. Checking each sleep in isolation
        // would let a scope whose penalty keeps being refreshed park a task indefinitely,
        // which is exactly what `max_rate_limit_wait` promises not to do.
        let deadline = Instant::now().checked_add(self.max_wait);

        loop {
            let (wait, blocking_scope) = {
                let now = Instant::now();
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());

                let mut blocker: Option<(Instant, Scope)> = None;
                for (scope, resource) in scopes.keys() {
                    let rates = self.limits.rates(scope);
                    if rates.is_empty() {
                        continue;
                    }
                    let entry = state
                        .entry((scope, resource))
                        .or_insert_with(|| ScopeState::new(rates));
                    if let Some(until) = entry.wait_until(now) {
                        if blocker.is_none_or(|(t, _)| until > t) {
                            blocker = Some((until, scope));
                        }
                    }
                }

                match blocker {
                    None => {
                        for key in scopes.keys() {
                            if let Some(entry) = state.get_mut(&key) {
                                entry.record(now);
                            }
                        }
                        if state.len() > EVICTION_THRESHOLD {
                            let before = state.len();
                            state.retain(|_, entry| !entry.is_idle(now));
                            tracing::debug!(
                                evicted = before - state.len(),
                                remaining = state.len(),
                                "swept idle rate-limit buckets"
                            );
                        }
                        return Ok(());
                    }
                    Some((until, scope)) => (until.saturating_duration_since(now), scope),
                }
            };

            // Over budget either as a single sleep or cumulatively across this call. A
            // `None` deadline means `max_wait` is large enough to overflow the clock, so
            // there is effectively no total budget to exceed.
            let over_total = deadline
                .zip(Instant::now().checked_add(wait))
                .is_some_and(|(deadline, finish)| finish > deadline);
            if wait > self.max_wait || over_total {
                return Err(Error::RateLimitWouldBlock {
                    scope: blocking_scope,
                    wait,
                    max_wait: self.max_wait,
                });
            }

            tracing::debug!(
                scope = %blocking_scope,
                wait_ms = wait.as_millis(),
                "local rate limit reached, waiting"
            );
            tokio::time::sleep(wait).await;
        }
    }

    /// Records a `429` so other tasks using the same scopes back off as well.
    pub(crate) fn record_throttled(&self, scopes: &ScopeSet, retry_after: Option<Duration>) {
        let Some(retry_after) = retry_after else {
            return;
        };

        // Capped at `max_wait`, for two reasons. A `Retry-After` the client has already
        // decided not to honour must not be written into a bucket it will then refuse to
        // wait out — one absurd header would otherwise take every scope offline for its
        // duration, and `Scope::User` is in every request's scope set, so that means the
        // whole client. And `Instant` arithmetic panics on overflow. If the server is
        // still throttling once the capped penalty expires, the next `429` re-applies it.
        let Some(until) = Instant::now().checked_add(retry_after.min(self.max_wait)) else {
            return;
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // The response does not say which scope tripped, so the backoff goes on every
        // scope the request counted against. That can idle a scope that was not at
        // fault, which is the conservative direction.
        for (scope, resource) in scopes.keys() {
            let rates = self.limits.rates(scope);
            if rates.is_empty() {
                continue;
            }
            let entry = state
                .entry((scope, resource))
                .or_insert_with(|| ScopeState::new(rates));
            entry.penalty_until = entry.penalty_until.max(Some(until));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rate(s: &str) -> Rate {
        s.parse().expect("test rate parses")
    }

    #[test]
    fn parses_desec_rate_notation() {
        assert_eq!(rate("10/s"), Rate::new(10, Duration::from_secs(1)).unwrap());
        assert_eq!(
            rate("50/min"),
            Rate::new(50, Duration::from_secs(60)).unwrap()
        );
        assert_eq!(
            rate("600/h"),
            Rate::new(600, Duration::from_secs(3600)).unwrap()
        );
        assert_eq!(
            rate("2000/day"),
            Rate::new(2000, Duration::from_secs(86_400)).unwrap()
        );
        // The dyndns scope carries a period multiplier, which plain DRF rates lack.
        assert_eq!(
            rate("2/2min"),
            Rate::new(2, Duration::from_secs(120)).unwrap()
        );
    }

    #[test]
    fn rejects_malformed_and_empty_rates() {
        for spec in ["10", "10/", "/s", "10/x", "0/s", "abc/s", ""] {
            assert!(spec.parse::<Rate>().is_err(), "{spec} should not parse");
        }
    }

    #[test]
    fn rate_display_round_trips() {
        for spec in ["10/s", "50/min", "600/h", "2000/day", "2/2min"] {
            assert_eq!(rate(spec).to_string(), spec);
        }
    }

    #[test]
    fn defaults_match_the_documented_table() {
        let limits = RateLimits::desec_defaults();
        let render = |scope| {
            limits
                .rates(scope)
                .iter()
                .map(Rate::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };

        assert_eq!(render(Scope::AccountManagementActive), "3/min");
        assert_eq!(render(Scope::AccountManagementPassive), "50/min, 600/h");
        assert_eq!(render(Scope::DnsApiCheap), "10/s, 50/min");
        assert_eq!(render(Scope::DnsApiExpensive), "10/s, 300/min, 1000/h");
        assert_eq!(
            render(Scope::DnsApiPerDomainExpensive),
            "2/s, 15/min, 100/h, 300/day"
        );
        assert_eq!(render(Scope::DynDns), "2/2min");
        assert_eq!(render(Scope::User), "2000/day");
    }

    #[test]
    fn with_scope_overrides_and_clears() {
        let limits = RateLimits::desec_defaults()
            .with_scope(Scope::DnsApiCheap, [rate("1/s")])
            .with_scope(Scope::User, []);
        assert_eq!(limits.rates(Scope::DnsApiCheap), [rate("1/s")]);
        assert!(limits.rates(Scope::User).is_empty());
    }

    /// Two requests fit in the window; the third has to wait for the first to age out.
    #[tokio::test(start_paused = true)]
    async fn sliding_window_admits_a_burst_then_paces() {
        let limits = RateLimits::unlimited().with_scope(Scope::DnsApiCheap, [rate("2/s")]);
        let limiter = Limiter::new(limits, Duration::from_secs(60));
        let scopes = ScopeSet::new(Scope::DnsApiCheap);

        let start = Instant::now();
        for _ in 0..2 {
            limiter.acquire(&scopes).await.expect("burst fits");
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        limiter.acquire(&scopes).await.expect("third waits");
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }

    /// The tightest applicable window is what a request actually waits on.
    #[tokio::test(start_paused = true)]
    async fn narrowest_of_several_levels_wins() {
        let limits = RateLimits::unlimited().with_scope(
            Scope::DnsApiPerDomainExpensive,
            [rate("10/s"), rate("2/min")],
        );
        let limiter = Limiter::new(limits, Duration::from_secs(600));
        let scopes = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, "example.com");

        let start = Instant::now();
        for _ in 0..2 {
            limiter.acquire(&scopes).await.expect("under both limits");
        }
        // The per-second window is clear, but the per-minute one is full.
        limiter
            .acquire(&scopes)
            .await
            .expect("waits for the minute");
        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn per_domain_scopes_are_counted_separately() {
        let limits =
            RateLimits::unlimited().with_scope(Scope::DnsApiPerDomainExpensive, [rate("1/min")]);
        let limiter = Limiter::new(limits, Duration::from_secs(600));

        let start = Instant::now();
        for domain in ["a.example.com", "b.example.com", "c.example.com"] {
            let scopes = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, domain);
            limiter
                .acquire(&scopes)
                .await
                .expect("each domain is fresh");
        }
        assert_eq!(start.elapsed(), Duration::ZERO);

        // Coming back to the first domain does have to wait.
        let scopes = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, "a.example.com");
        limiter.acquire(&scopes).await.expect("waits");
        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }

    /// The shared `user` scope paces requests that otherwise have nothing in common.
    #[tokio::test(start_paused = true)]
    async fn user_scope_constrains_unrelated_operations() {
        let limits = RateLimits::unlimited().with_scope(Scope::User, [rate("1/min")]);
        let limiter = Limiter::new(limits, Duration::from_secs(600));

        let start = Instant::now();
        limiter
            .acquire(&ScopeSet::new(Scope::DnsApiCheap))
            .await
            .expect("first is free");
        limiter
            .acquire(&ScopeSet::new(Scope::AccountManagementPassive))
            .await
            .expect("shares the user cap");
        assert_eq!(start.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn refuses_to_wait_past_the_ceiling() {
        let limits = RateLimits::unlimited().with_scope(Scope::DnsApiCheap, [rate("1/h")]);
        let limiter = Limiter::new(limits, Duration::from_secs(5));
        let scopes = ScopeSet::new(Scope::DnsApiCheap);

        limiter.acquire(&scopes).await.expect("first is free");
        let err = limiter
            .acquire(&scopes)
            .await
            .expect_err("an hour is over the ceiling");
        assert!(matches!(
            err,
            Error::RateLimitWouldBlock {
                scope: Scope::DnsApiCheap,
                ..
            }
        ));
    }

    /// A blocked request must not consume quota in the scopes that were not full,
    /// otherwise repeated failures would drain unrelated buckets.
    #[tokio::test(start_paused = true)]
    async fn a_refused_acquire_claims_nothing() {
        let limits = RateLimits::unlimited()
            .with_scope(Scope::DnsApiCheap, [rate("1/h")])
            .with_scope(Scope::User, [rate("10/day")]);
        let limiter = Limiter::new(limits, Duration::from_secs(5));

        let cheap = ScopeSet::new(Scope::DnsApiCheap);
        limiter.acquire(&cheap).await.expect("first is free");
        limiter.acquire(&cheap).await.expect_err("over the ceiling");

        // One hit in the user window, from the single successful acquire.
        let mut state = limiter.state.lock().expect("uncontended");
        let user = state
            .get_mut(&(Scope::User, None))
            .expect("user scope was touched");
        assert_eq!(user.windows[0].hits.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_429_backs_off_the_whole_scope() {
        let limits = RateLimits::unlimited().with_scope(Scope::DnsApiCheap, [rate("100/s")]);
        let limiter = Limiter::new(limits, Duration::from_secs(600));
        let scopes = ScopeSet::new(Scope::DnsApiCheap);

        let start = Instant::now();
        limiter.record_throttled(&scopes, Some(Duration::from_secs(30)));
        limiter
            .acquire(&scopes)
            .await
            .expect("waits out the penalty");
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }

    /// A penalty longer than the wait budget must not park every scope for its duration.
    /// `Scope::User` is in every scope set, so an uncapped penalty is a whole-client
    /// outage that only a restart clears.
    #[tokio::test(start_paused = true)]
    async fn a_server_penalty_is_capped_at_the_wait_budget() {
        let max_wait = Duration::from_secs(60);
        let limits = RateLimits::unlimited().with_scope(Scope::DnsApiCheap, [rate("100/s")]);
        let limiter = Limiter::new(limits, max_wait);
        let scopes = ScopeSet::new(Scope::DnsApiCheap);

        let start = Instant::now();
        limiter.record_throttled(&scopes, Some(Duration::from_secs(100_000)));
        limiter
            .acquire(&scopes)
            .await
            .expect("the penalty was clamped, so this waits rather than failing");
        assert_eq!(start.elapsed(), max_wait);
    }

    /// Waiters are not queued, so one that loses a race has to sleep again. `max_wait` is
    /// a budget for the whole call rather than for each sleep, so a repeatedly overtaken
    /// caller fails instead of being parked indefinitely.
    #[tokio::test(start_paused = true)]
    async fn the_wait_budget_covers_the_whole_call() {
        let limits = RateLimits::unlimited().with_scope(Scope::DnsApiCheap, [rate("1/min")]);
        let limiter = Arc::new(Limiter::new(limits, Duration::from_secs(90)));

        limiter
            .acquire(&ScopeSet::new(Scope::DnsApiCheap))
            .await
            .expect("first is free");

        // Two waiters for one slot a minute. Both wake at 60s; the loser needs another
        // 60s, which is past its budget.
        let waiter = || {
            let limiter = Arc::clone(&limiter);
            tokio::spawn(async move { limiter.acquire(&ScopeSet::new(Scope::DnsApiCheap)).await })
        };
        let (first, second) = (waiter(), waiter());
        let results = [
            first.await.expect("task did not panic"),
            second.await.expect("task did not panic"),
        ];

        assert_eq!(
            results.iter().filter(|r| r.is_ok()).count(),
            1,
            "exactly one waiter should win the slot"
        );
        let err = results
            .into_iter()
            .find_map(Result::err)
            .expect("the other should have given up");
        assert!(matches!(err, Error::RateLimitWouldBlock { .. }), "{err:?}");
    }

    /// Per-domain buckets are keyed on the domain name, so a process syncing thousands of
    /// zones would otherwise hold one bucket per zone until it exits.
    #[tokio::test(start_paused = true)]
    async fn idle_per_domain_buckets_are_evicted() {
        let limits =
            RateLimits::unlimited().with_scope(Scope::DnsApiPerDomainExpensive, [rate("1/s")]);
        let limiter = Limiter::new(limits, Duration::from_secs(60));

        for i in 0..EVICTION_THRESHOLD + 10 {
            let domain = format!("zone-{i}.example");
            let scopes = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, &domain);
            limiter.acquire(&scopes).await.expect("each zone is fresh");
            // Past the 1/s window, so the bucket just used is idle again.
            tokio::time::advance(Duration::from_secs(2)).await;
        }

        let held = limiter.state.lock().expect("uncontended").len();
        assert!(
            held <= EVICTION_THRESHOLD + 1,
            "expected a sweep to bound the map, held {held}"
        );
    }

    /// A live bucket must survive the sweep, or the limiter would forget quota it is
    /// still enforcing.
    #[tokio::test(start_paused = true)]
    async fn eviction_keeps_buckets_that_still_constrain() {
        let limits =
            RateLimits::unlimited().with_scope(Scope::DnsApiPerDomainExpensive, [rate("2/h")]);
        let limiter = Limiter::new(limits, Duration::from_secs(1));
        let hot = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, "hot.example");

        limiter.acquire(&hot).await.expect("first");
        limiter.acquire(&hot).await.expect("second");

        for i in 0..EVICTION_THRESHOLD + 10 {
            let domain = format!("zone-{i}.example");
            let scopes = ScopeSet::per_domain(Scope::DnsApiPerDomainExpensive, &domain);
            limiter.acquire(&scopes).await.expect("fresh zone");
        }

        // The hot domain is still at its hourly limit despite the sweep.
        let err = limiter
            .acquire(&hot)
            .await
            .expect_err("hot bucket was not forgotten");
        assert!(matches!(err, Error::RateLimitWouldBlock { .. }), "{err:?}");
    }

    /// `Scope::User` is appended to every set, so a set built *for* it must not list it
    /// twice and charge the window double.
    #[tokio::test(start_paused = true)]
    async fn the_user_scope_is_not_double_counted() {
        let limits = RateLimits::unlimited().with_scope(Scope::User, [rate("2/min")]);
        let limiter = Limiter::new(limits, Duration::from_secs(1));
        let scopes = ScopeSet::new(Scope::User);

        let start = Instant::now();
        limiter.acquire(&scopes).await.expect("first");
        limiter.acquire(&scopes).await.expect("second");
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[test]
    fn rejects_a_period_that_would_overflow_the_clock() {
        assert!(Rate::new(1, Duration::MAX).is_err());
        assert!(Rate::new(1, Duration::from_secs(367 * 86_400)).is_err());
        assert!(Rate::new(1, Duration::from_secs(366 * 86_400)).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn unlimited_never_waits() {
        let limiter = Limiter::new(RateLimits::unlimited(), Duration::ZERO);
        let scopes = ScopeSet::new(Scope::DnsApiCheap);
        let start = Instant::now();
        for _ in 0..1_000 {
            limiter
                .acquire(&scopes)
                .await
                .expect("no limits configured");
        }
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
}
