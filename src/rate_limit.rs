//! Generic rate limiting framework for HTTP requests.
//!
//! This module provides a declarative rate limiting system using the token bucket
//! algorithm via the `governor` crate. Rate limits are declared using the `check!` macro.
//!
//! # Architecture
//!
//! - **`check!` macro**: Check rate limits at the start of methods
//! - **`RateLimiters`**: Manages rate limiter instances and checks requests
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::check;
//!
//! impl Client {
//!     pub async fn get_book(&self, req: &BookRequest) -> Result<Book> {
//!         check!(self, key: "book", quota: "1500/10s");
//!         // Make request
//!     }
//!
//!     pub async fn post_order(&self, req: &OrderRequest) -> Result<Order> {
//!         check!(self, key: "post_order", burst: "3500/10s", sustained: "36000/10m");
//!         // Make request
//!     }
//! }
//! ```
//!
//! See <https://docs.polymarket.com/quickstart/introduction/rate-limits> for Polymarket's limits.

#[cfg(feature = "rate-limit")]
pub(crate) mod implementation {
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::time::Duration;

    use dashmap::DashMap;
    use futures::join;
    use governor::{
        Quota as GovernorQuota, RateLimiter,
        clock::DefaultClock,
        state::{InMemoryState, NotKeyed},
    };

    /// Type alias for a rate limiter instance.
    pub type Limiter = Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>;

    /// Rate limit quota specification.
    #[non_exhaustive]
    #[derive(Clone, Debug)]
    pub enum Quota {
        /// Single time window quota
        Single(GovernorQuota),
        /// Multi-window quota (both burst and sustained limits must be satisfied)
        MultiWindow {
            burst: GovernorQuota,
            sustained: GovernorQuota,
        },
    }

    /// Specification for an endpoint's rate limits.
    #[expect(
        clippy::exhaustive_structs,
        reason = "The macro creates these manually, and since the macro runs in test (public) code we have to ignore this."
    )]
    #[derive(Clone, Debug)]
    pub struct Spec {
        /// Unique key for this endpoint
        pub key: &'static str,
        /// The rate limit quota
        pub quota: Quota,
        /// Optional API-level quota
        pub api_quota: Option<GovernorQuota>,
    }

    impl Spec {
        /// Creates a new spec with the given key and quota.
        #[must_use]
        pub fn new(key: &'static str, quota: Quota) -> Self {
            Self {
                key,
                quota,
                api_quota: None,
            }
        }

        /// Creates a new spec with the given key, quota, and API quota.
        #[must_use]
        pub fn with_api_quota(key: &'static str, quota: Quota, api_quota: GovernorQuota) -> Self {
            Self {
                key,
                quota,
                api_quota: Some(api_quota),
            }
        }
    }

    /// Parses a quota from count and period string.
    ///
    /// Period format: "10s" (10 seconds), "1m" (1 minute), "10m" (10 minutes)
    ///
    /// # Panics
    ///
    /// Panics if the period format is invalid.
    #[must_use]
    pub fn parse_quota(quota: &str) -> GovernorQuota {
        let (count, period) = quota
            .split_once('/')
            .expect("Invalid quota format: expected 'count/period' (e.g., '1500/10s')");

        let count = count.parse().expect("Count must be convertible to u32");

        let duration = match period {
            "1s" => Duration::from_secs(1),
            "10s" => Duration::from_secs(10),
            "1m" | "60s" => Duration::from_secs(60),
            "10m" | "600s" => Duration::from_secs(600),
            _ => panic!("Unsupported period: {period}. Supported: 1s, 10s, 1m, 10m"),
        };

        GovernorQuota::with_period(duration)
            .unwrap_or_else(|| panic!("Invalid quota period: {period}"))
            .allow_burst(NonZeroU32::new(count).expect("count must be non-zero"))
    }

    /// Manages rate limiters for API endpoints.
    ///
    /// Rate limiters are created lazily when first accessed and cached for reuse.
    #[non_exhaustive]
    #[derive(Debug, Default)]
    pub struct RateLimiters {
        limiters: DashMap<String, Limiter>,
    }

    impl RateLimiters {
        /// Creates a new rate limiters instance.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Gets or creates a rate limiter for the given key and quota.
        #[must_use]
        pub fn get_or_create_limiter(&self, key: &str, quota: GovernorQuota) -> Limiter {
            self.limiters
                .entry(key.to_owned())
                .or_insert_with(|| Arc::new(RateLimiter::direct(quota)))
                .clone()
        }

        /// Checks an API-level rate limit, waiting if necessary.
        ///
        /// This creates or gets a rate limiter for the API (e.g., "`clob_api`", "`gamma_api`")
        /// and waits until the quota is available.
        ///
        /// # Errors
        ///
        /// Returns Ok after waiting for quota to be available.
        pub async fn check_api_limit(&self, api: &str, quota: GovernorQuota) {
            let api_key = format!("{api}_api");
            let limiter = self.get_or_create_limiter(&api_key, quota);
            limiter.until_ready().await;
        }

        /// Checks rate limits for a specification, waiting if necessary.
        ///
        /// This checks rate limits concurrently:
        /// 1. Endpoint-specific limit(s)
        /// 2. API-level limit (if configured)
        /// 3. Global limit (if configured)
        ///
        /// # Errors
        ///
        /// Currently, always returns Ok after waiting. Future versions may support fail-fast.
        pub async fn check_spec(&self, spec: &Spec) {
            let endpoint_fut = async move {
                match &spec.quota {
                    Quota::Single(quota) => {
                        self.get_or_create_limiter(spec.key, *quota)
                            .until_ready()
                            .await;
                    }
                    Quota::MultiWindow { burst, sustained } => {
                        // For multi-window, check both burst and sustained
                        let burst_key = format!("{}_burst", spec.key);
                        let sustained_key = format!("{}_sustained", spec.key);

                        let burst_limiter = self.get_or_create_limiter(&burst_key, *burst);
                        let sustained_limiter =
                            self.get_or_create_limiter(&sustained_key, *sustained);

                        // If the burst limiter passes the check, regardless of the sustained limiter,
                        // we'll allow the request through. If we exceed the burst allowance, we
                        // must wait for that limiter to be ready. If both limiters are not ready,
                        // wait for both.
                        match (burst_limiter.check(), sustained_limiter.check()) {
                            (Ok(()), _) => {}
                            (Err(_), Ok(())) => burst_limiter.until_ready().await,
                            (Err(_), Err(_)) => {
                                join!(sustained_limiter.until_ready(), burst_limiter.until_ready());
                            }
                        }
                    }
                }
            };

            let api_fut = async move {
                if let Some(quota) = spec.api_quota {
                    let api = spec.key.split('_').next().unwrap_or("unknown");
                    let api_key = format!("{api}_api");
                    let limiter = self.get_or_create_limiter(&api_key, quota);
                    limiter.until_ready().await;
                }
            };

            join!(endpoint_fut, api_fut);
        }
    }
}

#[cfg(feature = "rate-limit")]
pub use implementation::*;

/// Macro to check rate limits at the start of a method.
///
/// This macro is only active when the `rate-limit` feature is enabled.
/// When disabled, it compiles to nothing (zero overhead).
///
/// # Global Only
///
/// ```ignore
/// check!(self, global_only);
/// ```
///
/// # API-Level Only
///
/// ```ignore
/// check!(self, api_only: "clob", quota: "9000/10s");
/// check!(self, api_only: "gamma", quota: "4000/10s");
/// ```
///
/// # Single Quota
///
/// ```ignore
/// check!(self, key: "book", quota: "1500/10s");
/// ```
///
/// # Multi-Window Quota (burst + sustained)
///
/// ```ignore
/// check!(self, key: "post_order", burst: "3500/10s", sustained: "36000/10m");
/// ```
///
/// # With Endpoint and API Quotas
///
/// ```ignore
/// check!(self,
///     key: "book",
///     quota: "1500/10s",
///     api_quota: "9000/10s",
/// );
/// ```
// TODO: introduce stacked rate limiters to better match docs
#[macro_export]
macro_rules! check {
    // API-only rate limiting
    ($self:expr, api_only: $api:expr, quota: $quota:expr) => {{
        #[cfg(feature = "rate-limit")]
        {
            let limiters = &$self.rate_limiters;
            let api_quota = $crate::rate_limit::parse_quota($quota);
            limiters.check_api_limit($api, api_quota).await;
        }
    }};

    // Single quota with optional API quota
    ($self:expr, key: $key:expr, quota: $quota:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limit")]
        {
            let limiters = &$self.rate_limiters;
            let quota = $crate::rate_limit::parse_quota($quota);

            let api_quota = None $( .or(Some({
                $crate::rate_limit::parse_quota($api_quota)
            })) )?;

            let spec = $crate::rate_limit::Spec {
                key: $key,
                quota: $crate::rate_limit::Quota::Single(quota),
                api_quota,
            };
            limiters.check_spec(&spec).await;
        }
    }};

    // Multi-window quota (burst + sustained)
    ($self:expr, key: $key:expr, burst: $burst:expr, sustained: $sustained:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limit")]
        {
            let limiters = &$self.rate_limiters;
            let burst_quota = $crate::rate_limit::parse_quota($burst);
            let sustained_quota = $crate::rate_limit::parse_quota($sustained);

            let api_quota = None $( .or(Some({
                $crate::rate_limit::parse_quota($api_quota)
            })) )?;

            let spec = $crate::rate_limit::Spec {
                key: $key,
                quota: $crate::rate_limit::Quota::MultiWindow {
                    burst: burst_quota,
                    sustained: sustained_quota,
                },
                api_quota,
            };
            limiters.check_spec(&spec).await;
        }
    }};
}

#[cfg(all(test, feature = "rate-limit"))]
mod tests {
    use std::sync::Arc;

    use crate::rate_limit::implementation::{RateLimiters, parse_quota};

    #[test]
    fn parse_quota_str_works() {
        let q = parse_quota("100/10s");
        assert_eq!(q.burst_size().get(), 100);

        let q = parse_quota("60/1m");
        assert_eq!(q.burst_size().get(), 60);

        let q = parse_quota("1000/10m");
        assert_eq!(q.burst_size().get(), 1000);
    }

    #[tokio::test]
    async fn api_only_works() -> crate::Result<()> {
        struct MockClient {
            rate_limiters: Arc<RateLimiters>,
        }

        let limiters = RateLimiters::new();

        let client = MockClient {
            rate_limiters: Arc::new(limiters),
        };

        // This should not panic or error
        check!(client, api_only: "clob", quota: "9000/10s");

        // Check another API
        check!(client, api_only: "gamma", quota: "4000/10s");

        // Test direct method call
        client
            .rate_limiters
            .check_api_limit("data", parse_quota("1000/10s"))
            .await;

        Ok(())
    }
}
