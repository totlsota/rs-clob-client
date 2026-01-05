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

#[cfg(feature = "rate-limiting")]
mod implementation {
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
    #[non_exhaustive]
    #[derive(Clone, Debug)]
    pub struct Spec {
        /// Unique key for this endpoint
        pub key: &'static str,
        /// The rate limit quota
        pub quota: Quota,
        /// Optional API-level quota
        pub api_quota: Option<GovernorQuota>,
    }

    /// Parses a quota string literal like "1500/10s" into (count, period).
    ///
    /// Used by the `check!` macro to parse quota strings.
    ///
    /// # Panics
    ///
    /// Panics if the format is invalid.
    #[must_use]
    pub fn parse_quota_literal(quota: &str) -> (u32, &str) {
        let (count, period) = quota
            .split_once('/')
            .expect("Invalid quota format: expected 'count/period' (e.g., '1500/10s')");

        (
            count.parse().expect("Count must be convertible to u32"),
            period,
        )
    }

    /// Parses a quota from count and period string.
    ///
    /// Period format: "10s" (10 seconds), "1m" (1 minute), "10m" (10 minutes)
    ///
    /// # Panics
    ///
    /// Panics if the period format is invalid.
    #[must_use]
    pub fn parse_quota(count: u32, period: &str) -> GovernorQuota {
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
        pub(crate) global: Option<Limiter>,
    }

    impl RateLimiters {
        /// Creates a new rate limiters instance.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Creates rate limiters with a global quota.
        #[must_use]
        pub fn with_global(global: Limiter) -> Self {
            Self {
                limiters: DashMap::new(),
                global: Some(global),
            }
        }

        /// Gets or creates a rate limiter for the given key and quota.
        fn get_or_create_limiter(&self, key: &str, quota: GovernorQuota) -> Limiter {
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
        pub async fn check_api_limit(&self, api: &str, quota: GovernorQuota) -> crate::Result<()> {
            let api_key = format!("{api}_api");
            let limiter = self.get_or_create_limiter(&api_key, quota);
            limiter.until_ready().await;

            if let Some(global_limiter) = &self.global {
                global_limiter.until_ready().await;
            }

            Ok(())
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
        pub async fn check_spec(&self, spec: &Spec) -> crate::Result<()> {
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

            let global_fut = async move {
                if let Some(global) = &self.global {
                    global.until_ready().await;
                }
            };

            join!(endpoint_fut, api_fut, global_fut);

            Ok(())
        }
    }
}

#[cfg(feature = "rate-limiting")]
pub use implementation::*;

/// Macro to check rate limits at the start of a method.
///
/// This macro is only active when the `rate-limiting` feature is enabled.
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
#[macro_export]
macro_rules! check {
    // API-only rate limiting
    ($self:expr, api_only: $api:expr, quota: $quota:expr) => {{
        #[cfg(feature = "rate-limiting")]
        {
            let limiters = &$self.rate_limiters;
            let (count, period) = $crate::rate_limit::parse_quota_literal($quota);
            let api_quota = $crate::rate_limit::parse_quota(count, period);
            limiters.check_api_limit($api, api_quota).await?;
        }
    }};

    // Single quota with optional API quota
    ($self:expr, key: $key:expr, quota: $quota:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limiting")]
        {
            let limiters = &$self.rate_limiters;
            let (count, period) = $crate::rate_limit::parse_quota_literal($quota);
            let quota = $crate::rate_limit::parse_quota(count, period);

            $(let api_quota = {
                let (count, period) = $crate::rate_limit::parse_quota_literal($api_quota);
                Some($crate::rate_limit::parse_quota(count, period))
            };)?
            let api_quota = None $( .or(Some({
                let (count, period) = $crate::rate_limit::parse_quota_literal($api_quota);
                $crate::rate_limit::parse_quota(count, period)
            })) )?;

            let spec = $crate::rate_limit::Spec {
                key: $key,
                quota: $crate::rate_limit::Quota::Single(quota),
                api_quota,
            };
            limiters.check_spec(&spec).await?;
        }
    }};

    // Multi-window quota (burst + sustained)
    ($self:expr, key: $key:expr, burst: $burst:expr, sustained: $sustained:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limiting")]
        {
            let limiters = &$self.rate_limiters;
            let (burst_count, burst_period) = $crate::rate_limit::parse_quota_literal($burst);
            let burst_quota = $crate::rate_limit::parse_quota(burst_count, burst_period);

            let (sustained_count, sustained_period) = $crate::rate_limit::parse_quota_literal($sustained);
            let sustained_quota = $crate::rate_limit::parse_quota(sustained_count, sustained_period);

            $(let api_quota = {
                let (count, period) = $crate::rate_limit::parse_quota_literal($api_quota);
                Some($crate::rate_limit::parse_quota(count, period))
            };)?
            let api_quota = None $( .or(Some({
                let (count, period) = $crate::rate_limit::parse_quota_literal($api_quota);
                $crate::rate_limit::parse_quota(count, period)
            })) )?;

            let spec = $crate::rate_limit::Spec {
                key: $key,
                quota: $crate::rate_limit::Quota::MultiWindow {
                    burst: burst_quota,
                    sustained: sustained_quota,
                },
                api_quota,
            };
            limiters.check_spec(&spec).await?;
        }
    }};
}

// Re-export at crate level for easier access
pub use check;

#[cfg(all(test, feature = "rate-limiting"))]
mod tests {
    use std::sync::Arc;

    use governor::RateLimiter;

    use super::*;

    #[test]
    fn parse_quota_str_works() {
        let q = parse_quota(100, "10s");
        assert_eq!(q.burst_size().get(), 100);

        let q = parse_quota(60, "1m");
        assert_eq!(q.burst_size().get(), 60);

        let q = parse_quota(1000, "10m");
        assert_eq!(q.burst_size().get(), 1000);
    }

    #[tokio::test]
    async fn rate_limiters_can_be_created() {
        let limiters = RateLimiters::new();
        assert!(limiters.global.is_none());

        let global = Arc::new(RateLimiter::direct(parse_quota(10000, "10s")));
        let limiters = RateLimiters::with_global(global);
        assert!(limiters.global.is_some());
    }

    #[tokio::test]
    async fn rate_limiting_check_spec_works() {
        let limiters = RateLimiters::new();
        let spec = Spec {
            key: "test",
            quota: Quota::Single(parse_quota(1000, "10s")),
            api_quota: None,
        };

        // Should not error
        let result = limiters.check_spec(&spec).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn multi_window_quota_works() {
        let limiters = RateLimiters::new();
        let spec = Spec {
            key: "test_multi",
            quota: Quota::MultiWindow {
                burst: parse_quota(100, "10s"),
                sustained: parse_quota(1000, "10m"),
            },
            api_quota: None,
        };

        let result = limiters.check_spec(&spec).await;
        result.unwrap();
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
            .check_api_limit("data", parse_quota(1000, "10s"))
            .await?;

        Ok(())
    }
}
