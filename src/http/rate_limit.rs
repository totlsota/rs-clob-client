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
    pub fn parse_quota_str(count: u32, period: &str) -> GovernorQuota {
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

    /// Helper to create a 10-second quota.
    #[must_use]
    pub fn quota_10s(count: u32) -> GovernorQuota {
        parse_quota_str(count, "10s")
    }

    /// Helper to create a 1-minute quota.
    #[must_use]
    pub fn quota_1min(count: u32) -> GovernorQuota {
        parse_quota_str(count, "1m")
    }

    /// Helper to create a 10-minute quota.
    #[must_use]
    pub fn quota_10min(count: u32) -> GovernorQuota {
        parse_quota_str(count, "10m")
    }

    /// Manages rate limiters for API endpoints.
    ///
    /// Rate limiters are created lazily when first accessed and cached for reuse.
    #[non_exhaustive]
    #[derive(Debug, Default)]
    pub struct RateLimiters {
        limiters: DashMap<String, Limiter>,
        // TODO: way to supply this directly instead of a quota, since we'll have to clone
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
        pub fn with_global(global_quota: GovernorQuota) -> Self {
            Self {
                limiters: DashMap::new(),
                global: Some(Arc::new(RateLimiter::direct(global_quota))),
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
        /// This checks rate limits in order:
        /// 1. Endpoint-specific limit(s)
        /// 2. API-level limit (if configured)
        /// 3. Global limit (if configured)
        ///
        /// # Errors
        ///
        /// Currently, always returns Ok after waiting. Future versions may support fail-fast.
        // TODO: combine the async/awaits, check that they work for burst
        pub async fn check_spec(&self, spec: &Spec) -> crate::Result<()> {
            match &spec.quota {
                Quota::Single(quota) => {
                    let limiter = self.get_or_create_limiter(spec.key, *quota);
                    limiter.until_ready().await;
                }
                Quota::MultiWindow { burst, sustained } => {
                    // For multi-window, check both burst and sustained
                    let burst_key = format!("{}_burst", spec.key);
                    let sustained_key = format!("{}_sustained", spec.key);

                    let burst_limiter = self.get_or_create_limiter(&burst_key, *burst);
                    let sustained_limiter = self.get_or_create_limiter(&sustained_key, *sustained);

                    burst_limiter.until_ready().await;
                    sustained_limiter.until_ready().await;
                }
            }

            if let Some(api_quota) = spec.api_quota {
                let api = spec.key.split('_').next().unwrap_or("unknown");
                let api_key = format!("{api}_api");
                let limiter = self.get_or_create_limiter(&api_key, api_quota);
                limiter.until_ready().await;
            }

            if let Some(global_limiter) = &self.global {
                global_limiter.until_ready().await;
            }

            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_quota_str_works() {
            let q = parse_quota_str(100, "10s");
            assert_eq!(q.burst_size().get(), 100);

            let q = parse_quota_str(60, "1m");
            assert_eq!(q.burst_size().get(), 60);

            let q = parse_quota_str(1000, "10m");
            assert_eq!(q.burst_size().get(), 1000);
        }

        #[test]
        fn quota_helpers_work() {
            let q = quota_10s(100);
            assert_eq!(q.burst_size().get(), 100);

            let q = quota_1min(60);
            assert_eq!(q.burst_size().get(), 60);

            let q = quota_10min(1000);
            assert_eq!(q.burst_size().get(), 1000);
        }

        #[tokio::test]
        async fn rate_limiters_can_be_created() {
            let limiters = RateLimiters::new();
            assert!(limiters.global.is_none());

            let limiters = RateLimiters::with_global(quota_10s(10000));
            assert!(limiters.global.is_some());
        }

        #[tokio::test]
        async fn rate_limiting_check_spec_works() {
            let limiters = RateLimiters::new();
            let spec = Spec {
                key: "test",
                quota: Quota::Single(quota_10s(1000)),
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
                    burst: quota_10s(100),
                    sustained: quota_10min(1000),
                },
                api_quota: None,
            };

            // Should not error
            let result = limiters.check_spec(&spec).await;
            result.unwrap();
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
/// # With API and Global Quotas
///
/// ```ignore
/// check!(self,
///     key: "book",
///     quota: "1500/10s",
///     api_quota: "9000/10s",
///     global_quota: "15000/10s"
/// );
/// ```
#[macro_export]
macro_rules! check {
    // API-only rate limiting
    ($self:expr, api_only: $api:expr, quota: $quota:expr) => {{
        #[cfg(feature = "rate-limiting")]
        if let Some(ref limiters) = $self.rate_limiters {
            let (count, period) = $crate::http::rate_limit::parse_quota_literal($quota);
            let api_quota = $crate::http::rate_limit::parse_quota_str(count, period);
            limiters.check_api_limit($api, api_quota).await?;
        }
    }};

    // Single quota with optional API quota
    ($self:expr, key: $key:expr, quota: $quota:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limiting")]
        if let Some(ref limiters) = $self.rate_limiters {
            let (count, period) = $crate::http::rate_limit::parse_quota_literal($quota);
            let quota = $crate::http::rate_limit::parse_quota_str(count, period);

            $(let api_quota = {
                let (count, period) = $crate::http::rate_limit::parse_quota_literal($api_quota);
                Some($crate::http::rate_limit::parse_quota_str(count, period))
            };)?
            let api_quota = None $( .or(Some({
                let (count, period) = $crate::http::rate_limit::parse_quota_literal($api_quota);
                $crate::http::rate_limit::parse_quota_str(count, period)
            })) )?;

            let spec = $crate::http::rate_limit::Spec {
                key: $key,
                quota: $crate::http::rate_limit::Quota::Single(quota),
                api_quota,
            };
            limiters.check_spec(&spec).await?;
        }
    }};

    // Multi-window quota (burst + sustained)
    ($self:expr, key: $key:expr, burst: $burst:expr, sustained: $sustained:expr $(, api_quota: $api_quota:expr)? ) => {{
        #[cfg(feature = "rate-limiting")]
        if let Some(ref limiters) = $self.rate_limiters {
            let (burst_count, burst_period) = $crate::http::rate_limit::parse_quota_literal($burst);
            let burst_quota = $crate::http::rate_limit::parse_quota_str(burst_count, burst_period);

            let (sustained_count, sustained_period) = $crate::http::rate_limit::parse_quota_literal($sustained);
            let sustained_quota = $crate::http::rate_limit::parse_quota_str(sustained_count, sustained_period);

            $(let api_quota = {
                let (count, period) = $crate::http::rate_limit::parse_quota_literal($api_quota);
                Some($crate::http::rate_limit::parse_quota_str(count, period))
            };)?
            let api_quota = None $( .or(Some({
                let (count, period) = $crate::http::rate_limit::parse_quota_literal($api_quota);
                $crate::http::rate_limit::parse_quota_str(count, period)
            })) )?;

            let spec = $crate::http::rate_limit::Spec {
                key: $key,
                quota: $crate::http::rate_limit::Quota::MultiWindow {
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
    use super::*;

    #[test]
    fn parse_quota_str_works() {
        let q = parse_quota_str(100, "10s");
        assert_eq!(q.burst_size().get(), 100);

        let q = parse_quota_str(60, "1m");
        assert_eq!(q.burst_size().get(), 60);

        let q = parse_quota_str(1000, "10m");
        assert_eq!(q.burst_size().get(), 1000);
    }

    #[test]
    fn quota_helpers_work() {
        let q = quota_10s(100);
        assert_eq!(q.burst_size().get(), 100);

        let q = quota_1min(60);
        assert_eq!(q.burst_size().get(), 60);

        let q = quota_10min(1000);
        assert_eq!(q.burst_size().get(), 1000);
    }

    #[tokio::test]
    async fn rate_limiters_can_be_created() {
        let limiters = RateLimiters::new();
        assert!(limiters.global.is_none());

        let limiters = RateLimiters::with_global(quota_10s(10000));
        assert!(limiters.global.is_some());
    }

    #[tokio::test]
    async fn rate_limiting_check_spec_works() {
        let limiters = RateLimiters::new();
        let spec = Spec {
            key: "test",
            quota: Quota::Single(quota_10s(1000)),
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
                burst: quota_10s(100),
                sustained: quota_10min(1000),
            },
            api_quota: None,
        };

        let result = limiters.check_spec(&spec).await;
        result.unwrap();
    }

    #[tokio::test]
    async fn api_only_works() -> crate::Result<()> {
        struct MockClient {
            rate_limiters: Option<std::sync::Arc<RateLimiters>>,
        }

        let limiters = RateLimiters::new();

        let client = MockClient {
            rate_limiters: Some(std::sync::Arc::new(limiters)),
        };

        // This should not panic or error
        check!(client, api_only: "clob", quota: "9000/10s");

        // Check another API
        check!(client, api_only: "gamma", quota: "4000/10s");

        // Test direct method call
        if let Some(limiters) = &client.rate_limiters {
            limiters.check_api_limit("data", quota_10s(1000)).await?;
        }

        Ok(())
    }
}
