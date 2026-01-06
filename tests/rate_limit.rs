//! Integration tests for rate limiting functionality
//!
//! These tests verify that rate limiting actually throttles requests as expected.
#![allow(clippy::print_stdout, reason = "Tests are okay to print to stdout")]
#![cfg(feature = "rate-limit")]

use std::sync::Arc;
use std::time::Instant;

use polymarket_client_sdk::rate_limit::RateLimiters;

/// Mock client for testing rate limiting without making actual HTTP requests.
///
/// This client simulates API endpoints with configurable rate limits.
#[non_exhaustive]
#[derive(Clone, Debug)]
struct MockClient {
    rate_limiters: Arc<RateLimiters>,
}

impl MockClient {
    /// Creates a new mock client with default rate limiters.
    fn new() -> Self {
        Self {
            rate_limiters: Arc::new(RateLimiters::new()),
        }
    }

    /// Mock endpoint with a single quota limit.
    ///
    /// This simulates a lightweight API call that returns immediately after
    /// passing rate limit checks.
    async fn mock_endpoint_single(&self, key: &'static str, quota: &str) {
        polymarket_client_sdk::check!(self, key: key, quota: quota);
    }

    /// Mock endpoint with multi-window quota (burst + sustained).
    async fn mock_endpoint_multi(&self, key: &'static str, burst: &str, sustained: &str) {
        polymarket_client_sdk::check!(self, key: key, burst: burst, sustained: sustained);
    }

    /// Mock endpoint with API-level quota only.
    async fn mock_endpoint_api_only(&self, api: &str, quota: &str) {
        polymarket_client_sdk::check!(self, api_only: api, quota: quota);
    }
}

/// Test that mock client is fast and doesn't make HTTP requests.
///
/// This demonstrates the value of the mock client - tests run instantly.
#[tokio::test]
async fn mock_client_is_fast() {
    let client = MockClient::new();
    let start = Instant::now();

    // Make 10 requests with a generous quota - should complete almost instantly
    for _ in 0..10 {
        client.mock_endpoint_single("fast_test", "100/10s").await;
    }

    let elapsed = start.elapsed();

    // Should complete in well under a second (no HTTP overhead)
    assert!(
        elapsed.as_millis() < 1000,
        "Mock requests should be fast (got {elapsed:?})"
    );
}

/// Test rate limiting with multiple rapid requests using mock client.
///
/// This test makes 5 requests at a 2/10s rate and verifies the timing.
#[tokio::test]
async fn mock_rate_limiting_with_multiple_requests() {
    let client = MockClient::new();
    let start = Instant::now();

    for i in 0..5 {
        let req_start = Instant::now();
        polymarket_client_sdk::check!(client, key: "multi_test", quota: "2/1s");

        let req_elapsed = req_start.elapsed();
        let total_elapsed = start.elapsed();
        println!("{i} REQ elapsed: {req_elapsed:?}");
        println!("{i} Total: {total_elapsed:?}\n");
    }

    let total = start.elapsed();

    // 5 requests at 2/10s rate:
    // - Requests 1-2: immediate (within burst)
    // - Request 3: waits ~1s
    // - Request 4: waits ~2s
    // - Request 5: waits ~3s
    // Total should be ~3 seconds
    assert!(
        total.as_secs() >= 3 && total.as_secs() <= 4,
        "Expected ~3s for 5 requests at 2/1s (got {total:?})"
    );
}

/// Test API-level rate limiting shared across different endpoints using mock client.
#[tokio::test]
async fn mock_api_level_rate_limit_shared() {
    let client = MockClient::new();
    let start = Instant::now();

    // API limit of 3/10s shared across all endpoints using the same API
    // First 3 requests should be fast (allowing for initialization overhead)
    client.mock_endpoint_api_only("test_api", "3/1s").await;
    client.mock_endpoint_api_only("test_api", "3/1s").await;
    client.mock_endpoint_api_only("test_api", "3/1s").await;

    let after_three = start.elapsed();
    assert!(
        after_three.as_millis() < 500,
        "First 3 requests should be fast"
    );

    // Fourth request should wait ~10s regardless of endpoint
    client.mock_endpoint_api_only("test_api", "3/1s").await;

    let total = start.elapsed();
    println!("✓ Fourth request completed after {total:?}");

    assert!(
        total.as_secs() >= 1,
        "Fourth request should hit API limit (got {total:?})"
    );
}

/// Test multi-window quota (burst + sustained) using mock client.
///
/// This test verifies that both burst and sustained limits work correctly.
#[tokio::test]
async fn mock_multi_window_quota() {
    let client = MockClient::new();
    let start = Instant::now();

    // Burst: 3/10s, Sustained: 5/10s
    // This means we can make 3 requests immediately (burst),
    // then we're limited by the sustained rate

    // First 3 requests should be immediate (within burst, allowing for initialization overhead)
    for _ in 1..=3 {
        client
            .mock_endpoint_multi("multi_window", "3/1s", "5/1s")
            .await;
    }

    let after_burst = start.elapsed();
    assert!(
        after_burst.as_millis() < 500,
        "First 3 requests (burst) should be fast"
    );

    // Fourth request should wait for sustained rate
    client
        .mock_endpoint_multi("multi_window", "3/1s", "5/1s")
        .await;

    // Fifth request should also wait
    client
        .mock_endpoint_multi("multi_window", "3/1s", "5/1s")
        .await;

    let total = start.elapsed();

    // We should have waited for at least one period
    assert!(
        total.as_secs() >= 2,
        "Multi-window quota should enforce sustained limit (got {total:?})"
    );
}

/// Benchmark test: Measure actual throughput at a specific rate using mock client.
///
/// This test verifies that the rate limiter maintains the correct request rate.
#[tokio::test]
#[ignore = "Run with: `cargo test --features rate-limit -- --ignored --nocapture`"]
async fn benchmark_mock_rate_limiting_throughput() {
    let client = MockClient::new();
    let start = Instant::now();

    println!("🚀 Starting throughput benchmark (5 req/10s)...");

    // Make 15 requests
    for i in 0..15 {
        let req_start = Instant::now();
        client.mock_endpoint_single("benchmark", "5/10s").await;
        let req_time = req_start.elapsed();

        println!(
            "  Request {:2}: {:>8}ms (total: {:>5.1}s)",
            i + 1,
            req_time.as_millis(),
            start.elapsed().as_secs_f64()
        );
    }

    let total = start.elapsed();
    let rate = 15.0 / total.as_secs_f64();

    println!("\n📊 Results:");
    println!("  Total time: {total:?}");
    println!("  Requests:   15");
    println!("  Rate:       {rate:.2} req/s");
    println!("  Expected:   ~0.5 req/s (5 per 10s)");

    // 15 requests at 5/10s = should take ~30 seconds
    // Allow some variance
    assert!(
        total.as_secs() >= 28 && total.as_secs() <= 32,
        "Expected ~30s for 15 requests at 5/10s (got {total:?})"
    );

    // Verify rate is close to 0.5 req/s
    assert!(
        (0.45..=0.55).contains(&rate),
        "Rate should be ~0.5 req/s (got {rate:.2})"
    );
}
