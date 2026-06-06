#![allow(dead_code)]

use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::warn;

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests per window
    pub max_requests: u32,
    /// Time window in seconds
    pub window_seconds: u64,
    /// Maximum binary size in bytes (default: 100MB)
    pub max_binary_size: usize,
    /// Maximum batch size for batch operations
    pub max_batch_size: usize,
    /// Allowed file extensions for binary upload
    pub allowed_extensions: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        RateLimitConfig {
            max_requests: 100,
            window_seconds: 60,
            max_binary_size: 100 * 1024 * 1024, // 100MB
            max_batch_size: 10,
            allowed_extensions: vec![
                "exe".to_string(),
                "dll".to_string(),
                "so".to_string(),
                "dylib".to_string(),
                "elf".to_string(),
                "bin".to_string(),
                "".to_string(), // Allow extensionless files
            ],
        }
    }
}

/// Request tracking for a single IP
#[derive(Debug)]
struct RequestTracker {
    requests: Vec<Instant>,
    blocked_until: Option<Instant>,
}

impl RequestTracker {
    fn new() -> Self {
        RequestTracker {
            requests: Vec::new(),
            blocked_until: None,
        }
    }

    fn is_blocked(&self) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            if Instant::now() < blocked_until {
                return true;
            }
        }
        false
    }

    fn add_request(&mut self, max_requests: u32, window: Duration) -> bool {
        let now = Instant::now();

        // Remove old requests outside the window
        self.requests.retain(|&t| now.duration_since(t) < window);

        if self.requests.len() >= max_requests as usize {
            // Block for twice the window duration
            self.blocked_until = Some(now + window * 2);
            return false;
        }

        self.requests.push(now);
        true
    }

    fn cleanup(&mut self, window: Duration) {
        let now = Instant::now();
        self.requests.retain(|&t| now.duration_since(t) < window);
        if let Some(blocked_until) = self.blocked_until {
            if now >= blocked_until {
                self.blocked_until = None;
            }
        }
    }
}

/// Rate limiter state
pub struct RateLimiter {
    trackers: Mutex<HashMap<String, RequestTracker>>,
    config: RateLimitConfig,
    last_cleanup: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Arc<Self> {
        Arc::new(RateLimiter {
            trackers: Mutex::new(HashMap::new()),
            config,
            last_cleanup: Mutex::new(Instant::now()),
        })
    }

    pub fn default_limiter() -> Arc<Self> {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a request from the given IP should be allowed
    pub fn check_rate_limit(&self, ip: &str) -> bool {
        let mut trackers = self.trackers.lock().unwrap();

        // Periodic cleanup every 5 minutes
        let now = Instant::now();
        {
            let mut last_cleanup = self.last_cleanup.lock().unwrap();
            if now.duration_since(*last_cleanup) > Duration::from_secs(300) {
                let window = Duration::from_secs(self.config.window_seconds);
                for tracker in trackers.values_mut() {
                    tracker.cleanup(window);
                }
                trackers.retain(|_, tracker| {
                    !tracker.requests.is_empty() || tracker.blocked_until.is_some()
                });
                *last_cleanup = now;
            }
        }

        let tracker = trackers.entry(ip.to_string()).or_insert_with(RequestTracker::new);

        if tracker.is_blocked() {
            return false;
        }

        let window = Duration::from_secs(self.config.window_seconds);
        tracker.add_request(self.config.max_requests, window)
    }

    /// Get current rate limit status for an IP
    pub fn get_status(&self, ip: &str) -> RateLimitStatus {
        let trackers = self.trackers.lock().unwrap();
        let tracker = trackers.get(ip);

        match tracker {
            Some(t) => {
                let now = Instant::now();
                let window = Duration::from_secs(self.config.window_seconds);
                let requests_in_window = t
                    .requests
                    .iter()
                    .filter(|&&t| now.duration_since(t) < window)
                    .count() as u32;

                RateLimitStatus {
                    allowed: !t.is_blocked(),
                    remaining: self.config.max_requests.saturating_sub(requests_in_window),
                    limit: self.config.max_requests,
                    reset_after: self.config.window_seconds,
                }
            }
            None => RateLimitStatus {
                allowed: true,
                remaining: self.config.max_requests,
                limit: self.config.max_requests,
                reset_after: self.config.window_seconds,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitStatus {
    pub allowed: bool,
    pub remaining: u32,
    pub limit: u32,
    pub reset_after: u64,
}

/// Middleware function for rate limiting
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    // Extract rate limiter from extensions if available
    let rate_limiter = request
        .extensions()
        .get::<Arc<RateLimiter>>()
        .cloned()
        .unwrap_or_else(RateLimiter::default_limiter);

    let ip = addr.ip().to_string();

    if !rate_limiter.check_rate_limit(&ip) {
        warn!("Rate limit exceeded for IP: {}", ip);
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "60")],
            "Rate limit exceeded. Please try again later.",
        )
            .into_response();
    }

    next.run(request).await
}

/// Input validation for binary paths
pub fn validate_binary_path(path: &str) -> Result<(), ValidationError> {
    // Check for path traversal attempts
    if path.contains("..") || path.contains("//") {
        return Err(ValidationError::PathTraversal);
    }

    // Check for null bytes
    if path.contains('\0') {
        return Err(ValidationError::InvalidCharacters);
    }

    // Check path length
    if path.len() > 4096 {
        return Err(ValidationError::PathTooLong);
    }

    // Only allow absolute paths or relative paths within current directory
    if !path.starts_with('/') && !path.starts_with("./") && !path.starts_with("../") {
        // Allow simple relative paths
    }

    Ok(())
}

/// Input validation for function addresses
pub fn validate_address(addr: &str) -> Result<u64, ValidationError> {
    // Must start with 0x for hex
    if !addr.starts_with("0x") && !addr.starts_with("0X") {
        return Err(ValidationError::InvalidAddressFormat);
    }

    let hex_str = &addr[2..];

    // Check length (max 16 hex digits for 64-bit)
    if hex_str.len() > 16 {
        return Err(ValidationError::AddressTooLarge);
    }

    // Parse hex
    match u64::from_str_radix(hex_str, 16) {
        Ok(addr) => Ok(addr),
        Err(_) => Err(ValidationError::InvalidAddressFormat),
    }
}

/// Validate binary ID format
pub fn validate_binary_id(id: &str) -> Result<(), ValidationError> {
    if id.len() > 256 {
        return Err(ValidationError::InvalidId);
    }

    // Allow alphanumeric, hyphens, and underscores
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(ValidationError::InvalidId);
    }

    Ok(())
}

/// Validate annotation text
pub fn validate_annotation_text(text: &str) -> Result<(), ValidationError> {
    if text.is_empty() {
        return Err(ValidationError::EmptyText);
    }

    if text.len() > 10000 {
        return Err(ValidationError::TextTooLong);
    }

    // Check for potential XSS in annotations
    if text.contains("<script>") || text.contains("javascript:") {
        return Err(ValidationError::InvalidCharacters);
    }

    Ok(())
}

/// Validate plugin path
pub fn validate_plugin_path(path: &str) -> Result<(), ValidationError> {
    validate_binary_path(path)?;

    // Plugin files should be .so on Linux, .dll on Windows, .dylib on macOS
    let allowed = [".so", ".dll", ".dylib"];
    if !allowed.iter().any(|ext| path.ends_with(ext)) {
        return Err(ValidationError::InvalidPluginExtension);
    }

    Ok(())
}

/// Input validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationError {
    PathTraversal,
    InvalidCharacters,
    PathTooLong,
    InvalidAddressFormat,
    AddressTooLarge,
    InvalidId,
    EmptyText,
    TextTooLong,
    InvalidPluginExtension,
    BinaryTooLarge,
    BatchTooLarge,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::PathTraversal => write!(f, "Path traversal attempt detected"),
            ValidationError::InvalidCharacters => {
                write!(f, "Invalid characters in input")
            }
            ValidationError::PathTooLong => write!(f, "Path too long (max 4096 characters)"),
            ValidationError::InvalidAddressFormat => {
                write!(f, "Invalid address format (expected 0x...)")
            }
            ValidationError::AddressTooLarge => write!(f, "Address too large"),
            ValidationError::InvalidId => write!(f, "Invalid ID format"),
            ValidationError::EmptyText => write!(f, "Text cannot be empty"),
            ValidationError::TextTooLong => write!(f, "Text too long (max 10000 characters)"),
            ValidationError::InvalidPluginExtension => {
                write!(f, "Invalid plugin extension (expected .so, .dll, or .dylib)")
            }
            ValidationError::BinaryTooLarge => write!(f, "Binary file too large"),
            ValidationError::BatchTooLarge => write!(f, "Batch size too large"),
        }
    }
}

impl std::error::Error for ValidationError {}

impl IntoResponse for ValidationError {
    fn into_response(self) -> Response {
        let status = match &self {
            ValidationError::PathTraversal
            | ValidationError::InvalidCharacters
            | ValidationError::InvalidAddressFormat
            | ValidationError::InvalidId
            | ValidationError::EmptyText
            | ValidationError::InvalidPluginExtension => StatusCode::BAD_REQUEST,
            ValidationError::PathTooLong
            | ValidationError::AddressTooLarge
            | ValidationError::TextTooLong
            | ValidationError::BinaryTooLarge
            | ValidationError::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        };

        (status, self.to_string()).into_response()
    }
}

/// Security headers middleware
pub async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'none'; object-src 'none'"
            .parse()
            .unwrap(),
    );
    headers.insert("Referrer-Policy", "strict-origin-when-cross-origin".parse().unwrap());

    response
}

/// Request size limit middleware
pub async fn request_size_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check content length header
    if let Some(content_length) = request.headers().get(axum::http::header::CONTENT_LENGTH) {
        if let Ok(len_str) = content_length.to_str() {
            if let Ok(len) = len_str.parse::<u64>() {
                // 50MB limit for requests
                if len > 50 * 1024 * 1024 {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Sanitize a string for safe display (basic XSS prevention)
pub fn sanitize_for_display(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 3,
            window_seconds: 60,
            max_binary_size: 100 * 1024 * 1024,
            max_batch_size: 10,
            allowed_extensions: vec!["exe".to_string()],
        });

        let ip = "127.0.0.1";

        // First 3 requests should pass
        assert!(limiter.check_rate_limit(ip));
        assert!(limiter.check_rate_limit(ip));
        assert!(limiter.check_rate_limit(ip));

        // 4th request should be blocked
        assert!(!limiter.check_rate_limit(ip));

        // Check status
        let status = limiter.get_status(ip);
        assert!(!status.allowed);
        assert_eq!(status.remaining, 0);
    }

    #[test]
    fn test_rate_limiter_different_ips() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_requests: 2,
            window_seconds: 60,
            max_binary_size: 100 * 1024 * 1024,
            max_batch_size: 10,
            allowed_extensions: vec!["exe".to_string()],
        });

        assert!(limiter.check_rate_limit("1.1.1.1"));
        assert!(limiter.check_rate_limit("1.1.1.1"));
        assert!(!limiter.check_rate_limit("1.1.1.1"));

        // Different IP should not be affected
        assert!(limiter.check_rate_limit("2.2.2.2"));
    }

    #[test]
    fn test_validate_binary_path() {
        assert!(validate_binary_path("/bin/ls").is_ok());
        assert!(validate_binary_path("./test.exe").is_ok());
        assert!(validate_binary_path("test.exe").is_ok());

        assert_eq!(
            validate_binary_path("/etc/../passwd"),
            Err(ValidationError::PathTraversal)
        );
        assert_eq!(
            validate_binary_path("/etc//passwd"),
            Err(ValidationError::PathTraversal)
        );
    }

    #[test]
    fn test_validate_address() {
        assert_eq!(validate_address("0x1000"), Ok(0x1000));
        assert_eq!(validate_address("0xABCDEF"), Ok(0xABCDEF));
        assert_eq!(validate_address("0x0"), Ok(0));

        assert_eq!(
            validate_address("1000"),
            Err(ValidationError::InvalidAddressFormat)
        );
        assert_eq!(
            validate_address("0xGGGG"),
            Err(ValidationError::InvalidAddressFormat)
        );
        assert_eq!(
            validate_address("0x1234567890ABCDEF0"),
            Err(ValidationError::AddressTooLarge)
        );
    }

    #[test]
    fn test_validate_binary_id() {
        assert!(validate_binary_id("bin_123").is_ok());
        assert!(validate_binary_id("bin-123").is_ok());
        assert!(validate_binary_id("abc123").is_ok());

        assert_eq!(
            validate_binary_id("bin@123"),
            Err(ValidationError::InvalidId)
        );
    }

    #[test]
    fn test_validate_annotation_text() {
        assert!(validate_annotation_text("Hello world").is_ok());

        assert_eq!(
            validate_annotation_text(""),
            Err(ValidationError::EmptyText)
        );

        assert_eq!(
            validate_annotation_text("<script>alert(1)</script>"),
            Err(ValidationError::InvalidCharacters)
        );
    }

    #[test]
    fn test_validate_plugin_path() {
        assert!(validate_plugin_path("/plugins/test.so").is_ok());
        assert!(validate_plugin_path("./plugin.dll").is_ok());
        assert!(validate_plugin_path("plugin.dylib").is_ok());

        assert_eq!(
            validate_plugin_path("/plugins/test.exe"),
            Err(ValidationError::InvalidPluginExtension)
        );
    }

    #[test]
    fn test_sanitize_for_display() {
        assert_eq!(
            sanitize_for_display("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(
            sanitize_for_display("\"quoted\""),
            "&quot;quoted&quot;"
        );
    }

    #[test]
    fn test_rate_limit_status() {
        let limiter = RateLimiter::default_limiter();
        let status = limiter.get_status("127.0.0.1");

        assert!(status.allowed);
        assert_eq!(status.limit, 100);
        assert_eq!(status.remaining, 100);
        assert_eq!(status.reset_after, 60);
    }

    #[test]
    fn test_request_tracker_cleanup() {
        let mut tracker = RequestTracker::new();
        let window = Duration::from_secs(1);

        // Add some requests
        tracker.add_request(10, window);
        tracker.add_request(10, window);

        assert_eq!(tracker.requests.len(), 2);

        // Wait for window to expire
        std::thread::sleep(Duration::from_secs(2));
        tracker.cleanup(window);

        assert!(tracker.requests.is_empty());
    }

    #[test]
    fn test_validation_error_display() {
        assert_eq!(
            ValidationError::PathTraversal.to_string(),
            "Path traversal attempt detected"
        );
        assert_eq!(
            ValidationError::InvalidAddressFormat.to_string(),
            "Invalid address format (expected 0x...)"
        );
    }
}
