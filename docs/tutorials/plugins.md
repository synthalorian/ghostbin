# Plugin Development Tutorial

GhostBin's plugin system lets you write custom analyzers that integrate seamlessly with the analysis workflow.

## Overview

Plugins are dynamic libraries that implement the analyzer interface. They can:

- Analyze specific functions
- Scan for custom signatures
- Generate custom reports
- Integrate with the marketplace

## Writing a Plugin

### Plugin Interface

Plugins must implement this trait:

```rust
pub trait AnalyzerPlugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn analyze(&self, binary: &[u8], function: &str) -> AnalysisResult;
}

pub struct AnalysisResult {
    pub findings: Vec<Finding>,
    pub score: f64, // 0.0 to 1.0
}

pub struct Finding {
    pub severity: Severity,
    pub message: String,
    pub address: Option<u64>,
}

pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

### Example Plugin: Cryptographic Scanner

```rust
// my_plugin/src/lib.rs
use ghostbin_plugin::{AnalyzerPlugin, AnalysisResult, Finding, Severity};

pub struct CryptoScanner;

impl AnalyzerPlugin for CryptoScanner {
    fn name(&self) -> &str {
        "crypto-scanner"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn analyze(&self, binary: &[u8], _function: &str) -> AnalysisResult {
        let mut findings = Vec::new();

        // Look for common crypto constants
        let aes_sbox: &[u8] = &[0x63, 0x7c, 0x77, 0x7b, ...];
        if binary.windows(aes_sbox.len()).any(|w| w == aes_sbox) {
            findings.push(Finding {
                severity: Severity::Medium,
                message: "AES S-box detected".to_string(),
                address: None,
            });
        }

        AnalysisResult {
            findings,
            score: if findings.is_empty() { 0.0 } else { 0.5 },
        }
    }
}

#[no_mangle]
pub extern "C" fn create_plugin() -> Box<dyn AnalyzerPlugin> {
    Box::new(CryptoScanner)
}
```

### Building the Plugin

```bash
# Create library crate
cargo new --lib my_plugin

# In Cargo.toml
crate-type = ["cdylib"]

# Build
cargo build --release

# The plugin is at:
# ./target/release/libmy_plugin.so
```

## Loading a Plugin

### Via API

```bash
curl -X POST http://localhost:8081/api/plugins/load \
  -H "Content-Type: application/json" \
  -d '{"path": "/path/to/libmy_plugin.so"}'
```

### Via Web UI

Go to Plugins → Load Plugin and select the .so file.

## Running a Plugin

```bash
curl -X POST http://localhost:8081/api/plugins/crypto-scanner/analyze \
  -H "Content-Type: application/json" \
  -d '{"binary_id": "bin_0", "function_name": "main"}'
```

Response:
```json
{
  "findings": [
    {
      "severity": "Medium",
      "message": "AES S-box detected",
      "address": null
    }
  ],
  "score": 0.5
}
```

## Plugin Marketplace

### Publishing a Plugin

1. Create a plugin manifest:

```json
{
  "name": "crypto-scanner",
  "version": "1.0.0",
  "description": "Detects cryptographic implementations",
  "author": "Your Name",
  "category": "security",
  "tags": ["crypto", "aes", "rsa"],
  "repository": "https://github.com/you/crypto-scanner",
  "license": "MIT",
  "platforms": ["x86_64-linux", "aarch64-linux"]
}
```

2. Submit to the marketplace via the API or web UI.

### Installing from Marketplace

```bash
curl -X POST http://localhost:8081/api/marketplace/install \
  -d '{"plugin_name": "crypto-scanner", "version": "1.0.0"}'
```

## Best Practices

### Performance

- Keep analysis fast (< 1 second per function)
- Use efficient algorithms
- Avoid unnecessary allocations

### Error Handling

- Return empty findings instead of crashing
- Log errors for debugging
- Handle missing data gracefully

### Security

- Don't execute arbitrary code
- Validate all inputs
- Use bounded loops

### Documentation

- Document what your plugin detects
- Provide example outputs
- List known limitations

## Example Plugins

### String Pattern Matcher

```rust
pub struct StringMatcher {
    patterns: Vec<String>,
}

impl AnalyzerPlugin for StringMatcher {
    fn analyze(&self, binary: &[u8], _function: &str) -> AnalysisResult {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            if let Some(pos) = find_pattern(binary, pattern) {
                findings.push(Finding {
                    severity: Severity::Info,
                    message: format!("Pattern '{}' found at 0x{:x}", pattern, pos),
                    address: Some(pos as u64),
                });
            }
        }

        AnalysisResult { findings, score: 0.0 }
    }
}
```

### API Call Tracer

```rust
pub struct APITracer;

impl AnalyzerPlugin for APITracer {
    fn analyze(&self, binary: &[u8], function: &str) -> AnalysisResult {
        let mut findings = Vec::new();
        let suspicious_apis = ["CreateRemoteThread", "WriteProcessMemory"];

        for api in &suspicious_apis {
            if binary.windows(api.len()).any(|w| w == api.as_bytes()) {
                findings.push(Finding {
                    severity: Severity::High,
                    message: format!("Suspicious API: {}", api),
                    address: None,
                });
            }
        }

        AnalysisResult { findings, score: 0.8 }
    }
}
```

## Debugging Plugins

1. Build with debug symbols:
```bash
cargo build
```

2. Load the debug version:
```bash
curl -X POST http://localhost:8081/api/plugins/load \
  -d '{"path": "./target/debug/libmy_plugin.so"}'
```

3. Check server logs for errors

4. Use `RUST_LOG=debug` for verbose output:
```bash
RUST_LOG=debug cargo run
```

## Plugin Lifecycle

1. **Load** — Library is loaded into memory
2. **Analyze** — Called for each analysis request
3. **Unload** — Library is unloaded, resources freed

### Unloading

```bash
curl -X DELETE http://localhost:8081/api/plugins/crypto-scanner
```

## Advanced Topics

### Stateful Plugins

Plugins can maintain state between analyses (use with caution):

```rust
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref CACHE: Mutex<HashMap<String, AnalysisResult>> = Mutex::new(HashMap::new());
}
```

### Multi-threading

GhostBin may call your plugin from multiple threads. Use `Send + Sync` types:

```rust
unsafe impl Send for MyPlugin {}
unsafe impl Sync for MyPlugin {}
```

### Configuration

Read configuration from environment or files:

```rust
let config_path = std::env::var("PLUGIN_CONFIG")
    .unwrap_or_else(|_| "/etc/ghostbin/plugins/my_plugin.conf".to_string());
```

## Next Steps

- Check out existing plugins in the marketplace
- Read the [API Reference](../API.md) for plugin endpoints
- Share your plugin with the community
