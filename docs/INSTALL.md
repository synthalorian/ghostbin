# Installation Guide

## Requirements

- **Rust** 1.70+ with Cargo
- **Linux** (x86_64, ARM64) or **macOS**
- A local LLM server (optional, for AI analysis)

## Quick Install

### From Source

```bash
# Clone the repository
git clone https://github.com/synthalorian/ghostbin.git
cd ghostbin

# Build release binary
cargo build --release

# Run
./target/release/ghostbin
```

### Static Binary (musl)

For a fully static binary with no dynamic dependencies:

```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Build static binary
cargo build --release --target x86_64-unknown-linux-musl

# The binary is at:
# ./target/x86_64-unknown-linux-musl/release/ghostbin
```

## Setup Local LLM (Optional)

GhostBin works without a local LLM for disassembly and analysis, but AI-powered function explanation requires one.

### Using llama.cpp

```bash
# Download llama.cpp server binary or build from source
# https://github.com/ggerganov/llama.cpp

# Start the server with your model
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080
```

### Using Ollama

```bash
# Install Ollama
# https://ollama.ai

# Pull a code model
ollama pull codellama

# Start the API server (default port 11434)
ollama serve
```

## Configuration

Create `ghostbin.toml` in the working directory:

```toml
# Server settings
bind_addr = "0.0.0.0"
port = 8081

# LLM configuration
[llm]
provider = "llamacpp"  # or "ollama"
base_url = "http://localhost:8080"
model = "codellama-34b"
max_tokens = 4096

# Analysis settings
[analysis]
max_report_functions = 100
min_string_length = 4
enable_decompiler = true
enable_yara = true
```

## Running

### Development

```bash
cargo run
```

### Production

```bash
# Build optimized release
cargo build --release

# Run with config
./target/release/ghostbin

# Or specify config location
GHOSTBIN_CONFIG=/etc/ghostbin.toml ./target/release/ghostbin
```

## Docker (Optional)

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libcapstone4
COPY --from=builder /app/target/release/ghostbin /usr/local/bin/ghostbin
COPY static/ /usr/local/share/ghostbin/static/
WORKDIR /usr/local/share/ghostbin
EXPOSE 8081
CMD ["ghostbin"]
```

Build and run:

```bash
docker build -t ghostbin .
docker run -p 8081:8081 -v $(pwd)/ghostbin.toml:/ghostbin.toml ghostbin
```

## Verification

After starting GhostBin:

1. Open http://localhost:8081
2. Load a test binary: `POST /api/binary/load` with path `/bin/ls`
3. Check status: `GET /api/status`
4. View API docs: http://localhost:8081/api/docs

## Troubleshooting

### Capstone not found

```bash
# Ubuntu/Debian
sudo apt-get install libcapstone-dev

# Fedora
sudo dnf install capstone-devel

# macOS
brew install capstone
```

### SQLite errors

GhostBin uses bundled SQLite by default. If you see SQLite errors:

```bash
# Ubuntu/Debian
sudo apt-get install libsqlite3-dev
```

### Port already in use

Change the port in `ghostbin.toml`:

```toml
port = 8082
```

### LLM connection refused

Ensure your LLM server is running and the `base_url` in config matches.

## Building for Other Platforms

### ARM64 (Apple Silicon, Raspberry Pi)

```bash
rustup target add aarch64-unknown-linux-gnu
cargo build --release --target aarch64-unknown-linux-gnu
```

### ARM32

```bash
rustup target add armv7-unknown-linux-gnueabihf
cargo build --release --target armv7-unknown-linux-gnueabihf
```

## Development Setup

```bash
# Install dev dependencies
cargo install cargo-watch

# Watch for changes and auto-rebuild
cargo watch -x run

# Run tests
cargo test

# Run linter
cargo clippy -- -D warnings

# Format code
cargo fmt
```
