# 👻 GhostBin

**AI-assisted reverse engineering. Fully offline. No cloud, no API keys, no data leaves your machine.**

Ghosts in the machine, illuminated by local intelligence. Decompile, analyze, and understand binaries without ever touching the network.

---

## Features

- **Binary Analysis** — ELF, Mach-O, PE parsing with [goblin](https://github.com/m4b/goblin)
- **Disassembly** — Capstone-powered multi-arch support (x86, x64, ARM64)
- **Decompilation** — Control flow analysis + pseudo-code generation
- **AI Analysis** — Local LLM explains functions, finds vulnerabilities, suggests names
- **Collaborative** — Real-time annotations via WebSocket
- **Graph View** — Interactive CFG visualization
- **Web UI** — Modern dark interface, no Electron bloat
- **Plugin System** — Extensible plugin architecture with marketplace
- **Session Management** — Persistent analysis sessions with state
- **Export** — Markdown and PDF report generation
- **Security** — Rate limiting, input validation, security headers

---

## Quick Start

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- A local LLM server (e.g., [llama.cpp](https://github.com/ggerganov/llama.cpp))

### Installation

```bash
# Clone the repository
git clone https://github.com/synthalorian/ghostbin.git
cd ghostbin

# Build in release mode
cargo build --release

# Or run directly
cargo run --release
```

### Running

```bash
# 1. Start your local LLM server
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080

# 2. Run GhostBin
cargo run --release

# 3. Open http://localhost:8081
# 4. Load a binary, select a function, hit "AI Analyze"
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Web UI (Browser)                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │ Disasm   │  │ Decompile│  │ AI Analysis      │  │
│  │ View     │  │ View     │  │ Panel            │  │
│  └────┬─────┘  └────┬─────┘  └────────┬─────────┘  │
└───────┼─────────────┼─────────────────┼────────────┘
        │             │                 │
        └─────────────┴─────────────────┘
                          │
                   ┌──────┴──────┐
                   │  Axum API   │
                   └──────┬──────┘
        ┌─────────────────┼─────────────────┐
        │                 │                 │
   ┌────┴────┐      ┌────┴────┐      ┌────┴────┐
   │ Binary  │      │ Capstone│      │ Local   │
   │ Parser  │      │ Disasm  │      │ LLM     │
   │(goblin) │      │         │      │(llama)  │
   └─────────┘      └─────────┘      └─────────┘
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server health and statistics |
| `/api/config` | GET | Current configuration |
| `/api/openapi.json` | GET | OpenAPI specification |
| `/api/docs` | GET | Swagger UI documentation |
| `/api/binary/load` | POST | Load binary for analysis |
| `/api/binary/batch` | POST | Batch load binaries |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/sections` | GET | List sections |
| `/api/binary/:id/symbols` | GET | List symbols |
| `/api/binary/:id/strings` | GET | Extract strings |
| `/api/binary/:id/function/:addr/disasm` | GET | Get disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Decompile to pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis |
| `/api/graph/:id/cfg` | GET | Control flow graph |
| `/api/graph/:id/callgraph` | GET | Call graph |
| `/api/annotations/:addr` | GET/POST | Get/add annotations |
| `/api/bookmarks` | GET/POST | List/create bookmarks |
| `/api/sessions` | GET/POST | List/create sessions |
| `/api/export/:id/markdown` | POST | Export markdown report |
| `/api/export/:id/pdf` | POST | Export PDF report |
| `/api/plugins/list` | GET | List loaded plugins |
| `/api/marketplace/plugins` | GET | List marketplace plugins |
| `/ws` | WS | Real-time collaboration |

---

## Configuration

Create a `ghostbin.toml` in the working directory:

```toml
[server]
bind_addr = "127.0.0.1"
port = 8081

[llm]
provider = "llamacpp"
base_url = "http://localhost:8080"
model = "codellama-34b"
max_tokens = 4096

[analysis]
max_report_functions = 100
min_string_length = 4
auto_decompile = false
```

---

## Development

```bash
# Run tests
cargo test

# Run with clippy warnings
cargo clippy --all-targets --all-features

# Format code
cargo fmt

# Check without building
cargo check
```

---

## Project Structure

```
ghostbin/
├── src/
│   ├── main.rs          # Axum server and route handlers
│   ├── binary.rs        # Binary parsing (ELF/PE/Mach-O)
│   ├── disasm.rs        # Capstone disassembly
│   ├── decompiler.rs    # Pseudo-code generation
│   ├── llm.rs           # Local LLM client
│   ├── graph.rs         # CFG and call graph
│   ├── annotations.rs   # Annotation system
│   ├── bookmarks.rs     # Bookmark management
│   ├── session.rs       # Session persistence
│   ├── security.rs      # Rate limiting and validation
│   ├── export.rs        # Markdown/PDF export
│   ├── plugin.rs        # Plugin system
│   ├── marketplace.rs   # Plugin marketplace
│   ├── websocket.rs     # Real-time collaboration
│   ├── diff.rs          # Binary diffing
│   ├── entropy.rs       # Entropy analysis
│   ├── strings.rs       # String extraction
│   ├── yara.rs          # Signature scanning
│   ├── idb.rs           # IDA/Ghidra import
│   ├── config.rs        # Configuration management
│   └── openapi.rs       # OpenAPI specification
├── static/              # Web UI assets
├── docs/                # Documentation
├── Cargo.toml
└── README.md
```

---

## License

MIT — Own your analysis. 🎹🦈

---

## Contributing

Contributions are welcome! Please ensure:

1. `cargo check` passes
2. `cargo clippy` has no warnings
3. `cargo test` passes
4. Code is formatted with `cargo fmt`

---

## Security

GhostBin is designed with security in mind:

- All analysis happens locally — no data leaves your machine
- Rate limiting prevents abuse
- Input validation on all endpoints
- Security headers on all responses
- Request size limits

---

## Acknowledgments

- [goblin](https://github.com/m4b/goblin) — Binary parsing
- [Capstone](https://www.capstone-engine.org/) — Disassembly engine
- [Axum](https://github.com/tokio-rs/axum) — Web framework
- [llama.cpp](https://github.com/ggerganov/llama.cpp) — Local LLM inference
