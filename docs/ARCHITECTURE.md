# GhostBin Architecture

## Overview

GhostBin is built as a modern Rust web application with a clear separation between binary analysis engines, the HTTP API layer, and the web frontend.

```
┌─────────────────────────────────────────────────────────────┐
│                     Web UI (Browser)                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────┐  │
│  │ Disasm   │  │ Decompile│  │ AI Analysis              │  │
│  │ View     │  │ View     │  │ Panel                    │  │
│  └────┬─────┘  └────┬─────┘  └───────────┬──────────────┘  │
└───────┼─────────────┼────────────────────┼─────────────────┘
        │             │                    │
        └─────────────┴────────────────────┘
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
        │
   ┌────┴────┐
   │  CFG    │
   │ Builder │
   └────┬────┘
        │
   ┌────┴────┐
   │  Graph  │
   │ Layout  │
   └─────────┘
```

## Core Modules

### `src/main.rs` — HTTP Server

The Axum server hosts all REST API endpoints and WebSocket connections. It initializes all shared state (analyzers, stores, clients) and routes requests to handler functions.

Key responsibilities:
- Route registration
- Middleware (security headers, request size limits)
- State management via Arc<RwLock<>>
- Server startup and configuration

### `src/binary.rs` — Binary Parser

Uses `goblin` to parse ELF, PE, and Mach-O binaries. Extracts:
- Sections, segments, and headers
- Symbols (static and dynamic)
- Functions (from symbols + heuristic boundary detection)
- Imports and exports
- Relocations
- Resources (PE)

Multi-architecture support:
- x86 (32-bit)
- x86_64 (64-bit)
- ARM32
- ARM64 (AArch64)

Architecture auto-detection from binary headers.

### `src/disasm.rs` — Disassembly Engine

Wraps Capstone for multi-architecture disassembly:
- x86/x64 with Intel syntax
- ARM32 (ARM mode)
- ARM64

Provides `DisasmInstruction` with address, bytes, mnemonic, and operands.

### `src/decompiler.rs` — Pseudo-Code Generation

Builds a Control Flow Graph (CFG) from disassembly and generates C-like pseudo-code:
- Basic block detection
- Edge classification (fallthrough, branch, call, return)
- Pattern matching for common instructions
- Type inference
- Register-to-variable mapping

### `src/graph.rs` — Graph Visualization

- Force-directed layout algorithm using repulsion/attraction
- Interactive graph state (pan, zoom, node selection)
- DOT format export
- Integration with petgraph

### `src/llm.rs` — AI Analysis

Connects to local LLM servers (llama.cpp, etc.) for:
- Function explanation
- Vulnerability detection
- Naming suggestions
- Pattern recognition

Fully offline — no cloud APIs.

### `src/strings.rs` — String Analysis

Extracts and cross-references strings:
- ASCII strings
- UTF-8 strings
- UTF-16LE strings (Windows)
- String xrefs in disassembly

### `src/annotations.rs` — Collaborative Comments

Threaded annotation system:
- Address-based comments
- Reply threads
- Author tracking
- Parent-child relationships

### `src/websocket.rs` — Real-Time Sync

WebSocket hub for:
- Live cursor positions
- Annotation updates
- Analysis progress
- Multi-user sessions

### `src/idb.rs` — IDA/Ghidra Import

Imports existing analysis from:
- IDA Pro .i64 databases (SQLite-based)
- IDA Pro .idb databases
- Ghidra .gpr projects

Extracts function names, comments, and metadata.

### `src/session.rs` — Session Persistence

SQLite-backed session storage:
- Save analysis state
- Renamed symbols
- Graph viewport settings
- Bookmark preservation

### `src/config.rs` — Configuration

TOML-based configuration (`ghostbin.toml`):
- LLM connection settings
- Analysis parameters
- Server bind address and port
- Report limits

### Additional Modules

- `src/bookmarks.rs` — Bookmark management
- `src/diff.rs` — Binary diffing and patch detection
- `src/entropy.rs` — Section entropy analysis
- `src/export.rs` — Markdown/PDF report generation
- `src/marketplace.rs` — Plugin marketplace
- `src/openapi.rs` — OpenAPI specification
- `src/plugin.rs` — Plugin loading and execution
- `src/security.rs` — Rate limiting, input validation
- `src/yara.rs` — YARA signature matching

## Data Flow

### Binary Loading

```
File Upload → Goblin Parser → Architecture Detection
                                    ↓
                           Section Extraction
                           Symbol Table Parse
                           Function Boundary Detection
                                    ↓
                           Binary Store (HashMap)
```

### Function Analysis

```
Function Select → Disassembler (Capstone)
                        ↓
                   CFG Builder
                   Decompiler
                        ↓
                   Graph Layout
                   AI Analysis (LLM)
                        ↓
                   Annotated Output
```

### Real-Time Collaboration

```
User Action → WebSocket → WsHub Broadcast
                              ↓
                        Other Clients Update
```

## State Management

All mutable state is wrapped in `Arc<RwLock<T>>` for thread-safe concurrent access:

```rust
struct AppState {
    analyzer: Arc<RwLock<BinaryAnalyzer>>,
    annotations: Arc<RwLock<AnnotationStore>>,
    bookmarks: Arc<RwLock<BookmarkStore>>,
    sessions: Arc<RwLock<SessionStore>>,
    llm: Arc<LlmClient>,
    hub: Arc<WsHub>,
    plugins: Arc<PluginManager>,
    marketplace: Arc<PluginMarketplace>,
    rate_limiter: Arc<RateLimiter>,
    config: Arc<Config>,
}
```

## Security Considerations

- Input validation on all endpoints
- Request size limiting (prevents DoS)
- Rate limiting per IP
- Security headers middleware
- Path sanitization
- No external network dependencies

## Performance

- Async I/O with Tokio
- Parallel processing with Rayon
- SQLite for persistent storage
- In-memory HashMap for binary cache
- Capstone for fast disassembly

Target: Analyze 10MB binaries in under 5 seconds.

## Plugin System

Plugins are dynamic libraries (.so/.dll) that implement the analyzer trait:

```rust
pub trait AnalyzerPlugin {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn analyze(&self, binary: &[u8], function: &str) -> AnalysisResult;
}
```

The marketplace provides discovery and installation of community plugins.

## Future Architecture

Potential improvements for v1.1.0+:
- WASM-based plugins (sandboxed)
- Distributed analysis cluster
- Incremental analysis caching
- Binary diff visualization
- Hex editor integration
