# GhostBin — Development Plan

AI-assisted reverse engineering. Rust + Axum. Fully offline. No cloud.

---

## v0.1.0 — Parse + Disasm ✅

- [x] Wire `binary.rs` parser to API endpoints
- [x] Integrate Capstone for real x86/x64/ARM64 disassembly
- [x] ELF parsing: sections, symbols, relocations
- [x] PE parsing: imports, exports, resources
- [x] Mach-O parsing: segments, sections, symbols
- [x] Function boundary detection (symbols + heuristics)

## v0.2.0 — Analyze ✅

- [x] Build CFG from disassembly (basic blocks, edges)
- [x] Simple decompiler: pattern match → C-like pseudo-code
- [x] Wire LLM analysis to `/analyze` endpoint
- [x] Function signature detection (arguments, return type)
- [x] String xref analysis
- [x] Call graph generation

## v0.3.0 — Collaborate ✅

- [x] Real-time collaborative annotations via WebSocket
- [x] User cursors in disassembly view
- [x] Annotation threads (reply to comments)
- [x] Export analysis report (PDF/Markdown)
- [x] Plugin API for custom analyzers

## v0.4.0 — Stabilize ✅

- [x] String cross-reference analysis (ASCII, UTF-8, UTF-16LE)
- [x] Configuration system (TOML-based, `ghostbin.toml`)
- [x] Health/status API endpoint (`/api/status`)
- [x] Configurable report limits and analysis parameters
- [x] Force-directed graph layout for CFG visualization
- [x] Fix all clippy warnings and code quality issues
- [x] Comprehensive unit tests for all modules
- [x] `/api/binary/:id/strings` endpoint with filtering

## v1.0.0 — Ship It

- [ ] Multi-arch support: x86, x64, ARM64, ARM32
- [ ] Interactive graph view (pan, zoom, navigate)
- [ ] IDA/Ghidra database import
- [ ] All tests pass, CI green
- [ ] Static binary release (musl)
- [ ] Documentation + tutorial videos

---

## Architecture

```
Binary Upload → Goblin Parser → Function List
                      ↓
Disassembly ← Capstone ← Selected Function
      ↓
CFG Builder → Graph Layout → Web UI
      ↓
LLM Analysis → Annotated Output
```

## Key Files

| File | Responsibility |
|------|---------------|
| `src/main.rs` | Axum server, API routes |
| `src/binary.rs` | ELF/PE/Mach-O parsing |
| `src/disasm.rs` | Capstone integration |
| `src/decompiler.rs` | CFG + pseudo-code |
| `src/graph.rs` | Graph layout, dot export |
| `src/llm.rs` | Local LLM client |
| `src/annotations.rs` | Comment storage |
| `src/websocket.rs` | Real-time collaboration |
| `src/strings.rs` | String extraction + xrefs |
| `src/config.rs` | TOML configuration |
| `static/index.html` | Web UI |

## Local Dev

```bash
# Start local LLM:
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080

# Run GhostBin:
cargo run

# Open http://localhost:8081
```

## Testing

```bash
cargo test
cargo clippy -- -D warnings
cargo build --release --target x86_64-unknown-linux-musl
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Server health and stats |
| `/api/config` | GET | Current configuration |
| `/api/binary/load` | POST | Upload binary |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/sections` | GET | List sections |
| `/api/binary/:id/symbols` | GET | List symbols |
| `/api/binary/:id/strings` | GET | Extract strings with xrefs |
| `/api/binary/:id/function/:addr/disasm` | GET | Disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis |
| `/api/annotations/:addr` | GET/POST | Annotations |
| `/api/annotations/:addr/threads` | GET | Annotation threads |
| `/api/export/:id/markdown` | POST | Markdown report |
| `/api/export/:id/pdf` | POST | PDF report |
| `/api/plugins/load` | POST | Load plugin |
| `/api/plugins/list` | GET | List plugins |
| `/api/plugins/:name/analyze` | POST | Run plugin |
| `/api/plugins/:name` | DELETE | Unload plugin |
| `/api/graph/:id/cfg` | GET | Control flow graph |
| `/ws` | WS | Real-time sync |

---

*Ghosts in the machine, illuminated.* 👻
