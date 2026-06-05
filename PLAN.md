# GhostBin — Development Plan

AI-assisted reverse engineering. Rust + Axum. Fully offline. No cloud.

---

## v0.1.0 — Parse + Disasm (Now)

- [ ] Wire `binary.rs` parser to API endpoints
- [ ] Integrate Capstone for real x86/x64/ARM64 disassembly
- [ ] ELF parsing: sections, symbols, relocations
- [ ] PE parsing: imports, exports, resources
- [ ] Mach-O parsing: segments, sections, symbols
- [ ] Function boundary detection (symbols + heuristics)

## v0.2.0 — Analyze

- [ ] Build CFG from disassembly (basic blocks, edges)
- [ ] Simple decompiler: pattern match → C-like pseudo-code
- [ ] Wire LLM analysis to `/analyze` endpoint
- [ ] Function signature detection (arguments, return type)
- [ ] String xref analysis
- [ ] Call graph generation

## v0.3.0 — Collaborate

- [ ] Real-time collaborative annotations via WebSocket
- [ ] User cursors in disassembly view
- [ ] Annotation threads (reply to comments)
- [ ] Export analysis report (PDF/Markdown)
- [ ] Plugin API for custom analyzers

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
| `/api/binary/load` | POST | Upload binary |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/function/:addr/disasm` | GET | Disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis |
| `/api/annotations/:addr` | GET/POST | Annotations |
| `/api/graph/:id/cfg` | GET | Control flow graph |
| `/ws` | WS | Real-time sync |

---

*Ghosts in the machine, illuminated.* 👻
