# GhostBin — Development Plan

AI-assisted reverse engineering. Rust + Axum. Fully offline. No cloud.

> **v1.0.0 status (2026-07-28):** the offline analysis core is real, tested,
> and shipped. Items below are marked against reality, not aspiration.

---

## ✅ v1.0.0 — Shipped: Working Offline Analysis Core

- [x] ELF parsing: sections, symbols (static + dynamic), relocations — `binary.rs`
- [x] PE parsing: sections, imports, exports, entry point, arch detection
- [x] Mach-O parsing (single-arch): segments/sections, symbols, arch detection
      (fat/multi-arch Mach-O rejected with a clear error — use `lipo -thin` first)
- [x] Capstone disassembly: x86, x86-64, ARM64
- [x] Function boundary detection (symbols + prologue heuristics for stripped ELFs)
- [x] CFG construction: basic blocks, branch/fallthrough/call edges
- [x] Pattern-matching decompiler → C-like pseudo-code
- [x] Annotations CRUD (in-memory) + WebSocket annotation sync
- [x] CFG JSON endpoint (`/api/graph/:id/cfg`) with simple layered layout
- [x] LLM analysis wired to `/analyze`, **optional**: unreachable or
      non-OpenAI-compatible server → 503 JSON error, app fully usable
- [x] LLM status endpoint (`/api/llm/status`) + UI indicator
- [x] Single-page UI wired to real endpoints (functions, disasm, decompile,
      AI analysis, annotations)
- [x] 26 tests green, `cargo clippy --all-targets` clean, release build green
- [x] JSON error bodies on all API failures
- [x] Binds to localhost by default (`GHOSTBIN_BIND` to override)

## ⏭️ Cut from v1.0.0 (deferred, not promised)

- [ ] ARM32 disassembly (capstone supports it; not wired/tested)
- [ ] Function signature detection (arguments, return type)
- [ ] String xref analysis
- [ ] Call graph generation (CFG has call edges; no global call graph view)
- [ ] Interactive graph view in UI (pan/zoom) — CFG data endpoint exists
- [ ] Real-time collaborative cursors (WS echoes only; no broadcast/rooms)
- [ ] Annotation threads / replies
- [ ] Export analysis report (PDF/Markdown)
- [ ] Plugin API for custom analyzers
- [ ] IDA/Ghidra database import
- [ ] Fat Mach-O support
- [ ] Persistent annotation storage (currently in-memory)
- [ ] CI pipeline / musl static release / tutorial videos

## Architecture

```
Binary path → Goblin Parser → Function List
                    ↓
Disassembly ← Capstone ← Selected Function
      ↓
CFG Builder → Layout → Web UI (JSON)
      ↓
LLM Analysis (optional) → Annotated Output
```

## Key Files

| File | Responsibility |
|------|---------------|
| `src/lib.rs` | Axum router, API handlers, JSON errors |
| `src/main.rs` | Thin binary: env config + serve |
| `src/binary.rs` | ELF/PE/Mach-O parsing via goblin |
| `src/disasm.rs` | Capstone integration |
| `src/decompiler.rs` | CFG builder + pseudo-code |
| `src/graph.rs` | Graph layout, dot export |
| `src/llm.rs` | Optional local LLM client (OpenAI-compatible) |
| `src/annotations.rs` | In-memory comment storage |
| `src/websocket.rs` | Annotation/cursor message sync |
| `static/index.html` | Single-page web UI |
| `tests/` | Fixture + API integration tests |

## Local Dev

```bash
# Optional: start a local OpenAI-compatible LLM server:
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080

# Run GhostBin (works fine without the LLM):
cargo run

# Open http://localhost:8081
```

## Testing

```bash
cargo test                      # 26 tests (fixture binary built with cc)
cargo clippy --all-targets      # clean
cargo build --release
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/binary/load` | POST | Load binary from server path |
| `/api/binary/:id` | GET | Format/arch/entry/counts summary |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/sections` | GET | List sections |
| `/api/binary/:id/symbols` | GET | List symbols / imports / exports |
| `/api/binary/:id/relocations` | GET | List relocations (ELF) |
| `/api/binary/:id/function/:addr/disasm` | GET | Disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis (503 if LLM offline) |
| `/api/annotations/:addr` | GET/POST | Annotations (GET returns list, possibly empty) |
| `/api/graph/:id/cfg` | GET | Control flow graph of first function |
| `/api/llm/status` | GET | LLM reachability + config |
| `/ws` | WS | Annotation/cursor message sync |

---

*Ghosts in the machine, illuminated.* 👻
