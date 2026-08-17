# 👻 GhostBin

AI-assisted reverse engineering. Fully offline. No cloud, no API keys, no telemetry — no data ever leaves your machine.

Ghosts in the machine, illuminated by local intelligence. Disassemble, decompile, and annotate binaries; optionally let a local LLM explain what you found.

## Features

- **Binary parsing** — ELF (sections, static + dynamic symbols, relocations), PE (sections, imports, exports), and single-arch Mach-O (segments/sections, symbols) via goblin
- **Disassembly** — Capstone: x86, x86-64, ARM64
- **Decompilation** — CFG construction (basic blocks, branch/fallthrough/call edges) + pattern-matched C-like pseudo-code
- **Function discovery** — Symbol tables, with prologue heuristics for stripped x86/ARM64 ELFs
- **Annotations** — Per-address notes over REST + WebSocket sync
- **AI analysis (optional)** — Any local OpenAI-compatible server (llama.cpp, etc.). If no model is running you get a clear 503 and everything else keeps working
- **Web UI** — Single static page, no build step, no Electron

Not in v1.0.0 (see PLAN.md): graph UI, collaborative cursors, IDA/Ghidra import, export reports, plugins, fat Mach-O, ARM32, persistent annotation storage.

## Quick Start

```bash
# Run the server (no LLM needed for core features)
cargo run --release

# Open http://localhost:8081
# Click "Load Binary", enter a path on the server (e.g. /bin/ls),
# select a function → disassembly. "Decompile" for pseudo-code.
```

### Optional: local LLM

```bash
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080
```

GhostBin probes `http://localhost:8080` and shows its status in the UI bar.
Override with env vars:

```bash
GHOSTBIN_LLM_URL=http://localhost:8080   # OpenAI-compatible endpoint
GHOSTBIN_LLM_MODEL=codellama-34b         # model name sent in requests
GHOSTBIN_BIND=127.0.0.1:8081             # listen address (localhost by default)
```

## Testing

```bash
cargo test                  # 26 tests; fixture binary is compiled with cc at test time
cargo clippy --all-targets  # clean
cargo build --release
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/binary/load` | POST | Load binary from a server-local path |
| `/api/binary/:id` | GET | Format / arch / entry / counts |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/sections` | GET | List sections |
| `/api/binary/:id/symbols` | GET | List symbols / imports / exports |
| `/api/binary/:id/relocations` | GET | List relocations (ELF) |
| `/api/binary/:id/function/:addr/disasm` | GET | Disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis (503 if LLM offline) |
| `/api/annotations/:addr` | GET/POST | List / add annotations |
| `/api/graph/:id/cfg` | GET | Control flow graph (nodes + edges) |
| `/api/llm/status` | GET | LLM reachability and config |
| `/ws` | WS | Annotation/cursor message sync |

All failures return JSON: `{"error": "..."}` with an appropriate status code.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                 Web UI (static page)                │
│  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │ Disasm   │  │ Decompile │  │ AI Analysis      │  │
│  │ View     │  │ View      │  │ Panel (optional) │  │
│  └────┬─────┘  └────┬──────┘  └────────┬─────────┘  │
└───────┼─────────────┼──────────────────┼────────────┘
        └─────────────┴──────────────────┘
                          │
                   ┌──────┴──────┐
                   │  Axum API   │
                   └──────┬──────┘
        ┌─────────────────┼─────────────────┐
   ┌────┴────┐      ┌────┴────┐       ┌─────┴─────┐
   │ goblin  │      │ capstone│       │ local LLM │
   │ parser  │      │ disasm  │       │ (optional)│
   └─────────┘      └─────────┘       └───────────┘
```

## License

MIT — Own your analysis. 🎹🦞

---

## ☕ Support the Developer

If this project saved you time, solved a problem, or just made your day a little more neon, you can fuel the next one:

[![Buy Me A Coffee](https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png)](https://buymeacoffee.com/synthalorian)
