# 👻 GhostBin

AI-assisted reverse engineering. Fully offline. No cloud, no API keys, no data leaves your machine.

Ghosts in the machine, illuminated by local intelligence. Decompile, analyze, and understand binaries without ever touching the network.

## Features

- **Binary Analysis** — ELF, Mach-O, PE parsing with goblin
- **Disassembly** — Capstone-powered multi-arch support (x86, x64, ARM64)
- **Decompilation** — Control flow analysis + pseudo-code generation
- **AI Analysis** — Local LLM explains functions, finds vulnerabilities, suggests names
- **Collaborative** — Real-time annotations via WebSocket
- **Graph View** — Interactive CFG visualization
- **Web UI** — Modern dark interface, no Electron bloat

## Quick Start

```bash
# 1. Start your local LLM
llama-server -m codellama-34b.Q4_K_M.gguf -c 4096 --port 8080

# 2. Run Rev Engine
cargo run --release

# 3. Open http://localhost:8081
# 4. Load a binary, select a function, hit "AI Analyze"
```

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

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/binary/load` | POST | Load binary for analysis |
| `/api/binary/:id/functions` | GET | List functions |
| `/api/binary/:id/function/:addr/disasm` | GET | Get disassembly |
| `/api/binary/:id/function/:addr/decompile` | POST | Decompile to pseudo-code |
| `/api/binary/:id/function/:addr/analyze` | POST | AI analysis |
| `/api/annotations/:addr` | GET/POST | Get/add annotations |
| `/api/graph/:id/cfg` | GET | Control flow graph |
| `/ws` | WS | Real-time collaboration |

## Configuration

```toml
[llm]
provider = "llamacpp"
base_url = "http://localhost:8080"
model = "codellama-34b"
max_tokens = 4096
```

## License

MIT — Own your analysis. 🎹🦈
