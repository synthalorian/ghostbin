# GhostBin Documentation

Welcome to the GhostBin documentation. GhostBin is an AI-assisted reverse engineering platform built in Rust. It operates fully offline with no cloud dependencies.

## Quick Links

- [Installation Guide](INSTALL.md) — Get GhostBin running locally
- [API Reference](API.md) — Complete REST API documentation
- [Architecture Overview](ARCHITECTURE.md) — How GhostBin works under the hood
- [Contributing](CONTRIBUTING.md) — How to contribute to the project

## Tutorials

- [Getting Started](tutorials/getting-started.md) — Your first binary analysis
- [Interactive Graph View](tutorials/graph-view.md) — Navigate control flow graphs
- [Plugin Development](tutorials/plugins.md) — Write custom analyzers
- [IDA/Ghidra Import](tutorials/ida-ghidra-import.md) — Import existing analysis databases

## What is GhostBin?

GhostBin illuminates the ghosts in the machine. It combines:

- **Multi-format binary parsing** — ELF, PE, Mach-O with goblin
- **Multi-architecture disassembly** — x86, x64, ARM32, ARM64 via Capstone
- **Control flow analysis** — Build and visualize CFGs
- **AI-powered analysis** — Local LLM integration for function explanation
- **Collaborative annotations** — Real-time teamwork via WebSocket
- **Plugin ecosystem** — Extensible analyzer marketplace
- **Fully offline** — No API keys, no cloud, no data leaves your machine

## Version

Current version: **v1.0.0**

## License

MIT — Own your analysis. 🎹🦈
