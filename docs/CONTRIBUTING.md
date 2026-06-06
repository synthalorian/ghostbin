# Contributing to GhostBin

Thank you for your interest in contributing to GhostBin! This document provides guidelines for contributing to the project.

## Development Philosophy

GhostBin is built on these principles:

- **Fully offline** — No cloud dependencies, no API keys
- **Privacy first** — User data never leaves the machine
- **Performance** — Fast analysis, responsive UI
- **Extensibility** — Plugin system for custom analyzers
- **Multi-architecture** — Support all major CPU architectures

## Getting Started

1. Fork the repository
2. Clone your fork
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cargo test`
6. Run linter: `cargo clippy -- -D warnings`
7. Commit: `git commit -m "feat: add my feature"`
8. Push and open a Pull Request

## Code Style

- Follow Rust standard formatting: `cargo fmt`
- All code must pass clippy with zero warnings
- Write tests for new functionality
- Document public APIs with doc comments
- Use `anyhow` for error handling
- Prefer `?` over `unwrap()`

## Project Structure

```
ghostbin/
├── src/              # Rust source code
│   ├── main.rs       # Server and routes
│   ├── binary.rs     # Binary parsing
│   ├── disasm.rs     # Disassembly
│   ├── decompiler.rs # CFG + pseudo-code
│   ├── graph.rs      # Graph layout
│   ├── llm.rs        # Local LLM client
│   ├── idb.rs        # IDA/Ghidra import
│   └── ...
├── static/           # Web UI assets
├── docs/             # Documentation
├── tests/            # Integration tests
└── Cargo.toml        # Dependencies
```

## Adding New Features

### New API Endpoints

1. Add route in `src/main.rs`
2. Implement handler function
3. Add request/response types
4. Update OpenAPI spec in `src/openapi.rs`
5. Add tests
6. Update documentation

### New Binary Format Support

1. Update `src/binary.rs` parser
2. Add format detection
3. Extract relevant metadata
4. Add tests with sample binaries
5. Update architecture detection if needed

### New Architecture Support

1. Add variant to `Architecture` enum in `src/disasm.rs`
2. Configure Capstone for the architecture
3. Add function boundary detection heuristics
4. Update auto-detection logic
5. Add tests

### Plugin Development

See [Plugin Tutorial](tutorials/plugins.md) for details.

## Testing

### Unit Tests

Add tests in the module's `#[cfg(test)]` section:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_feature() {
        assert_eq!(my_function(), expected);
    }
}
```

### Integration Tests

Add to `tests/` directory:

```rust
#[tokio::test]
async fn test_api_endpoint() {
    // Test full HTTP request/response cycle
}
```

### Test Data

- Use `/bin/ls` or `/bin/cat` for ELF tests
- Create minimal test binaries for specific formats
- Keep test data small (< 1MB)

## Commit Messages

Follow conventional commits:

- `feat:` — New feature
- `fix:` — Bug fix
- `docs:` — Documentation changes
- `test:` — Test additions/changes
- `refactor:` — Code refactoring
- `perf:` — Performance improvements
- `chore:` — Maintenance tasks

Examples:

```
feat: add ARM32 function boundary detection
fix: resolve Mach-O symbol parsing for stripped binaries
docs: update API reference for v1.0.0 endpoints
test: add entropy analysis tests
```

## Pull Request Process

1. Ensure all tests pass
2. Ensure clippy reports zero warnings
3. Update documentation if needed
4. Add CHANGELOG entry
5. Request review from maintainers
6. Address review feedback
7. Squash commits if requested

## Reporting Issues

When reporting bugs, include:

- GhostBin version
- Operating system and architecture
- Steps to reproduce
- Expected vs actual behavior
- Sample binary (if applicable)
- Error messages and logs

## Security

For security issues, please email security@ghostbin.dev instead of opening a public issue.

## Code of Conduct

- Be respectful and constructive
- Welcome newcomers
- Focus on the code, not the person
- Assume good intentions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
