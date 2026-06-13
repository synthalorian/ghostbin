# Getting Started with GhostBin

Welcome to GhostBin! This tutorial will walk you through your first binary analysis.

## Prerequisites

- GhostBin running locally (see [Installation Guide](../INSTALL.md))
- A sample binary to analyze (we'll use `/bin/ls`)

## Step 1: Start GhostBin

```bash
cargo run --release
```

You should see:
```
INFO GhostBin v1.0.0 listening on 127.0.0.1:8081
```

## Step 2: Open the Web UI

Navigate to http://localhost:8081 in your browser.

You'll see the GhostBin dashboard with options to:
- Load a binary
- View loaded binaries
- Access analysis tools

## Step 3: Load Your First Binary

Using curl:

```bash
curl -X POST http://localhost:8081/api/binary/load \
  -H "Content-Type: application/json" \
  -d '{"path": "/bin/ls", "name": "ls"}'
```

Response:
```json
{"id": "bin_0", "name": "ls"}
```

Or via the web UI, click "Load Binary" and enter the path.

## Step 4: Explore the Binary

### List Functions

```bash
curl http://localhost:8081/api/binary/bin_0/functions
```

You'll see a list of all functions found in the binary, including:
- Symbol names (if available)
- Heuristic names (e.g., `sub_401000`)
- Addresses and sizes

### View Sections

```bash
curl http://localhost:8081/api/binary/bin_0/sections
```

Shows sections like `.text`, `.data`, `.rodata` with their addresses and sizes.

### Extract Strings

```bash
curl "http://localhost:8081/api/binary/bin_0/strings?min_len=5"
```

Finds all ASCII, UTF-8, and UTF-16LE strings in the binary.

## Step 5: Disassemble a Function

Pick a function address from the list and disassemble it:

```bash
# Replace 0x401000 with an actual address from your binary
curl http://localhost:8081/api/binary/bin_0/function/0x401000/disasm
```

Response:
```json
[
  {
    "address": 4198400,
    "bytes": [85, 72, 137, 229],
    "mnemonic": "push",
    "operands": "rbp"
  },
  ...
]
```

## Step 6: Decompile to Pseudo-Code

```bash
curl -X POST http://localhost:8081/api/binary/bin_0/function/0x401000/decompile
```

Response:
```json
{
  "pseudo_code": "void sub_401000() {\n    int64_t var_8 = rbp;\n    rbp = rsp;\n    // ...\n}"
}
```

## Step 7: AI Analysis (Requires LLM)

If you have a local LLM running:

```bash
curl -X POST http://localhost:8081/api/binary/bin_0/function/0x401000/analyze
```

Response:
```json
{
  "analysis": "This function appears to be a utility function that..."
}
```

The AI will explain what the function does, identify potential vulnerabilities, and suggest better names.

## Step 8: View the Control Flow Graph

```bash
curl http://localhost:8081/api/graph/bin_0/cfg
```

Returns a graph with nodes (basic blocks) and edges (control flow) with layout coordinates.

## Step 9: Add Annotations

Mark interesting findings:

```bash
curl -X POST http://localhost:8081/api/annotations/0x401000 \
  -H "Content-Type: application/json" \
  -d '{"text": "Possible buffer overflow here", "author": "analyst1"}'
```

## Step 10: Export Your Analysis

Generate a report:

```bash
# Markdown report
curl -X POST http://localhost:8081/api/export/bin_0/markdown

# PDF report
curl -X POST http://localhost:8081/api/export/bin_0/pdf \
  --output analysis_report.pdf
```

## Next Steps

- Learn about the [Interactive Graph View](graph-view.md)
- Write your first [Plugin](plugins.md)
- Import from [IDA/Ghidra](ida-ghidra-import.md)
- Explore the [API Reference](../API.md)

## Tips

- **Large binaries**: GhostBin can analyze 10MB binaries in under 5 seconds
- **Batch analysis**: Use `/api/binary/batch` to process multiple binaries
- **Sessions**: Save your analysis state with `/api/sessions`
- **Bookmarks**: Mark important addresses for quick access
- **Diff**: Compare two binaries with `/api/binary/diff`

## Common Issues

### "Binary not found"

Ensure the path is absolute and the file exists:

```bash
readlink -f /bin/ls
```

### "No functions found"

Some stripped binaries may have limited symbol information. GhostBin uses heuristics to detect function boundaries, but accuracy varies by architecture.

### LLM not responding

Check your `ghostbin.toml` configuration:

```toml
[llm]
base_url = "http://localhost:8080"
model = "codellama-34b"
```

Ensure the LLM server is running and accessible.
