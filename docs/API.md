# GhostBin API Reference

Complete reference for the GhostBin REST API. All endpoints return JSON unless otherwise specified.

## Base URL

```
http://localhost:8081/api
```

## Authentication

GhostBin v1.0.0 does not require authentication. It runs entirely on your local machine.

## Endpoints

### Status & Configuration

#### GET /api/status

Returns server health and statistics.

**Response:**
```json
{
  "version": "1.0.0",
  "status": "healthy",
  "binaries_loaded": 3,
  "annotation_count": 42,
  "bookmark_count": 7,
  "session_count": 2,
  "plugins_loaded": 1,
  "websocket_users": 2
}
```

#### GET /api/config

Returns current server configuration.

**Response:**
```json
{
  "bind_addr": "0.0.0.0",
  "port": 8081,
  "llm_provider": "llamacpp",
  "llm_model": "codellama-34b",
  "analysis": {
    "max_report_functions": 100,
    "min_string_length": 4,
    "enable_decompiler": true
  }
}
```

#### GET /api/openapi.json

Returns the complete OpenAPI 3.0 specification.

#### GET /api/docs

Interactive Swagger UI documentation.

### Binary Analysis

#### POST /api/binary/load

Load a binary file for analysis.

**Request:**
```json
{
  "path": "/path/to/binary",
  "name": "target_binary"
}
```

**Response:**
```json
{
  "id": "bin_0",
  "name": "target_binary"
}
```

#### POST /api/binary/batch

Load multiple binaries at once.

**Request:**
```json
{
  "binaries": [
    { "path": "/bin/ls", "name": "ls" },
    { "path": "/bin/cat", "name": "cat" }
  ]
}
```

#### GET /api/binary/:id/functions

List all functions in the binary.

**Response:**
```json
[
  {
    "address": 4196000,
    "name": "main",
    "size": 256
  }
]
```

#### GET /api/binary/:id/sections

List binary sections.

#### GET /api/binary/:id/symbols

List symbols.

#### GET /api/binary/:id/strings

Extract strings with optional filtering.

**Query Parameters:**
- `min_len` — Minimum string length (default: 4)
- `pattern` — Filter pattern (optional)

#### GET /api/binary/:id/relocations

List relocations (ELF only).

#### GET /api/binary/:id/imports

List imports (PE only).

#### GET /api/binary/:id/exports

List exports.

#### GET /api/binary/:id/resources

List PE resources.

#### GET /api/binary/:id/entropy

Section entropy analysis for packer/encryption detection.

#### GET /api/binary/:id/signatures

YARA signature matches.

### Disassembly & Decompilation

#### GET /api/binary/:id/function/:addr/disasm

Get disassembly for a function.

**Example:** `/api/binary/bin_0/function/0x401000/disasm`

**Response:**
```json
[
  {
    "address": 4198400,
    "bytes": [85, 72, 137, 229],
    "mnemonic": "push",
    "operands": "rbp"
  }
]
```

#### POST /api/binary/:id/function/:addr/decompile

Decompile function to pseudo-C code.

**Response:**
```json
{
  "pseudo_code": "void sub_401000() {\n    // ...\n}"
}
```

#### POST /api/binary/:id/function/:addr/analyze

AI analysis of a function.

**Response:**
```json
{
  "analysis": "This function appears to be a string comparison routine..."
}
```

### Graph Visualization

#### GET /api/graph/:id/cfg

Get control flow graph for the first function.

**Response:**
```json
{
  "nodes": [
    {
      "id": "node_0",
      "address": "0x401000",
      "label": "0x401000",
      "x": 200.0,
      "y": 100.0
    }
  ],
  "edges": [
    {
      "from": "node_0",
      "to": "node_1",
      "edge_type": "branch"
    }
  ]
}
```

#### GET /api/graph/:id/callgraph

Get function call graph.

#### POST /api/graph/:id/interactive

Update interactive graph state (pan, zoom, selection).

**Request:**
```json
{
  "pan_dx": 10.0,
  "pan_dy": -5.0,
  "zoom": 1.5,
  "select_node": "node_3"
}
```

### IDA/Ghidra Import

#### POST /api/import/database

Import an IDA or Ghidra database file.

**Request:**
```json
{
  "database_path": "/path/to/database.i64",
  "binary_id": "bin_0",
  "options": {
    "import_functions": true,
    "import_comments": true,
    "import_data": true,
    "overwrite_existing": false
  }
}
```

**Response:**
```json
{
  "source": "ida",
  "binary_path": "/original/binary/path",
  "architecture": "metapc",
  "base_address": 4194304,
  "functions": [
    {
      "address": 4196000,
      "name": "main",
      "size": 256,
      "comment": "Entry point",
      "repeatable_comment": null,
      "flags": 0
    }
  ],
  "data_items": [],
  "comments": {
    "4196000": "Entry point"
  },
  "import_errors": []
}
```

#### POST /api/import/:id/apply

Apply imported database to a loaded binary.

**Response:**
```json
{
  "functions_renamed": 15,
  "functions_added": 3,
  "comments_added": 8,
  "annotations_created": 23
}
```

### Annotations

#### GET /api/annotations/:addr

Get annotation at address.

#### POST /api/annotations/:addr

Add annotation.

**Request:**
```json
{
  "text": "This is a buffer overflow vulnerability",
  "author": "analyst1",
  "parent_id": null
}
```

#### GET /api/annotations/:addr/threads

Get annotation threads (replies).

### Bookmarks

#### GET /api/bookmarks

List all bookmarks.

#### POST /api/bookmarks

Create bookmark.

**Request:**
```json
{
  "binary_id": "bin_0",
  "address": 4198400,
  "name": "Interesting function",
  "description": "Called from main",
  "category": "suspicious",
  "color": "#ff0000"
}
```

#### DELETE /api/bookmarks/:id

Delete bookmark.

#### POST /api/bookmarks/:id/rename

Rename bookmark.

### Sessions

#### GET /api/sessions

List saved analysis sessions.

#### POST /api/sessions

Create new session.

#### GET /api/sessions/:id

Get session details.

#### DELETE /api/sessions/:id

Delete session.

#### POST /api/sessions/:id/state

Update session state (renamed symbols, graph viewport).

### Binary Comparison

#### POST /api/binary/diff

Diff two binaries.

**Request:**
```json
{
  "binary_a_id": "bin_0",
  "binary_b_id": "bin_1"
}
```

#### GET /api/binary/:id/patches

Detect patches between binary versions.

**Query Parameters:**
- `compare_with` — Other binary ID to compare against

### Symbol Management

#### POST /api/binary/:id/symbols/rename

Rename a symbol.

**Request:**
```json
{
  "old_name": "sub_401000",
  "new_name": "main"
}
```

### Export

#### POST /api/export/:id/markdown

Export analysis report as Markdown.

#### POST /api/export/:id/pdf

Export analysis report as PDF.

### Plugins

#### GET /api/plugins/list

List loaded plugins.

#### POST /api/plugins/load

Load a plugin.

**Request:**
```json
{
  "path": "/path/to/plugin.so"
}
```

#### POST /api/plugins/:name/analyze

Run plugin analysis.

**Request:**
```json
{
  "binary_id": "bin_0",
  "function_name": "main"
}
```

#### DELETE /api/plugins/:name

Unload plugin.

### Plugin Marketplace

#### GET /api/marketplace/plugins

List marketplace plugins.

#### GET /api/marketplace/plugins/:name

Get plugin details.

#### POST /api/marketplace/install

Install plugin from marketplace.

#### GET /api/marketplace/categories

List plugin categories.

#### GET /api/marketplace/tags

List popular tags.

#### GET /api/marketplace/featured

Get featured plugins.

#### GET /api/marketplace/recent

Get recently updated plugins.

#### GET /api/marketplace/stats

Get marketplace statistics.

### WebSocket

#### GET /ws

Real-time collaboration endpoint.

Connect via WebSocket for:
- Live cursor tracking
- Annotation updates
- Analysis progress

### Rate Limiting

#### GET /api/rate-limit

Check current rate limit status.

## Error Responses

All errors follow this format:

```json
{
  "error": "Description of what went wrong"
}
```

HTTP status codes:
- `200` — Success
- `201` — Created
- `204` — No content (success, empty response)
- `400` — Bad request
- `404` — Not found
- `409` — Conflict (e.g., duplicate bookmark)
- `422` — Unprocessable entity (e.g., invalid database file)
- `429` — Rate limited
- `500` — Internal server error

## Data Types

### Architecture

- `x86` — 32-bit x86
- `x86_64` — 64-bit x86
- `arm32` — 32-bit ARM
- `arm64` — 64-bit ARM (AArch64)
- `unknown` — Could not detect

### BookmarkCategory

- `interesting` — Notable location
- `suspicious` — Potential malware indicator
- `vulnerability` — Security issue
- `string` — Important string reference
- `api` — API call of interest
- `other` — Uncategorized

## Rate Limits

Default rate limit: `max_report_functions * 10` requests per 60 seconds per IP.

Configure via `ghostbin.toml`:

```toml
[analysis]
max_report_functions = 100
```
