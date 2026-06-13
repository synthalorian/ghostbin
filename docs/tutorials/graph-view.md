# Interactive Graph View Tutorial

GhostBin's interactive graph view lets you visualize and navigate control flow graphs with pan, zoom, and node selection.

## What is a Control Flow Graph?

A CFG represents all paths that might be traversed through a program during execution:

- **Nodes** — Basic blocks (sequences of instructions with single entry/exit)
- **Edges** — Control flow between blocks (branches, jumps, falls through)

## Viewing the CFG

### Via API

Get the CFG for the first function in a binary:

```bash
curl http://localhost:8081/api/graph/bin_0/cfg
```

Response:
```json
{
  "nodes": [
    {
      "id": "node_0",
      "address": "0x401000",
      "label": "0x401000",
      "x": 200.0,
      "y": 100.0
    },
    {
      "id": "node_1",
      "address": "0x401020",
      "label": "0x401020",
      "x": 350.0,
      "y": 250.0
    }
  ],
  "edges": [
    {
      "from": "node_0",
      "to": "node_1",
      "edge_type": "branch"
    },
    {
      "from": "node_0",
      "to": "node_2",
      "edge_type": "fallthrough"
    }
  ]
}
```

### Via Web UI

The web UI renders the CFG using the layout coordinates. Open a function and click the "Graph" tab.

## Interactive Controls

### Pan

Move the view around:

```bash
curl -X POST http://localhost:8081/api/graph/bin_0/interactive \
  -H "Content-Type: application/json" \
  -d '{"pan_dx": 50.0, "pan_dy": -30.0}'
```

### Zoom

Zoom in/out:

```bash
# Zoom in
curl -X POST http://localhost:8081/api/graph/bin_0/interactive \
  -d '{"zoom": 1.5}'

# Zoom out
curl -X POST http://localhost:8081/api/graph/bin_0/interactive \
  -d '{"zoom": 0.7}'

# Reset zoom
curl -X POST http://localhost:8081/api/graph/bin_0/interactive \
  -d '{"zoom": 1.0}'
```

Zoom range: 0.1x to 10x

### Select Node

Highlight a specific node:

```bash
curl -X POST http://localhost:8081/api/graph/bin_0/interactive \
  -d '{"select_node": "node_3"}'
```

Multiple nodes can be selected. Use the web UI to shift-click for multi-select.

## Layout Algorithm

GhostBin uses a force-directed layout:

1. **Repulsion** — All nodes push away from each other
2. **Attraction** — Connected nodes pull toward each other
3. **Iterations** — 100 iterations to stabilize
4. **Damping** — Prevents oscillation

This produces a natural-looking layout that emphasizes graph structure.

## Call Graph

View function call relationships:

```bash
curl http://localhost:8081/api/graph/bin_0/callgraph
```

Shows which functions call which other functions. Useful for:
- Understanding program structure
- Finding entry points
- Identifying dead code

## Graph Data Format

### Node Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique node identifier |
| `address` | string | Memory address of basic block |
| `label` | string | Display label |
| `x` | float | X coordinate |
| `y` | float | Y coordinate |

### Edge Fields

| Field | Type | Description |
|-------|------|-------------|
| `from` | string | Source node ID |
| `to` | string | Target node ID |
| `edge_type` | string | `branch`, `fallthrough`, `call`, `return` |

## Edge Types Explained

- **fallthrough** — Sequential execution (no jump)
- **branch** — Conditional or unconditional jump
- **call** — Function call
- **return** — Function return

## Saving Graph State

Save the current view (pan, zoom, selection) to a session:

```bash
curl -X POST http://localhost:8081/api/sessions/session_0/state \
  -d '{
    "graph_viewport": {
      "x": 100.0,
      "y": 50.0,
      "zoom": 2.0,
      "selected_nodes": ["node_1", "node_3"]
    }
  }'
```

## Tips for Large Graphs

- **Zoom out** first to see the overall structure
- **Pan** to the area of interest
- **Select nodes** to highlight specific paths
- Use the **call graph** for high-level overview before diving into CFG details
- **Diff two binaries** to see how control flow changed between versions

## Advanced: Custom Layout

The layout parameters can be tuned in the source:

```rust
// In src/graph.rs
let iterations = 100;
let repulsion_constant = 5000.0;
let attraction_constant = 0.01;
let damping = 0.9;
```

Adjust these for different graph aesthetics:
- More repulsion = nodes spread further apart
- More attraction = tighter clusters
- More iterations = better convergence

## Troubleshooting

### Graph looks cluttered

- Zoom out to see the full picture
- The force-directed layout may need more iterations for complex graphs

### Nodes overlap

This can happen with dense graphs. The layout tries to minimize overlap but isn't perfect.

### Missing edges

Some indirect jumps (e.g., via function pointers) can't be statically determined and won't appear in the CFG.
