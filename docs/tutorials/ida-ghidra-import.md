# IDA/Ghidra Import Tutorial

GhostBin can import analysis data from IDA Pro and Ghidra databases, preserving your existing work.

## Supported Formats

| Format | Extension | Description |
|--------|-----------|-------------|
| IDA 64-bit | `.i64` | IDA Pro 7.0+ database |
| IDA 32-bit | `.idb` | Legacy IDA database |
| Ghidra | `.gpr` | Ghidra project file |

## What Gets Imported

### From IDA Pro

- **Function names** — All renamed functions
- **Comments** — Regular and repeatable comments
- **Data labels** — Named data locations
- **Architecture info** — Processor type
- **Base address** — Image base

### From Ghidra

- **Project metadata** — Program name, architecture
- **Base address** — Image base
- **Function info** — (Limited, see notes below)

## Importing from IDA Pro

### Step 1: Prepare the Database

Ensure your IDA database has:
- Functions defined (Auto-analysis completed)
- Names applied (press `N` to rename)
- Comments added (press `;` for regular, `Shift+;` for repeatable)

### Step 2: Locate the Database File

IDA databases are typically stored alongside the original binary:

```
/path/to/
  ├── target_binary
  └── target_binary.i64
```

### Step 3: Import via API

```bash
curl -X POST http://localhost:8081/api/import/database \
  -H "Content-Type: application/json" \
  -d '{
    "database_path": "/path/to/target_binary.i64",
    "binary_id": "bin_0",
    "options": {
      "import_functions": true,
      "import_comments": true,
      "import_data": true,
      "overwrite_existing": false
    }
  }'
```

Response:
```json
{
  "source": "ida",
  "binary_path": "/path/to/target_binary",
  "architecture": "metapc",
  "base_address": 4194304,
  "functions": [
    {
      "address": 4196000,
      "name": "main",
      "size": 256,
      "comment": "Program entry point",
      "repeatable_comment": null,
      "flags": 0
    },
    {
      "address": 4196256,
      "name": "validate_input",
      "size": 128,
      "comment": null,
      "repeatable_comment": "Called from main",
      "flags": 0
    }
  ],
  "data_items": [
    {
      "address": 4212000,
      "name": "g_config",
      "data_type": "unknown",
      "size": 0,
      "comment": "Global configuration"
    }
  ],
  "comments": {
    "4196000": "Program entry point",
    "4196256": "Called from main",
    "4212000": "Global configuration"
  },
  "import_errors": []
}
```

### Step 4: Apply to Binary

The import returns metadata. To actually apply the names and comments to your loaded binary:

```bash
curl -X POST http://localhost:8081/api/import/bin_0/apply \
  -H "Content-Type: application/json" \
  -d '{
    "database_path": "/path/to/target_binary.i64",
    "binary_id": "bin_0",
    "options": {
      "import_functions": true,
      "import_comments": true,
      "import_data": true,
      "overwrite_existing": true
    }
  }'
```

Response:
```json
{
  "functions_renamed": 15,
  "functions_added": 3,
  "comments_added": 8,
  "annotations_created": 23
}
```

## Importing from Ghidra

### Step 1: Export from Ghidra

For best results with Ghidra:

1. Open your project in Ghidra
2. Go to **File → Export** 
3. Choose format: **XML** or **C Header**
4. Export functions and data

### Step 2: Import the GPR File

```bash
curl -X POST http://localhost:8081/api/import/database \
  -d '{
    "database_path": "/path/to/project.gpr",
    "binary_id": "bin_0",
    "options": {
      "import_functions": true,
      "import_comments": true,
      "import_data": true,
      "overwrite_existing": false
    }
  }'
```

**Note:** Ghidra `.gpr` files contain project metadata, not full program data. For complete import, use Ghidra's XML export feature and process the resulting XML.

### Ghidra Limitations

- `.gpr` files store project structure, not detailed analysis
- Function names and comments are in the `.rep` directory
- GhostBin extracts basic metadata from `.gpr`
- For full data, export XML from Ghidra and import that

## Import Options

| Option | Default | Description |
|--------|---------|-------------|
| `import_functions` | `true` | Import function names and boundaries |
| `import_comments` | `true` | Import comments as annotations |
| `import_data` | `true` | Import data labels |
| `overwrite_existing` | `false` | Overwrite existing names |

## Workflow Integration

### Typical Workflow

1. **Initial analysis in IDA/Ghidra**
   - Auto-analyze binary
   - Rename key functions
   - Add comments

2. **Import to GhostBin**
   - Load the same binary in GhostBin
   - Import the database
   - All names and comments are preserved

3. **Collaborate in GhostBin**
   - Share analysis session
   - Team members see IDA/Ghidra names
   - Add new annotations collaboratively

4. **Export final report**
   - Generate Markdown or PDF
   - Includes all imported + new analysis

### Batch Import

Import multiple databases:

```bash
for db in /path/to/databases/*.i64; do
  curl -X POST http://localhost:8081/api/import/bin_0/apply \
    -d "{\"database_path\": \"$db\", \"binary_id\": \"bin_0\"}"
done
```

## Troubleshooting

### "Unknown database format"

Ensure the file extension is correct:
- `.i64` for IDA 64-bit
- `.idb` for IDA 32-bit
- `.gpr` for Ghidra

### "Could not extract functions"

The database may use an unsupported schema. IDA versions before 7.0 use a different format. Try:
- Converting to a newer format
- Exporting from IDA as text first

### Missing comments

Comments in IDA have two types:
- **Regular** (`;`) — Only visible at the address
- **Repeatable** (`Shift+;`) — Visible at all references

GhostBin imports both types.

### Wrong architecture detected

GhostBin reads architecture from the database metadata. If incorrect:
- Check the database was created with the right processor type
- Manually specify architecture in GhostBin if needed

## Best Practices

1. **Complete auto-analysis first** — Ensure IDA/Ghidra has finished analyzing
2. **Name functions meaningfully** — `validate_input` is better than `sub_401000`
3. **Use repeatable comments** — They propagate to all call sites
4. **Backup databases** — Import doesn't modify the original
5. **Import before collaboration** — Team members benefit from existing names

## Advanced: Scripting IDA for Export

Automate IDA database preparation:

```python
# ida_export.py — Run in IDA Pro
import idautils
import idc
import json

data = {
    "functions": [],
    "comments": {}
}

for func_ea in idautils.Functions():
    func_name = idc.get_func_name(func_ea)
    func_end = idc.find_func_end(func_ea)
    comment = idc.get_func_cmt(func_ea, 0)  # Regular
    rpt_comment = idc.get_func_cmt(func_ea, 1)  # Repeatable
    
    data["functions"].append({
        "address": func_ea,
        "name": func_name,
        "size": func_end - func_ea,
        "comment": comment,
        "repeatable_comment": rpt_comment
    })
    
    if comment:
        data["comments"][hex(func_ea)] = comment

with open("/path/to/export.json", "w") as f:
    json.dump(data, f, indent=2)

print("Export complete!")
```

## Next Steps

- Learn about [Bookmarking](getting-started.md) important addresses
- Explore the [Graph View](graph-view.md) for visual analysis
- Write [Plugins](plugins.md) for automated detection
