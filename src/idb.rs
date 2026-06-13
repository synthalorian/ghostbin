//! IDA/Ghidra Database Import
//!
//! Supports importing analysis data from IDA Pro (.i64) and Ghidra (.gpr) databases.
//! Extracts function names, comments, and metadata to enrich GhostBin analysis.
#![allow(clippy::all, dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Imported function information from an external database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedFunction {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub comment: Option<String>,
    pub repeatable_comment: Option<String>,
    pub flags: u32,
}

/// Imported data item (strings, variables, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedData {
    pub address: u64,
    pub name: String,
    pub data_type: String,
    pub size: u64,
    pub comment: Option<String>,
}

/// Complete import result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseImport {
    pub source: String,
    pub binary_path: Option<String>,
    pub architecture: Option<String>,
    pub base_address: u64,
    pub functions: Vec<ImportedFunction>,
    pub data_items: Vec<ImportedData>,
    pub comments: HashMap<u64, String>,
    pub import_errors: Vec<String>,
}

/// Supported database formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseFormat {
    Ida64,
    Ida32,
    Ghidra,
    Unknown,
}

impl DatabaseFormat {
    pub fn from_path(path: &str) -> Self {
        let lower = path.to_lowercase();
        if lower.ends_with(".i64") {
            DatabaseFormat::Ida64
        } else if lower.ends_with(".idb") {
            DatabaseFormat::Ida32
        } else if lower.ends_with(".gpr") {
            DatabaseFormat::Ghidra
        } else {
            DatabaseFormat::Unknown
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DatabaseFormat::Ida64 => "ida64",
            DatabaseFormat::Ida32 => "ida32",
            DatabaseFormat::Ghidra => "ghidra",
            DatabaseFormat::Unknown => "unknown",
        }
    }
}

/// Parse an IDA .i64 database file
///
/// IDA 7.0+ uses SQLite format for .i64 files.
/// We extract functions, names, and comments from the IDB tables.
pub fn parse_ida_database(path: &str) -> anyhow::Result<DatabaseImport> {
    let conn = rusqlite::Connection::open(path)?;

    let mut import = DatabaseImport {
        source: "ida".to_string(),
        binary_path: None,
        architecture: None,
        base_address: 0,
        functions: Vec::new(),
        data_items: Vec::new(),
        comments: HashMap::new(),
        import_errors: Vec::new(),
    };

    // Try to get binary metadata
    if let Ok(mut stmt) = conn.prepare("SELECT value FROM metadata WHERE name = 'INPUT_FILE'") {
        if let Ok(mut rows) = stmt.query([]) {
            if let Ok(Some(row)) = rows.next() {
                import.binary_path = row.get(0).ok();
            }
        }
    }

    // Try to get architecture info
    if let Ok(mut stmt) = conn.prepare("SELECT value FROM metadata WHERE name = 'PROCNAME'") {
        if let Ok(mut rows) = stmt.query([]) {
            if let Ok(Some(row)) = rows.next() {
                import.architecture = row.get(0).ok();
            }
        }
    }

    // Try to get base address
    if let Ok(mut stmt) = conn.prepare("SELECT value FROM metadata WHERE name = 'IMAGE_BASE'") {
        if let Ok(mut rows) = stmt.query([]) {
            if let Ok(Some(row)) = rows.next() {
                if let Ok(base_str) = row.get::<_, String>(0) {
                    if let Ok(base) = u64::from_str_radix(&base_str, 16) {
                        import.base_address = base;
                    }
                }
            }
        }
    }

    // Extract functions from IDA functions table
    // IDA stores functions in various tables depending on version
    let function_queries = [
        "SELECT startEA, endEA, flags FROM functions",
        "SELECT ea, endEA, flags FROM functions",
        "SELECT start_ea, end_ea, flags FROM functions",
    ];

    for query in &function_queries {
        if let Ok(mut stmt) = conn.prepare(query) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let start: i64 = row.get(0)?;
                let end: i64 = row.get(1)?;
                let flags: i32 = row.get(2).unwrap_or(0);
                Ok((start as u64, end as u64, flags as u32))
            }) {
                for row_result in rows {
                    if let Ok((start, end, flags)) = row_result {
                        let size = end.saturating_sub(start);
                        import.functions.push(ImportedFunction {
                            address: start,
                            name: format!("sub_{:x}", start),
                            size,
                            comment: None,
                            repeatable_comment: None,
                            flags,
                        });
                    }
                }
                break; // Successfully found and parsed functions
            }
        }
    }

    // Extract names (function names, labels)
    let name_queries = [
        "SELECT ea, name FROM names",
        "SELECT address, name FROM names",
        "SELECT ea, name FROM ida_names",
    ];

    for query in &name_queries {
        if let Ok(mut stmt) = conn.prepare(query) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let addr: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                Ok((addr as u64, name))
            }) {
                for row_result in rows {
                    if let Ok((addr, name)) = row_result {
                        // Update function name if this address matches a function
                        if let Some(func) = import.functions.iter_mut().find(|f| f.address == addr) {
                            func.name = name;
                        } else {
                            // Could be a data item
                            import.data_items.push(ImportedData {
                                address: addr,
                                name: name.clone(),
                                data_type: "unknown".to_string(),
                                size: 0,
                                comment: None,
                            });
                        }
                    }
                }
                break;
            }
        }
    }

    // Extract comments
    let comment_queries = [
        "SELECT ea, comment, repeatable FROM comments",
        "SELECT address, comment, repeatable FROM comments",
        "SELECT ea, comment, type FROM comments",
    ];

    for query in &comment_queries {
        if let Ok(mut stmt) = conn.prepare(query) {
            if let Ok(rows) = stmt.query_map([], |row| {
                let addr: i64 = row.get(0)?;
                let comment: String = row.get(1)?;
                Ok((addr as u64, comment))
            }) {
                for row_result in rows {
                    if let Ok((addr, comment)) = row_result {
                        // Also attach to function if applicable
                        if let Some(func) = import.functions.iter_mut().find(|f| f.address == addr) {
                            func.comment = Some(comment.clone());
                        }
                        import.comments.insert(addr, comment);
                    }
                }
                break;
            }
        }
    }

    // If we couldn't find functions via standard tables, try alternative approaches
    if import.functions.is_empty() {
        // Some IDA versions store functions in different schemas
        let alt_queries = [
            "SELECT DISTINCT startEA FROM functions",
            "SELECT DISTINCT ea FROM functions",
            "SELECT address, size FROM funcs",
        ];

        for query in &alt_queries {
            if let Ok(mut stmt) = conn.prepare(query) {
                if let Ok(rows) = stmt.query_map([], |row| {
                    let addr: i64 = row.get(0)?;
                    let size: Result<i64, _> = row.get(1);
                    Ok((addr as u64, size.unwrap_or(0) as u64))
                }) {
                    for row_result in rows {
                        if let Ok((addr, size)) = row_result {
                            import.functions.push(ImportedFunction {
                                address: addr,
                                name: format!("sub_{:x}", addr),
                                size,
                                comment: None,
                                repeatable_comment: None,
                                flags: 0,
                            });
                        }
                    }
                    if !import.functions.is_empty() {
                        break;
                    }
                }
            }
        }
    }

    // Sort functions by address
    import.functions.sort_by_key(|f| f.address);
    import.data_items.sort_by_key(|d| d.address);

    if import.functions.is_empty() && import.data_items.is_empty() {
        import.import_errors.push(
            "Could not extract functions or data from IDA database. The database may use an unsupported schema.".to_string()
        );
    }

    Ok(import)
}

/// Parse a Ghidra .gpr project file
///
/// Ghidra stores project metadata in XML .gpr files.
/// We extract program information and try to locate the actual data files.
pub fn parse_ghidra_project(path: &str) -> anyhow::Result<DatabaseImport> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut import = DatabaseImport {
        source: "ghidra".to_string(),
        binary_path: None,
        architecture: None,
        base_address: 0,
        functions: Vec::new(),
        data_items: Vec::new(),
        comments: HashMap::new(),
        import_errors: Vec::new(),
    };

    // Simple XML parsing for Ghidra project files
    // Extract project name and program info
    if let Some(start) = contents.find("<PROGRAM ") {
        let tag_start = &contents[start..];
        if let Some(end) = tag_start.find('>') {
            let program_tag = &tag_start[..end];

            // Extract NAME attribute
            if let Some(name_start) = program_tag.find("NAME=\"") {
                let name_part = &program_tag[name_start + 6..];
                if let Some(name_end) = name_part.find('"') {
                    import.binary_path = Some(name_part[..name_end].to_string());
                }
            }

            // Extract EXE_PATH attribute
            if let Some(path_start) = program_tag.find("EXE_PATH=\"") {
                let path_part = &program_tag[path_start + 10..];
                if let Some(path_end) = path_part.find('"') {
                    import.binary_path = Some(path_part[..path_end].to_string());
                }
            }

            // Extract LANGUAGE_ID (contains architecture info)
            if let Some(lang_start) = program_tag.find("LANGUAGE_ID=\"") {
                let lang_part = &program_tag[lang_start + 13..];
                if let Some(lang_end) = lang_part.find('"') {
                    import.architecture = Some(lang_part[..lang_end].to_string());
                }
            }

            // Extract BASE_ADDRESS
            if let Some(base_start) = program_tag.find("BASE_ADDRESS=\"") {
                let base_part = &program_tag[base_start + 14..];
                if let Some(base_end) = base_part.find('"') {
                    let base_str = &base_part[..base_end];
                    if base_str.starts_with("0x") {
                        import.base_address = u64::from_str_radix(&base_str[2..], 16).unwrap_or(0);
                    } else {
                        import.base_address = base_str.parse().unwrap_or(0);
                    }
                }
            }
        }
    }

    // Try to find and parse the corresponding .rep directory for actual data
    let project_dir = std::path::Path::new(path).parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // Ghidra stores program data in .rep/project.prp or .rep/user data
    let rep_dir = std::path::Path::new(&project_dir).join(".rep");
    if rep_dir.exists() {
        // Try to parse program data from rep directory
        // This is a simplified extraction - Ghidra's actual format is more complex
        import.import_errors.push(
            "Ghidra .rep directory found but detailed program data extraction requires Ghidra's proprietary format parser. Basic metadata extracted.".to_string()
        );
    } else {
        // Try to extract function info from the GPR file itself if it contains any
        // Some .gpr files contain embedded XML data
        if let Some(funcs_start) = contents.find("<FUNCTIONS>") {
            if let Some(funcs_end) = contents[funcs_start..].find("</FUNCTIONS>") {
                let funcs_section = &contents[funcs_start..funcs_start + funcs_end + 12];
                // Parse individual function entries
                for _func_tag in funcs_section.matches("<FUNCTION ") {
                    // This is a simplified parse - in reality we'd use proper XML parsing
                    import.import_errors.push(
                        "GPR file contains function data but requires full XML parsing. Use the Ghidra export feature for better compatibility.".to_string()
                    );
                    break;
                }
            }
        }

        import.import_errors.push(
            "Ghidra .gpr files contain project metadata. For full analysis data, export from Ghidra using XML or CSV format.".to_string()
        );
    }

    Ok(import)
}

/// Auto-detect format and parse database
pub fn import_database(path: &str) -> anyhow::Result<DatabaseImport> {
    let format = DatabaseFormat::from_path(path);

    match format {
        DatabaseFormat::Ida64 | DatabaseFormat::Ida32 => parse_ida_database(path),
        DatabaseFormat::Ghidra => parse_ghidra_project(path),
        DatabaseFormat::Unknown => {
            anyhow::bail!("Unknown database format. Supported formats: .i64, .idb, .gpr")
        }
    }
}

/// Apply imported data to a GhostBin binary
///
/// Updates function names and adds annotations from the imported database.
pub fn apply_import(
    import: &DatabaseImport,
    binary: &mut crate::binary::Binary,
    annotations: &mut crate::annotations::AnnotationStore,
) -> anyhow::Result<ImportSummary> {
    let mut summary = ImportSummary {
        functions_renamed: 0,
        functions_added: 0,
        comments_added: 0,
        annotations_created: 0,
    };

    // Apply function names
    for imported_func in &import.functions {
        let mut found = false;
        for func in &mut binary.functions {
            if func.address == imported_func.address {
                func.name = imported_func.name.clone();
                summary.functions_renamed += 1;
                found = true;
                break;
            }
        }

        if !found {
            // Add new function
            binary.functions.push(crate::binary::Function {
                address: imported_func.address,
                name: imported_func.name.clone(),
                size: imported_func.size,
            });
            summary.functions_added += 1;
        }

        // Add comments as annotations
        if let Some(comment) = &imported_func.comment {
            let addr = format!("0x{:x}", imported_func.address);
            let _ = annotations.add(&addr, comment.clone(), "ida_import".to_string(), None);
            summary.annotations_created += 1;
        }

        if let Some(comment) = &imported_func.repeatable_comment {
            let addr = format!("0x{:x}", imported_func.address);
            let _ = annotations.add(&addr, comment.clone(), "ida_import".to_string(), None);
            summary.annotations_created += 1;
        }
    }

    // Apply general comments
    for (addr, comment) in &import.comments {
        let addr_str = format!("0x{:x}", addr);
        let _ = annotations.add(&addr_str, comment.clone(), "ida_import".to_string(), None);
        summary.comments_added += 1;
    }

    // Sort functions after modifications
    binary.functions.sort_by_key(|f| f.address);

    Ok(summary)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSummary {
    pub functions_renamed: usize,
    pub functions_added: usize,
    pub comments_added: usize,
    pub annotations_created: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    pub database_path: String,
    pub binary_id: String,
    pub options: ImportOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOptions {
    pub import_functions: bool,
    pub import_comments: bool,
    pub import_data: bool,
    pub overwrite_existing: bool,
}

impl Default for ImportOptions {
    fn default() -> Self {
        ImportOptions {
            import_functions: true,
            import_comments: true,
            import_data: true,
            overwrite_existing: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_database_format_detection() {
        assert_eq!(DatabaseFormat::from_path("test.i64"), DatabaseFormat::Ida64);
        assert_eq!(DatabaseFormat::from_path("test.idb"), DatabaseFormat::Ida32);
        assert_eq!(DatabaseFormat::from_path("test.gpr"), DatabaseFormat::Ghidra);
        assert_eq!(DatabaseFormat::from_path("test.bin"), DatabaseFormat::Unknown);
    }

    #[test]
    fn test_format_as_str() {
        assert_eq!(DatabaseFormat::Ida64.as_str(), "ida64");
        assert_eq!(DatabaseFormat::Ghidra.as_str(), "ghidra");
        assert_eq!(DatabaseFormat::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_import_options_default() {
        let opts = ImportOptions::default();
        assert!(opts.import_functions);
        assert!(opts.import_comments);
        assert!(opts.import_data);
        assert!(!opts.overwrite_existing);
    }

    #[test]
    fn test_apply_import_renames_functions() {
        let mut binary = crate::binary::Binary {
            id: "test".to_string(),
            name: "test".to_string(),
            data: vec![],
            format: crate::binary::BinaryFormat::Elf,
            architecture: crate::disasm::Architecture::X86_64,
            entry_point: 0x1000,
            sections: vec![],
            symbols: vec![],
            relocations: vec![],
            functions: vec![
                crate::binary::Function {
                    address: 0x1000,
                    name: "sub_1000".to_string(),
                    size: 0x20,
                },
            ],
            imports: vec![],
            exports: vec![],
            resources: vec![],
        };

        let mut annotations = crate::annotations::AnnotationStore::new();

        let import = DatabaseImport {
            source: "ida".to_string(),
            binary_path: None,
            architecture: None,
            base_address: 0,
            functions: vec![
                ImportedFunction {
                    address: 0x1000,
                    name: "main".to_string(),
                    size: 0x20,
                    comment: Some("Entry point".to_string()),
                    repeatable_comment: None,
                    flags: 0,
                },
            ],
            data_items: vec![],
            comments: HashMap::new(),
            import_errors: vec![],
        };

        let summary = apply_import(&import, &mut binary, &mut annotations).unwrap();
        assert_eq!(summary.functions_renamed, 1);
        assert_eq!(binary.functions[0].name, "main");
    }

    #[test]
    fn test_import_summary_serialization() {
        let summary = ImportSummary {
            functions_renamed: 5,
            functions_added: 2,
            comments_added: 3,
            annotations_created: 4,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("functions_renamed"));
        assert!(json.contains("5"));
    }
}
