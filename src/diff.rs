use serde::{Deserialize, Serialize};

/// Result of comparing two binaries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryDiff {
    pub added_functions: Vec<DiffFunction>,
    pub removed_functions: Vec<DiffFunction>,
    pub modified_functions: Vec<ModifiedFunction>,
    pub added_strings: Vec<DiffString>,
    pub removed_strings: Vec<DiffString>,
    pub section_changes: Vec<SectionChange>,
    pub similarity_score: f64, // 0.0 to 1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFunction {
    pub address: u64,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedFunction {
    pub name: String,
    pub old_address: u64,
    pub new_address: u64,
    pub old_size: u64,
    pub new_size: u64,
    pub byte_changes: Vec<ByteChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteChange {
    pub offset: usize,
    pub old_byte: u8,
    pub new_byte: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffString {
    pub address: u64,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionChange {
    pub name: String,
    pub change_type: ChangeType,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub old_address: Option<u64>,
    pub new_address: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeType {
    Added,
    Removed,
    Modified,
}

/// Diff two function lists
pub fn diff_functions(
    old: &[(u64, String, u64)],
    new: &[(u64, String, u64)],
) -> (Vec<DiffFunction>, Vec<DiffFunction>, Vec<ModifiedFunction>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    // Find added and modified
    for &(new_addr, ref new_name, new_size) in new {
        let found = old.iter().find(|(_, name, _)| name == new_name);
        if let Some(&(old_addr, _, old_size)) = found {
            if old_addr != new_addr || old_size != new_size {
                modified.push(ModifiedFunction {
                    name: new_name.clone(),
                    old_address: old_addr,
                    new_address: new_addr,
                    old_size,
                    new_size,
                    byte_changes: Vec::new(),
                });
            }
        } else {
            added.push(DiffFunction {
                address: new_addr,
                name: new_name.clone(),
                size: new_size,
            });
        }
    }

    // Find removed
    for &(old_addr, ref old_name, old_size) in old {
        if !new.iter().any(|(_, name, _)| name == old_name) {
            removed.push(DiffFunction {
                address: old_addr,
                name: old_name.clone(),
                size: old_size,
            });
        }
    }

    (added, removed, modified)
}

/// Diff two string lists
pub fn diff_strings(
    old: &[(u64, String)],
    new: &[(u64, String)],
) -> (Vec<DiffString>, Vec<DiffString>) {
    let mut added = Vec::new();
    let mut removed = Vec::new();

    for &(addr, ref content) in new {
        if !old.iter().any(|(_, c)| c == content) {
            added.push(DiffString {
                address: addr,
                content: content.clone(),
            });
        }
    }

    for &(addr, ref content) in old {
        if !new.iter().any(|(_, c)| c == content) {
            removed.push(DiffString {
                address: addr,
                content: content.clone(),
            });
        }
    }

    (added, removed)
}

/// Diff two section lists
pub fn diff_sections(
    old: &[(String, u64, u64)],
    new: &[(String, u64, u64)],
) -> Vec<SectionChange> {
    let mut changes = Vec::new();

    for (name, addr, size) in new {
        let found = old.iter().find(|(n, _, _)| n == name);
        if let Some((_, old_addr, old_size)) = found {
            if *addr != *old_addr || *size != *old_size {
                changes.push(SectionChange {
                    name: name.clone(),
                    change_type: ChangeType::Modified,
                    old_size: Some(*old_size),
                    new_size: Some(*size),
                    old_address: Some(*old_addr),
                    new_address: Some(*addr),
                });
            }
        } else {
            changes.push(SectionChange {
                name: name.clone(),
                change_type: ChangeType::Added,
                old_size: None,
                new_size: Some(*size),
                old_address: None,
                new_address: Some(*addr),
            });
        }
    }

    for (name, addr, size) in old {
        if !new.iter().any(|(n, _, _)| n == name) {
            changes.push(SectionChange {
                name: name.clone(),
                change_type: ChangeType::Removed,
                old_size: Some(*size),
                new_size: None,
                old_address: Some(*addr),
                new_address: None,
            });
        }
    }

    changes
}

/// Calculate a similarity score between two binaries
/// Returns a value between 0.0 (completely different) and 1.0 (identical)
pub fn calculate_similarity(old_funcs: &[(u64, String, u64)], new_funcs: &[(u64, String, u64)]) -> f64 {
    if old_funcs.is_empty() && new_funcs.is_empty() {
        return 1.0;
    }
    if old_funcs.is_empty() || new_funcs.is_empty() {
        return 0.0;
    }

    let old_names: std::collections::HashSet<_> = old_funcs.iter().map(|(_, n, _)| n.clone()).collect();
    let new_names: std::collections::HashSet<_> = new_funcs.iter().map(|(_, n, _)| n.clone()).collect();

    let intersection: std::collections::HashSet<_> = old_names.intersection(&new_names).cloned().collect();
    let union: std::collections::HashSet<_> = old_names.union(&new_names).cloned().collect();

    intersection.len() as f64 / union.len() as f64
}

/// Detect code patches between two binary versions
/// Returns a list of addresses where code differs
pub fn detect_patches(old_data: &[u8], new_data: &[u8]) -> Vec<PatchRegion> {
    let mut patches = Vec::new();
    let min_len = old_data.len().min(new_data.len());

    let mut current_start: Option<usize> = None;

    for i in 0..min_len {
        if old_data[i] != new_data[i] {
            if current_start.is_none() {
                current_start = Some(i);
            }
        } else if let Some(start) = current_start {
            patches.push(PatchRegion {
                offset: start,
                size: i - start,
                old_bytes: old_data[start..i].to_vec(),
                new_bytes: new_data[start..i].to_vec(),
            });
            current_start = None;
        }
    }

    // Handle patch at end
    if let Some(start) = current_start {
        patches.push(PatchRegion {
            offset: start,
            size: min_len - start,
            old_bytes: old_data[start..min_len].to_vec(),
            new_bytes: new_data[start..min_len].to_vec(),
        });
    }

    // Handle size differences
    if old_data.len() > min_len {
        patches.push(PatchRegion {
            offset: min_len,
            size: old_data.len() - min_len,
            old_bytes: old_data[min_len..].to_vec(),
            new_bytes: vec![],
        });
    } else if new_data.len() > min_len {
        patches.push(PatchRegion {
            offset: min_len,
            size: new_data.len() - min_len,
            old_bytes: vec![],
            new_bytes: new_data[min_len..].to_vec(),
        });
    }

    patches
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRegion {
    pub offset: usize,
    pub size: usize,
    pub old_bytes: Vec<u8>,
    pub new_bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diff_functions() {
        let old = vec![
            (0x1000, "main".to_string(), 100),
            (0x1100, "helper".to_string(), 50),
            (0x1200, "old_func".to_string(), 80),
        ];
        let new = vec![
            (0x1000, "main".to_string(), 100),
            (0x1100, "helper".to_string(), 60),
            (0x1300, "new_func".to_string(), 90),
        ];

        let (added, removed, modified) = diff_functions(&old, &new);

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].name, "new_func");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].name, "old_func");

        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].name, "helper");
        assert_eq!(modified[0].new_size, 60);
    }

    #[test]
    fn test_diff_strings() {
        let old = vec![
            (0x1000, "Hello".to_string()),
            (0x2000, "World".to_string()),
        ];
        let new = vec![
            (0x1000, "Hello".to_string()),
            (0x3000, "New".to_string()),
        ];

        let (added, removed) = diff_strings(&old, &new);

        assert_eq!(added.len(), 1);
        assert_eq!(added[0].content, "New");

        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].content, "World");
    }

    #[test]
    fn test_diff_sections() {
        let old = vec![
            (".text".to_string(), 0x1000, 0x1000),
            (".data".to_string(), 0x2000, 0x500),
        ];
        let new = vec![
            (".text".to_string(), 0x1000, 0x1200),
            (".rdata".to_string(), 0x3000, 0x400),
        ];

        let changes = diff_sections(&old, &new);

        assert_eq!(changes.len(), 3);

        let text_change = changes.iter().find(|c| c.name == ".text").unwrap();
        assert_eq!(text_change.change_type, ChangeType::Modified);

        let data_change = changes.iter().find(|c| c.name == ".data").unwrap();
        assert_eq!(data_change.change_type, ChangeType::Removed);

        let rdata_change = changes.iter().find(|c| c.name == ".rdata").unwrap();
        assert_eq!(rdata_change.change_type, ChangeType::Added);
    }

    #[test]
    fn test_calculate_similarity() {
        let old = vec![
            (0x1000, "main".to_string(), 100),
            (0x1100, "helper".to_string(), 50),
        ];
        let new = vec![
            (0x1000, "main".to_string(), 100),
            (0x1100, "helper".to_string(), 50),
        ];

        assert_eq!(calculate_similarity(&old, &new), 1.0);

        let new2 = vec![
            (0x1000, "main".to_string(), 100),
            (0x1200, "other".to_string(), 50),
        ];

        // intersection = {main} = 1, union = {main, helper, other} = 3
        assert_eq!(calculate_similarity(&old, &new2), 1.0 / 3.0);
    }

    #[test]
    fn test_detect_patches() {
        let old = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let new = vec![0x00, 0x01, 0xAA, 0xBB, 0x04, 0x05];

        let patches = detect_patches(&old, &new);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].offset, 2);
        assert_eq!(patches[0].size, 2);
        assert_eq!(patches[0].old_bytes, vec![0x02, 0x03]);
        assert_eq!(patches[0].new_bytes, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_detect_patches_no_changes() {
        let data = vec![0x00, 0x01, 0x02, 0x03];
        let patches = detect_patches(&data, &data);
        assert!(patches.is_empty());
    }
}
