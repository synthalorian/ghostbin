#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A simple signature rule for pattern matching in binary data
/// This is a lightweight YARA-like implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRule {
    pub name: String,
    pub description: String,
    pub pattern: Vec<u8>,
    pub mask: Option<Vec<u8>>,
    pub category: String,
}

/// Match result from a signature scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub rule_name: String,
    pub description: String,
    pub offset: usize,
    pub matched_bytes: Vec<u8>,
    pub category: String,
}

/// Built-in signature database for common patterns
pub fn built_in_rules() -> Vec<SignatureRule> {
    vec![
        SignatureRule {
            name: "UPX_Packer".to_string(),
            description: "UPX packed executable".to_string(),
            pattern: vec![0x55, 0x50, 0x58, 0x21],
            mask: None,
            category: "packer".to_string(),
        },
        SignatureRule {
            name: "PE_DOS_Header".to_string(),
            description: "DOS header magic (MZ)".to_string(),
            pattern: vec![0x4D, 0x5A],
            mask: None,
            category: "format".to_string(),
        },
        SignatureRule {
            name: "ELF_Header".to_string(),
            description: "ELF header magic".to_string(),
            pattern: vec![0x7F, 0x45, 0x4C, 0x46],
            mask: None,
            category: "format".to_string(),
        },
        SignatureRule {
            name: "MachO_Header".to_string(),
            description: "Mach-O header magic".to_string(),
            pattern: vec![0xFE, 0xED, 0xFA, 0xCE],
            mask: None,
            category: "format".to_string(),
        },
        SignatureRule {
            name: "MachO_Header_64".to_string(),
            description: "Mach-O 64-bit header magic".to_string(),
            pattern: vec![0xFE, 0xED, 0xFA, 0xCF],
            mask: None,
            category: "format".to_string(),
        },
        SignatureRule {
            name: "AES_Sbox".to_string(),
            description: "Possible AES S-box table".to_string(),
            pattern: vec![0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5],
            mask: None,
            category: "crypto".to_string(),
        },
        SignatureRule {
            name: "Suspicious_URL".to_string(),
            description: "Contains HTTP URL pattern".to_string(),
            pattern: b"http://".to_vec(),
            mask: None,
            category: "network".to_string(),
        },
        SignatureRule {
            name: "Suspicious_HTTPS".to_string(),
            description: "Contains HTTPS URL pattern".to_string(),
            pattern: b"https://".to_vec(),
            mask: None,
            category: "network".to_string(),
        },
        SignatureRule {
            name: "x86_Nop_Sled".to_string(),
            description: "Large sequence of NOP instructions (possible shellcode)".to_string(),
            pattern: vec![0x90; 16],
            mask: None,
            category: "shellcode".to_string(),
        },
        SignatureRule {
            name: "Base64_Alphabet".to_string(),
            description: "Base64 encoding alphabet".to_string(),
            pattern: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_vec(),
            mask: None,
            category: "encoding".to_string(),
        },
    ]
}

/// Scan binary data against a set of signature rules
pub fn scan(data: &[u8], rules: &[SignatureRule]) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();

    for rule in rules {
        let rule_matches = scan_single_rule(data, rule);
        matches.extend(rule_matches);
    }

    // Sort by offset for consistent output
    matches.sort_by_key(|m| m.offset);
    matches
}

fn scan_single_rule(data: &[u8], rule: &SignatureRule) -> Vec<SignatureMatch> {
    let mut matches = Vec::new();
    let pattern = &rule.pattern;

    if pattern.len() > data.len() {
        return matches;
    }

    for i in 0..=data.len() - pattern.len() {
        if matches_at(data, pattern, i, rule.mask.as_ref()) {
            let matched_bytes = data[i..i + pattern.len().min(32)].to_vec();
            matches.push(SignatureMatch {
                rule_name: rule.name.clone(),
                description: rule.description.clone(),
                offset: i,
                matched_bytes,
                category: rule.category.clone(),
            });

            // For large patterns, only report the first match to reduce noise
            if pattern.len() > 8 {
                break;
            }
        }
    }

    matches
}

fn matches_at(data: &[u8], pattern: &[u8], offset: usize, mask: Option<&Vec<u8>>) -> bool {
    if let Some(mask) = mask {
        if mask.len() != pattern.len() {
            return false;
        }
        for i in 0..pattern.len() {
            if mask[i] == 0xFF && data[offset + i] != pattern[i] {
                return false;
            }
        }
        true
    } else {
        data[offset..offset + pattern.len()] == pattern[..]
    }
}

/// Load custom rules from a simple JSON format
pub fn load_rules_from_json(json: &str) -> anyhow::Result<Vec<SignatureRule>> {
    let rules: Vec<SignatureRule> = serde_json::from_str(json)?;
    Ok(rules)
}

/// Categorize matches by category
pub fn categorize_matches(matches: &[SignatureMatch]) -> HashMap<String, Vec<SignatureMatch>> {
    let mut categories: HashMap<String, Vec<SignatureMatch>> = HashMap::new();

    for m in matches {
        categories
            .entry(m.category.clone())
            .or_default()
            .push(m.clone());
    }

    categories
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_pe_header() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        let rules = built_in_rules();
        let matches = scan(&data, &rules);

        let pe_match = matches.iter().find(|m| m.rule_name == "PE_DOS_Header");
        assert!(pe_match.is_some(), "Should detect PE DOS header");
        assert_eq!(pe_match.unwrap().offset, 0);
    }

    #[test]
    fn test_scan_elf_header() {
        let data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
        let rules = built_in_rules();
        let matches = scan(&data, &rules);

        let elf_match = matches.iter().find(|m| m.rule_name == "ELF_Header");
        assert!(elf_match.is_some(), "Should detect ELF header");
    }

    #[test]
    fn test_scan_no_match() {
        let data = vec![0x00; 100];
        let rules = built_in_rules();
        let matches = scan(&data, &rules);

        assert!(matches.is_empty(), "Should find no matches in zeroed data");
    }

    #[test]
    fn test_custom_rule() {
        let data = b"Hello, this contains http://example.com in it!";
        let rules = built_in_rules();
        let matches = scan(data, &rules);

        let url_match = matches.iter().find(|m| m.rule_name == "Suspicious_URL");
        assert!(url_match.is_some(), "Should detect HTTP URL");
    }

    #[test]
    fn test_load_rules_from_json() {
        let json = r#"[
            {
                "name": "TestRule",
                "description": "Test rule",
                "pattern": [65, 66, 67],
                "mask": null,
                "category": "test"
            }
        ]"#;

        let rules = load_rules_from_json(json).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "TestRule");

        let data = b"XXXABCXXX";
        let matches = scan(data, &rules);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offset, 3);
    }

    #[test]
    fn test_categorize_matches() {
        let matches = vec![
            SignatureMatch {
                rule_name: "Rule1".to_string(),
                description: "Desc1".to_string(),
                offset: 0,
                matched_bytes: vec![0x00],
                category: "packer".to_string(),
            },
            SignatureMatch {
                rule_name: "Rule2".to_string(),
                description: "Desc2".to_string(),
                offset: 10,
                matched_bytes: vec![0x00],
                category: "packer".to_string(),
            },
            SignatureMatch {
                rule_name: "Rule3".to_string(),
                description: "Desc3".to_string(),
                offset: 20,
                matched_bytes: vec![0x00],
                category: "crypto".to_string(),
            },
        ];

        let categories = categorize_matches(&matches);
        assert_eq!(categories.get("packer").unwrap().len(), 2);
        assert_eq!(categories.get("crypto").unwrap().len(), 1);
    }
}
