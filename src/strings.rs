use serde::{Deserialize, Serialize};

/// A string found in the binary with its location and referencing functions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BinaryString {
    pub address: u64,
    pub content: String,
    pub length: usize,
    pub encoding: StringEncoding,
    /// Addresses of functions that reference this string
    pub xrefs: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StringEncoding {
    Ascii,
    Utf8,
    Utf16Le,
}

impl std::fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StringEncoding::Ascii => write!(f, "ASCII"),
            StringEncoding::Utf8 => write!(f, "UTF-8"),
            StringEncoding::Utf16Le => write!(f, "UTF-16LE"),
        }
    }
}

/// Minimum length of strings to extract (to avoid noise)
const MIN_STRING_LENGTH: usize = 4;

/// Extract all printable strings from binary data
pub fn extract_strings(data: &[u8], base_address: u64) -> Vec<BinaryString> {
    let mut strings = Vec::new();

    // Extract ASCII/UTF-8 strings
    strings.extend(extract_ascii_strings(data, base_address));

    // Extract UTF-16LE strings
    strings.extend(extract_utf16le_strings(data, base_address));

    // Sort by address for consistent output
    strings.sort_by_key(|s| s.address);

    strings
}

fn extract_ascii_strings(data: &[u8], base_address: u64) -> Vec<BinaryString> {
    let mut strings = Vec::new();
    let mut current_start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        let is_printable = byte.is_ascii_graphic() || byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r';

        if is_printable {
            if current_start.is_none() {
                current_start = Some(i);
            }
        } else if let Some(start) = current_start {
            let len = i - start;
            if len >= MIN_STRING_LENGTH {
                if let Ok(content) = std::str::from_utf8(&data[start..i]) {
                    strings.push(BinaryString {
                        address: base_address + start as u64,
                        content: content.to_string(),
                        length: len,
                        encoding: StringEncoding::Ascii,
                        xrefs: Vec::new(),
                    });
                }
            }
            current_start = None;
        }
    }

    // Handle string at end of data
    if let Some(start) = current_start {
        let len = data.len() - start;
        if len >= MIN_STRING_LENGTH {
            if let Ok(content) = std::str::from_utf8(&data[start..]) {
                strings.push(BinaryString {
                    address: base_address + start as u64,
                    content: content.to_string(),
                    length: len,
                    encoding: StringEncoding::Ascii,
                    xrefs: Vec::new(),
                });
            }
        }
    }

    strings
}

fn extract_utf16le_strings(data: &[u8], base_address: u64) -> Vec<BinaryString> {
    let mut strings = Vec::new();
    let mut current_start: Option<usize> = None;

    for i in (0..data.len().saturating_sub(1)).step_by(2) {
        let low = data[i];
        let high = data[i + 1];

        // Check for printable UTF-16LE character (ASCII range with zero high byte)
        let is_printable = high == 0 && (low.is_ascii_graphic() || low == b' ' || low == b'\t' || low == b'\n' || low == b'\r');

        if is_printable {
            if current_start.is_none() {
                current_start = Some(i);
            }
        } else if let Some(start) = current_start {
            let len = (i - start) / 2;
            if len >= MIN_STRING_LENGTH {
                let u16_bytes: Vec<u16> = (start..i)
                    .step_by(2)
                    .map(|j| u16::from_le_bytes([data[j], data[j + 1]]))
                    .collect();

                if let Ok(content) = String::from_utf16(&u16_bytes) {
                    strings.push(BinaryString {
                        address: base_address + start as u64,
                        content,
                        length: len,
                        encoding: StringEncoding::Utf16Le,
                        xrefs: Vec::new(),
                    });
                }
            }
            current_start = None;
        }
    }

    strings
}

/// Find cross-references to strings by scanning disassembly for address references
///
/// This is a heuristic approach that looks for instruction operands containing
/// string addresses. A more precise approach would require full instruction decoding.
pub fn find_string_xrefs(
    strings: &mut [BinaryString],
    instructions: &[(u64, String, String)], // (address, mnemonic, operands)
) {
    for string in strings.iter_mut() {
        let string_addr = string.address;

        for (insn_addr, _mnemonic, operands) in instructions {
            // Look for the string address in operands
            let addr_str = format!("0x{:x}", string_addr);
            let addr_str_upper = format!("0x{:X}", string_addr);

            if operands.contains(&addr_str) || operands.contains(&addr_str_upper) {
                string.xrefs.push(*insn_addr);
            } else {
                // Also check for RIP-relative references on x86_64
                // e.g., [rip + 0x1234] where the target is the string
                // This is a simplified check
                if operands.contains("rip") {
                    // The actual calculation would require instruction length
                    // For now, we skip precise RIP-relative matching
                }
            }
        }

        // Remove duplicates and sort
        string.xrefs.sort_unstable();
        string.xrefs.dedup();
    }
}

/// Filter strings by minimum length and optionally by pattern
pub fn filter_strings(strings: &[BinaryString], min_len: usize, pattern: Option<&str>) -> Vec<BinaryString> {
    strings
        .iter()
        .filter(|s| {
            if s.length < min_len {
                return false;
            }
            if let Some(pat) = pattern {
                return s.content.contains(pat);
            }
            true
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ascii_strings() {
        let data = b"\x00\x00Hello World\x00\x00Test\x00\x00Another long string here\x00";
        let strings = extract_ascii_strings(data, 0x1000);

        assert_eq!(strings.len(), 3, "Should find 3 strings (min length is 4)");
        assert_eq!(strings[0].content, "Hello World");
        assert_eq!(strings[0].address, 0x1002);
        assert_eq!(strings[0].encoding, StringEncoding::Ascii);

        assert_eq!(strings[1].content, "Test");
        assert_eq!(strings[1].address, 0x100F);

        assert_eq!(strings[2].content, "Another long string here");
        assert_eq!(strings[2].address, 0x1015);
    }

    #[test]
    fn test_extract_utf16le_strings() {
        // "Hello" in UTF-16LE
        let data = vec![
            0x00, 0x00,
            b'H', 0x00, b'e', 0x00, b'l', 0x00, b'l', 0x00, b'o', 0x00,
            0x00, 0x00,
        ];
        let strings = extract_utf16le_strings(&data, 0x2000);

        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].content, "Hello");
        assert_eq!(strings[0].address, 0x2002);
        assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
    }

    #[test]
    fn test_find_string_xrefs() {
        let mut strings = vec![
            BinaryString {
                address: 0x401000,
                content: "Hello".to_string(),
                length: 5,
                encoding: StringEncoding::Ascii,
                xrefs: Vec::new(),
            },
        ];

        let instructions = vec![
            (0x401100, "mov".to_string(), "rax, 0x401000".to_string()),
            (0x401104, "call".to_string(), "printf".to_string()),
            (0x401109, "mov".to_string(), "rbx, 0x402000".to_string()),
        ];

        find_string_xrefs(&mut strings, &instructions);

        assert_eq!(strings[0].xrefs.len(), 1);
        assert_eq!(strings[0].xrefs[0], 0x401100);
    }

    #[test]
    fn test_filter_strings() {
        let strings = vec![
            BinaryString {
                address: 0x1000,
                content: "Hello World".to_string(),
                length: 11,
                encoding: StringEncoding::Ascii,
                xrefs: Vec::new(),
            },
            BinaryString {
                address: 0x2000,
                content: "Test string".to_string(),
                length: 11,
                encoding: StringEncoding::Ascii,
                xrefs: Vec::new(),
            },
            BinaryString {
                address: 0x3000,
                content: "Hi".to_string(),
                length: 2,
                encoding: StringEncoding::Ascii,
                xrefs: Vec::new(),
            },
        ];

        let filtered = filter_strings(&strings, 5, Some("Hello"));
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].content, "Hello World");

        let min_len = filter_strings(&strings, 5, None);
        assert_eq!(min_len.len(), 2);
    }

    #[test]
    fn test_extract_strings_empty_data() {
        let data: &[u8] = b"";
        let strings = extract_strings(data, 0x1000);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_no_strings() {
        let data: &[u8] = b"\x00\x01\x02\x03\x04\x05";
        let strings = extract_strings(data, 0x1000);
        assert!(strings.is_empty());
    }
}
