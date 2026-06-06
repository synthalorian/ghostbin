use serde::{Deserialize, Serialize};

/// Calculate Shannon entropy of a byte slice
/// Returns value between 0.0 (constant) and 8.0 (maximum randomness)
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0u64; 256];
    for &byte in data {
        frequency[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &frequency {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

/// Section entropy result with classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub entropy: f64,
    pub classification: EntropyClassification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EntropyClassification {
    Low,
    Normal,
    High,
    VeryHigh,
}

impl std::fmt::Display for EntropyClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyClassification::Low => write!(f, "low"),
            EntropyClassification::Normal => write!(f, "normal"),
            EntropyClassification::High => write!(f, "high"),
            EntropyClassification::VeryHigh => write!(f, "very_high"),
        }
    }
}

/// Classify entropy value
/// - 0.0 - 5.0: Low (normal code/data)
/// - 5.0 - 6.5: Normal (mixed content)
/// - 6.5 - 7.2: High (possibly compressed/encrypted)
/// - 7.2 - 8.0: Very High (likely encrypted or random)
pub fn classify_entropy(entropy: f64) -> EntropyClassification {
    match entropy {
        e if e < 5.0 => EntropyClassification::Low,
        e if e < 6.5 => EntropyClassification::Normal,
        e if e < 7.2 => EntropyClassification::High,
        _ => EntropyClassification::VeryHigh,
    }
}

/// Analyze all sections of a binary for entropy
pub fn analyze_sections(
    sections: &[(String, u64, u64, u64)],
    data: &[u8],
) -> Vec<SectionEntropy> {
    let mut results = Vec::new();

    for (name, address, size, offset) in sections {
        let start = *offset as usize;
        let end = start + *size as usize;

        if end > data.len() || start >= data.len() {
            continue;
        }

        let section_data = &data[start..end];
        let entropy = calculate_entropy(section_data);
        let classification = classify_entropy(entropy);

        results.push(SectionEntropy {
            name: name.clone(),
            address: *address,
            size: *size,
            entropy,
            classification,
        });
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(calculate_entropy(b""), 0.0);
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0x41; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.1, "Constant data should have near-zero entropy");
    }

    #[test]
    fn test_entropy_maximum() {
        // Alternating bytes to get high entropy
        let mut data = Vec::with_capacity(256);
        for i in 0..256 {
            data.push(i as u8);
        }
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.0, "Random data should have high entropy, got {}", entropy);
    }

    #[test]
    fn test_entropy_english_text() {
        let text = b"The quick brown fox jumps over the lazy dog. ";
        let entropy = calculate_entropy(text);
        // English text typically has entropy around 4.0-4.5
        assert!(
            entropy > 3.0 && entropy < 5.5,
            "English text entropy should be moderate, got {}",
            entropy
        );
    }

    #[test]
    fn test_classify_entropy() {
        assert_eq!(classify_entropy(3.0), EntropyClassification::Low);
        assert_eq!(classify_entropy(5.5), EntropyClassification::Normal);
        assert_eq!(classify_entropy(7.0), EntropyClassification::High);
        assert_eq!(classify_entropy(7.5), EntropyClassification::VeryHigh);
    }

    #[test]
    fn test_analyze_sections() {
        let data = vec![0x41; 100]; // Constant data
        let sections = vec![(
            ".text".to_string(),
            0x1000,
            100,
            0,
        )];

        let results = analyze_sections(&sections, &data);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, ".text");
        assert!(results[0].entropy < 0.1);
        assert_eq!(results[0].classification, EntropyClassification::Low);
    }
}
