use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub address: String,
    pub text: String,
    pub author: String,
    pub timestamp: u64,
}

pub struct AnnotationStore {
    annotations: HashMap<String, Vec<Annotation>>,
}

impl AnnotationStore {
    pub fn new() -> anyhow::Result<Self> {
        Ok(AnnotationStore {
            annotations: HashMap::new(),
        })
    }

    pub fn get(&self, address: &str) -> Option<&Vec<Annotation>> {
        self.annotations.get(address)
    }

    pub async fn add(&mut self, address: &str, text: String, author: String) -> anyhow::Result<()> {
        let annotation = Annotation {
            address: address.to_string(),
            text,
            author,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
        };

        self.annotations
            .entry(address.to_string())
            .or_insert_with(Vec::new)
            .push(annotation);

        Ok(())
    }

    pub fn get_all(&self) -> &HashMap<String, Vec<Annotation>> {
        &self.annotations
    }
}
