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
            .or_default()
            .push(annotation);

        Ok(())
    }

    pub fn get_all(&self) -> &HashMap<String, Vec<Annotation>> {
        &self.annotations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_annotations_crud() {
        let mut store = AnnotationStore::new().unwrap();

        // Create
        store
            .add("0x1000", "entry point".to_string(), "alice".to_string())
            .await
            .unwrap();
        store
            .add("0x1000", "check stack canary".to_string(), "bob".to_string())
            .await
            .unwrap();
        store
            .add("0x2000", "helper".to_string(), "alice".to_string())
            .await
            .unwrap();

        // Read
        let anns = store.get("0x1000").unwrap();
        assert_eq!(anns.len(), 2);
        assert_eq!(anns[0].text, "entry point");
        assert_eq!(anns[0].author, "alice");
        assert_eq!(anns[1].author, "bob");
        assert!(anns[0].timestamp > 0);
        assert_eq!(anns[0].address, "0x1000");

        // Missing address returns None
        assert!(store.get("0xdead").is_none());

        // get_all covers both addresses
        assert_eq!(store.get_all().len(), 2);
    }
}
