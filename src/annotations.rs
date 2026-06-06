use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Annotation {
    pub id: String,
    pub address: String,
    pub text: String,
    pub author: String,
    pub timestamp: DateTime<Utc>,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationThread {
    pub root: Annotation,
    pub replies: Vec<Annotation>,
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

    pub fn get_threads(&self, address: &str) -> Vec<AnnotationThread> {
        let all = self.annotations.get(address).cloned().unwrap_or_default();
        let mut roots: Vec<Annotation> = all
            .iter()
            .filter(|a| a.parent_id.is_none())
            .cloned()
            .collect();
        roots.sort_by_key(|a| a.timestamp);

        roots
            .into_iter()
            .map(|root| {
                let mut replies: Vec<Annotation> = all
                    .iter()
                    .filter(|a| a.parent_id.as_ref() == Some(&root.id))
                    .cloned()
                    .collect();
                replies.sort_by_key(|a| a.timestamp);
                AnnotationThread { root, replies }
            })
            .collect()
    }

    pub async fn add(
        &mut self,
        address: &str,
        text: String,
        author: String,
        parent_id: Option<String>,
    ) -> anyhow::Result<String> {
        if let Some(ref pid) = parent_id {
            let exists = self
                .annotations
                .values()
                .any(|list| list.iter().any(|a| a.id == *pid));
            if !exists {
                anyhow::bail!("Parent annotation not found: {}", pid);
            }
        }

        let id = Uuid::new_v4().to_string();
        let annotation = Annotation {
            id: id.clone(),
            address: address.to_string(),
            text,
            author,
            timestamp: Utc::now(),
            parent_id,
        };

        self.annotations
            .entry(address.to_string())
            .or_default()
            .push(annotation);

        Ok(id)
    }

    #[allow(dead_code)]
    pub fn delete(&mut self, annotation_id: &str) -> anyhow::Result<()> {
        for list in self.annotations.values_mut() {
            if let Some(pos) = list.iter().position(|a| a.id == annotation_id) {
                list.remove(pos);
                return Ok(());
            }
        }
        anyhow::bail!("Annotation not found: {}", annotation_id)
    }

    #[allow(dead_code)]
    pub fn get_all(&self) -> &HashMap<String, Vec<Annotation>> {
        &self.annotations
    }

    pub fn annotation_count(&self) -> usize {
        self.annotations.values().map(|v| v.len()).sum()
    }
}
