#![allow(dead_code)]

use serde::{Deserialize, Serialize};

/// A bookmark representing an interesting address in a binary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    pub id: String,
    pub binary_id: String,
    pub address: u64,
    pub name: String,
    pub description: String,
    pub category: BookmarkCategory,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BookmarkCategory {
    Function,
    String,
    Data,
    Code,
    Suspicious,
    Custom(String),
}

impl std::fmt::Display for BookmarkCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BookmarkCategory::Function => write!(f, "function"),
            BookmarkCategory::String => write!(f, "string"),
            BookmarkCategory::Data => write!(f, "data"),
            BookmarkCategory::Code => write!(f, "code"),
            BookmarkCategory::Suspicious => write!(f, "suspicious"),
            BookmarkCategory::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// In-memory bookmark store (will be backed by SQLite in production)
pub struct BookmarkStore {
    bookmarks: Vec<Bookmark>,
}

impl BookmarkStore {
    pub fn new() -> Self {
        BookmarkStore {
            bookmarks: Vec::new(),
        }
    }

    pub fn add(&mut self, bookmark: Bookmark) -> anyhow::Result<()> {
        // Check for duplicate address in same binary
        if self
            .bookmarks
            .iter()
            .any(|b| b.binary_id == bookmark.binary_id && b.address == bookmark.address)
        {
            anyhow::bail!(
                "Bookmark already exists for address 0x{:x} in binary {}",
                bookmark.address,
                bookmark.binary_id
            );
        }

        self.bookmarks.push(bookmark);
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> anyhow::Result<()> {
        let pos = self
            .bookmarks
            .iter()
            .position(|b| b.id == id)
            .ok_or_else(|| anyhow::anyhow!("Bookmark not found: {}", id))?;
        self.bookmarks.remove(pos);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Bookmark> {
        self.bookmarks.iter().find(|b| b.id == id)
    }

    pub fn get_by_binary(&self, binary_id: &str) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.binary_id == binary_id)
            .collect()
    }

    pub fn get_by_category(
        &self,
        binary_id: &str,
        category: &BookmarkCategory,
    ) -> Vec<&Bookmark> {
        self.bookmarks
            .iter()
            .filter(|b| b.binary_id == binary_id && &b.category == category)
            .collect()
    }

    pub fn update_name(&mut self, id: &str, name: String) -> anyhow::Result<()> {
        let bookmark = self
            .bookmarks
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| anyhow::anyhow!("Bookmark not found: {}", id))?;
        bookmark.name = name;
        Ok(())
    }

    pub fn update_description(&mut self, id: &str, description: String) -> anyhow::Result<()> {
        let bookmark = self
            .bookmarks
            .iter_mut()
            .find(|b| b.id == id)
            .ok_or_else(|| anyhow::anyhow!("Bookmark not found: {}", id))?;
        bookmark.description = description;
        Ok(())
    }

    pub fn list_all(&self) -> &[Bookmark] {
        &self.bookmarks
    }

    pub fn count(&self) -> usize {
        self.bookmarks.len()
    }

    pub fn clear_binary(&mut self, binary_id: &str) {
        self.bookmarks.retain(|b| b.binary_id != binary_id);
    }
}

impl Default for BookmarkStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_bookmark(id: &str, binary_id: &str, address: u64) -> Bookmark {
        Bookmark {
            id: id.to_string(),
            binary_id: binary_id.to_string(),
            address,
            name: format!("bookmark_{}", id),
            description: "Test bookmark".to_string(),
            category: BookmarkCategory::Function,
            color: "#FF0000".to_string(),
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut store = BookmarkStore::new();
        let bookmark = create_test_bookmark("1", "bin1", 0x1000);

        store.add(bookmark.clone()).unwrap();
        assert_eq!(store.count(), 1);

        let retrieved = store.get("1").unwrap();
        assert_eq!(retrieved.address, 0x1000);
    }

    #[test]
    fn test_duplicate_address_fails() {
        let mut store = BookmarkStore::new();
        let b1 = create_test_bookmark("1", "bin1", 0x1000);
        let b2 = create_test_bookmark("2", "bin1", 0x1000);

        store.add(b1).unwrap();
        assert!(store.add(b2).is_err());
    }

    #[test]
    fn test_different_binaries_same_address() {
        let mut store = BookmarkStore::new();
        let b1 = create_test_bookmark("1", "bin1", 0x1000);
        let b2 = create_test_bookmark("2", "bin2", 0x1000);

        store.add(b1).unwrap();
        store.add(b2).unwrap();
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn test_remove() {
        let mut store = BookmarkStore::new();
        let bookmark = create_test_bookmark("1", "bin1", 0x1000);

        store.add(bookmark).unwrap();
        store.remove("1").unwrap();
        assert_eq!(store.count(), 0);
        assert!(store.get("1").is_none());
    }

    #[test]
    fn test_get_by_binary() {
        let mut store = BookmarkStore::new();
        store.add(create_test_bookmark("1", "bin1", 0x1000)).unwrap();
        store.add(create_test_bookmark("2", "bin1", 0x2000)).unwrap();
        store.add(create_test_bookmark("3", "bin2", 0x1000)).unwrap();

        let bin1_bookmarks = store.get_by_binary("bin1");
        assert_eq!(bin1_bookmarks.len(), 2);
    }

    #[test]
    fn test_get_by_category() {
        let mut store = BookmarkStore::new();
        let mut b1 = create_test_bookmark("1", "bin1", 0x1000);
        b1.category = BookmarkCategory::Suspicious;
        store.add(b1).unwrap();
        store.add(create_test_bookmark("2", "bin1", 0x2000)).unwrap();

        let suspicious = store.get_by_category("bin1", &BookmarkCategory::Suspicious);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].id, "1");
    }

    #[test]
    fn test_update_name() {
        let mut store = BookmarkStore::new();
        store.add(create_test_bookmark("1", "bin1", 0x1000)).unwrap();

        store.update_name("1", "new_name".to_string()).unwrap();
        assert_eq!(store.get("1").unwrap().name, "new_name");
    }

    #[test]
    fn test_clear_binary() {
        let mut store = BookmarkStore::new();
        store.add(create_test_bookmark("1", "bin1", 0x1000)).unwrap();
        store.add(create_test_bookmark("2", "bin1", 0x2000)).unwrap();
        store.add(create_test_bookmark("3", "bin2", 0x1000)).unwrap();

        store.clear_binary("bin1");
        assert_eq!(store.count(), 1);
        assert!(store.get("1").is_none());
        assert!(store.get("3").is_some());
    }
}
