use rusqlite::{Connection, Result as SqliteResult, params};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Persistent session storage using SQLite with thread-safe access
pub struct SessionStore {
    conn: Mutex<Connection>,
}

/// A saved analysis session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisSession {
    pub id: String,
    pub binary_id: String,
    pub binary_name: String,
    pub created_at: String,
    pub updated_at: String,
    pub state: SessionState,
}

/// Serializable session state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub renamed_symbols: HashMap<String, String>,
    pub bookmarks: Vec<crate::bookmarks::Bookmark>,
    pub annotations: Vec<SessionAnnotation>,
    pub graph_viewport: Option<GraphViewport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnnotation {
    pub address: String,
    pub text: String,
    pub author: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphViewport {
    pub x: f64,
    pub y: f64,
    pub zoom: f64,
    pub selected_node: Option<String>,
}

impl SessionStore {
    pub fn new(db_path: &str) -> SqliteResult<Self> {
        let conn = Connection::open(db_path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                binary_id TEXT NOT NULL,
                binary_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                state TEXT NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS renamed_symbols (
                session_id TEXT NOT NULL,
                original_name TEXT NOT NULL,
                new_name TEXT NOT NULL,
                PRIMARY KEY (session_id, original_name),
                FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_binary_id ON sessions(binary_id)",
            [],
        )?;

        Ok(SessionStore { conn: Mutex::new(conn) })
    }

    pub fn create_session(
        &self,
        id: String,
        binary_id: String,
        binary_name: String,
    ) -> SqliteResult<AnalysisSession> {
        let now = chrono::Utc::now().to_rfc3339();
        let state = SessionState {
            renamed_symbols: HashMap::new(),
            bookmarks: Vec::new(),
            annotations: Vec::new(),
            graph_viewport: None,
        };
        let state_json = serde_json::to_string(&state).unwrap_or_default();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sessions (id, binary_id, binary_name, created_at, updated_at, state)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![&id, &binary_id, &binary_name, &now, &now, &state_json],
        )?;

        Ok(AnalysisSession {
            id,
            binary_id,
            binary_name,
            created_at: now.clone(),
            updated_at: now,
            state,
        })
    }

    pub fn get_session(&self, id: &str) -> SqliteResult<Option<AnalysisSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, binary_id, binary_name, created_at, updated_at, state
             FROM sessions WHERE id = ?1"
        )?;

        let mut rows = stmt.query(params![id])?;

        if let Some(row) = rows.next()? {
            let state_json: String = row.get(5)?;
            let state: SessionState = serde_json::from_str(&state_json).unwrap_or_else(|_| SessionState {
                renamed_symbols: HashMap::new(),
                bookmarks: Vec::new(),
                annotations: Vec::new(),
                graph_viewport: None,
            });

            Ok(Some(AnalysisSession {
                id: row.get(0)?,
                binary_id: row.get(1)?,
                binary_name: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                state,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_session_state(&self, id: &str, state: &SessionState) -> SqliteResult<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let state_json = serde_json::to_string(state).unwrap_or_default();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sessions SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![&state_json, &now, id],
        )?;

        Ok(())
    }

    pub fn list_sessions(&self) -> SqliteResult<Vec<AnalysisSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, binary_id, binary_name, created_at, updated_at, state
             FROM sessions ORDER BY updated_at DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            let state_json: String = row.get(5)?;
            let state: SessionState = serde_json::from_str(&state_json).unwrap_or_else(|_| SessionState {
                renamed_symbols: HashMap::new(),
                bookmarks: Vec::new(),
                annotations: Vec::new(),
                graph_viewport: None,
            });

            Ok(AnalysisSession {
                id: row.get(0)?,
                binary_id: row.get(1)?,
                binary_name: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                state,
            })
        })?;

        let mut sessions = Vec::new();
        for session in rows {
            sessions.push(session?);
        }

        Ok(sessions)
    }

    pub fn list_sessions_for_binary(&self, binary_id: &str) -> SqliteResult<Vec<AnalysisSession>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, binary_id, binary_name, created_at, updated_at, state
             FROM sessions WHERE binary_id = ?1 ORDER BY updated_at DESC"
        )?;

        let rows = stmt.query_map(params![binary_id], |row| {
            let state_json: String = row.get(5)?;
            let state: SessionState = serde_json::from_str(&state_json).unwrap_or_else(|_| SessionState {
                renamed_symbols: HashMap::new(),
                bookmarks: Vec::new(),
                annotations: Vec::new(),
                graph_viewport: None,
            });

            Ok(AnalysisSession {
                id: row.get(0)?,
                binary_id: row.get(1)?,
                binary_name: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
                state,
            })
        })?;

        let mut sessions = Vec::new();
        for session in rows {
            sessions.push(session?);
        }

        Ok(sessions)
    }

    pub fn delete_session(&self, id: &str) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM sessions WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn save_renamed_symbol(
        &self,
        session_id: &str,
        original_name: &str,
        new_name: &str,
    ) -> SqliteResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO renamed_symbols (session_id, original_name, new_name)
             VALUES (?1, ?2, ?3)",
            params![session_id, original_name, new_name],
        )?;
        Ok(())
    }

    pub fn get_renamed_symbols(&self, session_id: &str) -> SqliteResult<HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT original_name, new_name FROM renamed_symbols WHERE session_id = ?1"
        )?;

        let rows = stmt.query_map(params![session_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;

        let mut symbols = HashMap::new();
        for row in rows {
            let (original, new) = row?;
            symbols.insert(original, new);
        }

        Ok(symbols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_store() -> SessionStore {
        SessionStore::new(":memory:").unwrap()
    }

    #[test]
    fn test_create_and_get_session() {
        let store = create_test_store();
        let session = store.create_session(
            "sess1".to_string(),
            "bin1".to_string(),
            "test_binary".to_string(),
        ).unwrap();

        assert_eq!(session.id, "sess1");
        assert_eq!(session.binary_id, "bin1");

        let retrieved = store.get_session("sess1").unwrap().unwrap();
        assert_eq!(retrieved.binary_name, "test_binary");
    }

    #[test]
    fn test_update_session_state() {
        let store = create_test_store();
        store.create_session(
            "sess1".to_string(),
            "bin1".to_string(),
            "test".to_string(),
        ).unwrap();

        let mut state = SessionState {
            renamed_symbols: HashMap::new(),
            bookmarks: Vec::new(),
            annotations: Vec::new(),
            graph_viewport: Some(GraphViewport {
                x: 100.0,
                y: 200.0,
                zoom: 1.5,
                selected_node: Some("node_1".to_string()),
            }),
        };
        state.renamed_symbols.insert("old_name".to_string(), "new_name".to_string());

        store.update_session_state("sess1", &state).unwrap();

        let retrieved = store.get_session("sess1").unwrap().unwrap();
        assert_eq!(retrieved.state.renamed_symbols.get("old_name"), Some(&"new_name".to_string()));
        assert!(retrieved.state.graph_viewport.is_some());
    }

    #[test]
    fn test_list_sessions() {
        let store = create_test_store();
        store.create_session("sess1".to_string(), "bin1".to_string(), "test1".to_string()).unwrap();
        store.create_session("sess2".to_string(), "bin2".to_string(), "test2".to_string()).unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_delete_session() {
        let store = create_test_store();
        store.create_session("sess1".to_string(), "bin1".to_string(), "test".to_string()).unwrap();

        store.delete_session("sess1").unwrap();
        assert!(store.get_session("sess1").unwrap().is_none());
    }

    #[test]
    fn test_renamed_symbols() {
        let store = create_test_store();
        store.create_session("sess1".to_string(), "bin1".to_string(), "test".to_string()).unwrap();
        store.save_renamed_symbol("sess1", "sub_401000", "main").unwrap();
        store.save_renamed_symbol("sess1", "sub_402000", "helper").unwrap();

        let symbols = store.get_renamed_symbols("sess1").unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols.get("sub_401000"), Some(&"main".to_string()));
    }
}
