use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::{broadcast, RwLock};
use tracing::{error, info};

use crate::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "cursor_move")]
    CursorMove {
        user: String,
        address: String,
        line: usize,
        color: String,
    },
    #[serde(rename = "cursor_update")]
    CursorUpdate {
        user: String,
        address: String,
        line: usize,
        color: String,
    },
    #[serde(rename = "annotation_add")]
    AnnotationAdd {
        address: String,
        text: String,
        author: String,
        parent_id: Option<String>,
    },
    #[serde(rename = "annotation_update")]
    AnnotationUpdate {
        address: String,
        threads: Vec<crate::annotations::AnnotationThread>,
    },
    #[serde(rename = "subscribe")]
    Subscribe { address: String },
    #[serde(rename = "user_joined")]
    UserJoined { user: String, count: usize },
    #[serde(rename = "user_left")]
    UserLeft { user: String, count: usize },
    #[serde(rename = "error")]
    Error { message: String },
}

pub struct WsHub {
    tx: broadcast::Sender<WsMessage>,
    users: RwLock<HashMap<String, String>>,
}

impl WsHub {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(256);
        WsHub {
            tx,
            users: RwLock::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<WsMessage> {
        self.tx.subscribe()
    }

    pub fn broadcast(&self, msg: WsMessage) {
        let _ = self.tx.send(msg);
    }

    pub async fn add_user(&self, id: String, name: String) {
        let mut users = self.users.write().await;
        users.insert(id.clone(), name.clone());
        let count = users.len();
        drop(users);
        self.broadcast(WsMessage::UserJoined {
            user: name,
            count,
        });
    }

    pub async fn remove_user(&self, id: &str) {
        let mut users = self.users.write().await;
        if let Some(name) = users.remove(id) {
            let count = users.len();
            drop(users);
            self.broadcast(WsMessage::UserLeft {
                user: name,
                count,
            });
        }
    }

    #[allow(dead_code)]
    pub async fn user_count(&self) -> usize {
        self.users.read().await.len()
    }
}

pub async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let user_id = uuid::Uuid::new_v4().to_string();
    let mut rx = state.hub.subscribe();

    info!("WebSocket connection established: {}", user_id);

    loop {
        tokio::select! {
            Some(msg) = socket.recv() => {
                match msg {
                    Ok(Message::Text(text)) => {
                        match serde_json::from_str::<WsMessage>(&text) {
                            Ok(client_msg) => {
                                if let Err(e) = handle_client_message(
                                    &user_id,
                                    client_msg,
                                    &state,
                                    &mut socket,
                                ).await {
                                    let error_msg = WsMessage::Error {
                                        message: e.to_string(),
                                    };
                                    let _ = send_msg(&mut socket, &error_msg).await;
                                }
                            }
                            Err(e) => {
                                error!("Failed to parse client message: {}", e);
                                let error_msg = WsMessage::Error {
                                    message: format!("Invalid message format: {}", e),
                                };
                                let _ = send_msg(&mut socket, &error_msg).await;
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        info!("WebSocket connection closed: {}", user_id);
                        state.hub.remove_user(&user_id).await;
                        break;
                    }
                    Err(e) => {
                        error!("WebSocket error: {}", e);
                        state.hub.remove_user(&user_id).await;
                        break;
                    }
                    _ => {}
                }
            }
            Ok(msg) = rx.recv() => {
                if let Err(e) = send_msg(&mut socket, &msg).await {
                    error!("Failed to broadcast to {}: {}", user_id, e);
                    break;
                }
            }
        }
    }

    state.hub.remove_user(&user_id).await;
}

async fn send_msg(socket: &mut WebSocket, msg: &WsMessage) -> anyhow::Result<()> {
    let json = serde_json::to_string(msg)?;
    socket.send(Message::Text(json)).await?;
    Ok(())
}

async fn handle_client_message(
    user_id: &str,
    msg: WsMessage,
    state: &AppState,
    socket: &mut WebSocket,
) -> anyhow::Result<()> {
    match msg {
        WsMessage::Subscribe { address } => {
            let store = state.annotations.read().await;
            let threads = store.get_threads(&address);
            let update = WsMessage::AnnotationUpdate { address, threads };
            send_msg(socket, &update).await?;
        }
        WsMessage::CursorMove { user, address, line, color } => {
            state.hub.add_user(user_id.to_string(), user.clone()).await;
            let update = WsMessage::CursorUpdate {
                user,
                address,
                line,
                color,
            };
            state.hub.broadcast(update);
        }
        WsMessage::AnnotationAdd {
            address,
            text,
            author,
            parent_id,
        } => {
            let mut store = state.annotations.write().await;
            store.add(&address, text, author, parent_id).await?;
            let threads = store.get_threads(&address);
            let update = WsMessage::AnnotationUpdate { address, threads };
            state.hub.broadcast(update);
        }
        _ => {}
    }
    Ok(())
}
