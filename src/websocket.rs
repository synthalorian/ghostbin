use axum::extract::ws::{WebSocket, Message};
use serde_json;
use tracing::{info, error};

use crate::AppState;

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "subscribe")]
    Subscribe { address: String },
    #[serde(rename = "cursor_move")]
    CursorMove { address: String, user: String },
    #[serde(rename = "annotation_add")]
    AnnotationAdd { address: String, text: String, author: String },
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "type")]
enum ServerMessage {
    #[serde(rename = "cursor_update")]
    CursorUpdate { address: String, user: String },
    #[serde(rename = "annotation_update")]
    AnnotationUpdate { address: String, annotations: Vec<crate::annotations::Annotation> },
    #[serde(rename = "error")]
    Error { message: String },
}

pub async fn handle_socket(mut socket: WebSocket, state: AppState) {
    info!("WebSocket connection established");

    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(client_msg) => {
                        let response = handle_client_message(client_msg, &state).await;
                        if let Ok(json) = serde_json::to_string(&response) {
                            if let Err(e) = socket.send(Message::Text(json)).await {
                                error!("Failed to send WebSocket message: {}", e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to parse client message: {}", e);
                        let error_msg = ServerMessage::Error {
                            message: format!("Invalid message format: {}", e),
                        };
                        if let Ok(json) = serde_json::to_string(&error_msg) {
                            let _ = socket.send(Message::Text(json)).await;
                        }
                    }
                }
            }
            Ok(Message::Close(_)) => {
                info!("WebSocket connection closed");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }
}

async fn handle_client_message(msg: ClientMessage, state: &AppState) -> ServerMessage {
    match msg {
        ClientMessage::Subscribe { address } => {
            let store = state.annotations.read().await;
            match store.get(&address) {
                Some(annotations) => ServerMessage::AnnotationUpdate {
                    address,
                    annotations: annotations.clone(),
                },
                None => ServerMessage::AnnotationUpdate {
                    address,
                    annotations: Vec::new(),
                },
            }
        }
        ClientMessage::CursorMove { address, user } => {
            ServerMessage::CursorUpdate { address, user }
        }
        ClientMessage::AnnotationAdd { address, text, author } => {
            let mut store = state.annotations.write().await;
            if let Err(e) = store.add(&address, text, author.clone()).await {
                return ServerMessage::Error {
                    message: format!("Failed to add annotation: {}", e),
                };
            }

            match store.get(&address) {
                Some(annotations) => ServerMessage::AnnotationUpdate {
                    address,
                    annotations: annotations.clone(),
                },
                None => ServerMessage::Error {
                    message: "Annotation added but not found".to_string(),
                },
            }
        }
    }
}
