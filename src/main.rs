use axum::{
    routing::{get, post},
    Router,
    extract::{State, Json, Path, WebSocketUpgrade},
    response::IntoResponse,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

mod binary;
mod disasm;
mod decompiler;
mod graph;
mod annotations;
mod llm;
mod websocket;

use binary::BinaryAnalyzer;
use annotations::AnnotationStore;
use llm::LlmClient;

#[derive(Clone)]
struct AppState {
    analyzer: Arc<RwLock<BinaryAnalyzer>>,
    annotations: Arc<RwLock<AnnotationStore>>,
    llm: Arc<LlmClient>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let state = AppState {
        analyzer: Arc::new(RwLock::new(BinaryAnalyzer::new())),
        annotations: Arc::new(RwLock::new(AnnotationStore::new()?)),
        llm: Arc::new(LlmClient::new("http://localhost:8080".to_string(), "default".to_string())),
    };

    let app = Router::new()
        .route("/", get(serve_ui))
        .route("/api/binary/load", post(load_binary))
        .route("/api/binary/:id/functions", get(list_functions))
        .route("/api/binary/:id/sections", get(list_sections))
        .route("/api/binary/:id/symbols", get(list_symbols))
        .route("/api/binary/:id/relocations", get(list_relocations))
        .route("/api/binary/:id/imports", get(list_imports))
        .route("/api/binary/:id/exports", get(list_exports))
        .route("/api/binary/:id/function/:addr/disasm", get(get_disassembly))
        .route("/api/binary/:id/function/:addr/decompile", post(decompile_function))
        .route("/api/binary/:id/function/:addr/analyze", post(ai_analyze))
        .route("/api/annotations/:addr", get(get_annotation).post(add_annotation))
        .route("/api/graph/:id/cfg", get(get_cfg))
        .route("/ws", get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    info!("👻 GhostBin listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_ui() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/index.html"))
}

async fn load_binary(
    State(state): State<AppState>,
    Json(req): Json<LoadBinaryRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut analyzer = state.analyzer.write().await;
    match analyzer.load(&req.path).await {
        Ok(id) => Ok(Json(BinaryResponse { id, name: req.name })),
        Err(e) => {
            error!("Failed to load binary: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_functions(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_functions(&id) {
        Ok(functions) => Ok(Json(functions)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_sections(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_sections(&id) {
        Ok(sections) => Ok(Json(sections)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_symbols(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_symbols(&id) {
        Ok(symbols) => Ok(Json(symbols)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_relocations(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_relocations(&id) {
        Ok(relocations) => Ok(Json(relocations)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_imports(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_imports(&id) {
        Ok(imports) => Ok(Json(imports)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_exports(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_exports(&id) {
        Ok(exports) => Ok(Json(exports)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_disassembly(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.disassemble_function(&id, &addr) {
        Ok(instructions) => Ok(Json(instructions)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn decompile_function(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.decompile_function(&id, &addr) {
        Ok(pseudo_code) => Ok(Json(DecompileResponse { pseudo_code })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn ai_analyze(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let disasm = match analyzer.disassemble_function(&id, &addr) {
        Ok(d) => d,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let llm = &state.llm;
    match llm.analyze_function(&disasm).await {
        Ok(analysis) => Ok(Json(AiAnalysisResponse { analysis })),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_annotation(
    State(state): State<AppState>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let store = state.annotations.read().await;
    match store.get(&addr) {
        Some(ann) => Ok(Json(ann.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn add_annotation(
    State(state): State<AppState>,
    Path(addr): Path<String>,
    Json(req): Json<AnnotationRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut store = state.annotations.write().await;
    match store.add(&addr, req.text, req.author).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_cfg(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_cfg(&id) {
        Ok(cfg) => Ok(Json(cfg)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| websocket::handle_socket(socket, state))
}

// Request/Response types
#[derive(Deserialize)]
struct LoadBinaryRequest {
    path: String,
    name: String,
}

#[derive(Serialize)]
struct BinaryResponse {
    id: String,
    name: String,
}

#[derive(Serialize)]
struct DecompileResponse {
    pseudo_code: String,
}

#[derive(Serialize)]
struct AiAnalysisResponse {
    analysis: String,
}

#[derive(Deserialize)]
struct AnnotationRequest {
    text: String,
    author: String,
}
