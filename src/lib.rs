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
use tracing::error;

pub mod binary;
pub mod disasm;
pub mod decompiler;
pub mod graph;
pub mod annotations;
pub mod llm;
pub mod websocket;

use binary::BinaryAnalyzer;
use annotations::AnnotationStore;
use llm::LlmClient;

#[derive(Clone)]
pub struct AppState {
    pub analyzer: Arc<RwLock<BinaryAnalyzer>>,
    pub annotations: Arc<RwLock<AnnotationStore>>,
    pub llm: Arc<LlmClient>,
}

impl AppState {
    pub fn new(llm_base_url: String, llm_model: String) -> anyhow::Result<Self> {
        Ok(AppState {
            analyzer: Arc::new(RwLock::new(BinaryAnalyzer::new())),
            annotations: Arc::new(RwLock::new(AnnotationStore::new()?)),
            llm: Arc::new(LlmClient::new(llm_base_url, llm_model)),
        })
    }
}

/// Build the Axum router. Exposed so tests can drive the API in-process.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_ui))
        .route("/api/binary/load", post(load_binary))
        .route("/api/binary/:id", get(binary_info))
        .route("/api/binary/:id/functions", get(list_functions))
        .route("/api/binary/:id/sections", get(list_sections))
        .route("/api/binary/:id/symbols", get(list_symbols))
        .route("/api/binary/:id/relocations", get(list_relocations))
        .route("/api/binary/:id/function/:addr/disasm", get(get_disassembly))
        .route("/api/binary/:id/function/:addr/decompile", post(decompile_function))
        .route("/api/binary/:id/function/:addr/analyze", post(ai_analyze))
        .route("/api/annotations/:addr", get(get_annotation).post(add_annotation))
        .route("/api/graph/:id/cfg", get(get_cfg))
        .route("/api/llm/status", get(llm_status))
        .route("/ws", get(websocket_handler))
        .with_state(state)
}

/// JSON error body returned by all API handlers.
#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

impl ApiError {
    fn new(msg: impl std::fmt::Display) -> Self {
        ApiError {
            error: msg.to_string(),
        }
    }
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError::new(msg)))
}

async fn serve_ui() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/index.html"))
}

async fn load_binary(
    State(state): State<AppState>,
    Json(req): Json<LoadBinaryRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let mut analyzer = state.analyzer.write().await;
    match analyzer.load(&req.path).await {
        Ok(id) => Ok(Json(BinaryResponse { id, name: req.name })),
        Err(e) => {
            error!("Failed to load binary: {}", e);
            Err(err(
                StatusCode::BAD_REQUEST,
                format!("failed to load binary: {}", e),
            ))
        }
    }
}

async fn binary_info(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_info(&id) {
        Ok(info) => Ok(Json(info)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn list_functions(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_functions(&id) {
        Ok(functions) => Ok(Json(functions)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn list_sections(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_sections(&id) {
        Ok(sections) => Ok(Json(sections)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn list_symbols(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_symbols(&id) {
        Ok(symbols) => Ok(Json(symbols)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn list_relocations(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_relocations(&id) {
        Ok(relocations) => Ok(Json(relocations)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn get_disassembly(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.disassemble_function(&id, &addr) {
        Ok(instructions) => Ok(Json(instructions)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn decompile_function(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.decompile_function(&id, &addr) {
        Ok(pseudo_code) => Ok(Json(DecompileResponse { pseudo_code })),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
    }
}

async fn ai_analyze(
    State(state): State<AppState>,
    Path((id, addr)): Path<(String, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    let disasm = match analyzer.disassemble_function(&id, &addr) {
        Ok(d) => d,
        Err(e) => return Err(err(StatusCode::NOT_FOUND, e)),
    };
    drop(analyzer);

    let llm = &state.llm;
    match llm.analyze_function(&disasm).await {
        Ok(analysis) => Ok(Json(AiAnalysisResponse {
            analysis,
            llm_available: true,
        })),
        Err(e) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "local LLM unavailable ({}). Disassembly and decompilation still work without it.",
                e
            ),
        )),
    }
}

async fn llm_status(State(state): State<AppState>) -> impl IntoResponse {
    let available = state.llm.check_available().await;
    Json(LlmStatusResponse {
        available,
        base_url: state.llm.base_url().to_string(),
        model: state.llm.model().to_string(),
    })
}

async fn get_annotation(
    State(state): State<AppState>,
    Path(addr): Path<String>,
) -> impl IntoResponse {
    let store = state.annotations.read().await;
    let annotations = store.get(&addr).cloned().unwrap_or_default();
    Json(annotations)
}

async fn add_annotation(
    State(state): State<AppState>,
    Path(addr): Path<String>,
    Json(req): Json<AnnotationRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let mut store = state.annotations.write().await;
    match store.add(&addr, req.text, req.author).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

async fn get_cfg(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ApiError>)> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_cfg(&id) {
        Ok(cfg) => Ok(Json(cfg)),
        Err(e) => Err(err(StatusCode::NOT_FOUND, e)),
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
pub struct LoadBinaryRequest {
    pub path: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct BinaryResponse {
    pub id: String,
    pub name: String,
}

#[derive(Serialize)]
pub struct DecompileResponse {
    pub pseudo_code: String,
}

#[derive(Serialize)]
pub struct AiAnalysisResponse {
    pub analysis: String,
    pub llm_available: bool,
}

#[derive(Serialize)]
pub struct LlmStatusResponse {
    pub available: bool,
    pub base_url: String,
    pub model: String,
}

#[derive(Deserialize)]
pub struct AnnotationRequest {
    pub text: String,
    pub author: String,
}
