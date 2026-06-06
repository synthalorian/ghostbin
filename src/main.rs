use axum::{
    extract::{Path, State, Json, WebSocketUpgrade},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info};

mod annotations;
mod binary;
mod decompiler;
mod disasm;
mod export;
mod graph;
mod llm;
mod plugin;
mod websocket;

use binary::BinaryAnalyzer;
use annotations::AnnotationStore;
use llm::LlmClient;
use plugin::PluginManager;
use websocket::WsHub;

#[derive(Clone)]
struct AppState {
    analyzer: Arc<RwLock<BinaryAnalyzer>>,
    annotations: Arc<RwLock<AnnotationStore>>,
    llm: Arc<LlmClient>,
    hub: Arc<WsHub>,
    plugins: Arc<PluginManager>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let state = AppState {
        analyzer: Arc::new(RwLock::new(BinaryAnalyzer::new())),
        annotations: Arc::new(RwLock::new(AnnotationStore::new()?)),
        llm: Arc::new(LlmClient::new(
            "http://localhost:8080".to_string(),
            "default".to_string(),
        )),
        hub: Arc::new(WsHub::new()),
        plugins: Arc::new(PluginManager::new()),
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
        .route("/api/binary/:id/resources", get(list_resources))
        .route("/api/binary/:id/function/:addr/disasm", get(get_disassembly))
        .route("/api/binary/:id/function/:addr/decompile", post(decompile_function))
        .route("/api/binary/:id/function/:addr/analyze", post(ai_analyze))
        .route("/api/annotations/:addr", get(get_annotation).post(add_annotation))
        .route("/api/annotations/:addr/threads", get(get_annotation_threads))
        .route("/api/export/:id/markdown", post(export_markdown))
        .route("/api/export/:id/pdf", post(export_pdf))
        .route("/api/plugins/load", post(load_plugin))
        .route("/api/plugins/list", get(list_plugins))
        .route("/api/plugins/:name/analyze", post(run_plugin))
        .route("/api/plugins/:name", delete(unload_plugin))
        .route("/api/graph/:id/cfg", get(get_cfg))
        .route("/ws", get(websocket_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    info!("GhostBin v0.3.0 listening on {}", listener.local_addr()?);

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

async fn list_resources(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_resources(&id) {
        Ok(resources) => Ok(Json(resources)),
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
    match store.add(&addr, req.text, req.author, req.parent_id).await {
        Ok(_) => Ok(StatusCode::CREATED),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_annotation_threads(
    State(state): State<AppState>,
    Path(addr): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let store = state.annotations.read().await;
    let threads = store.get_threads(&addr);
    Ok(Json(threads))
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

async fn export_markdown(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let annotations = state.annotations.read().await;

    let binary = match analyzer.get_binary(&id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let all_annotations: Vec<_> = binary
        .functions
        .iter()
        .flat_map(|f| {
            let addr = format!("0x{:x}", f.address);
            annotations.get_threads(&addr)
        })
        .collect();

    let report = export::AnalysisReport {
        binary_name: binary.name.clone(),
        binary_id: id.clone(),
        architecture: binary.architecture.as_str().to_string(),
        entry_point: format!("0x{:x}", binary.entry_point),
        functions: binary.functions.clone(),
        sections: binary.sections.clone(),
        symbols: binary.symbols.clone(),
        imports: binary.imports.clone(),
        exports: binary.exports.clone(),
        annotations: all_annotations,
        analysis_text: None,
    };

    let markdown = export::export_markdown(&report);
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/markdown; charset=utf-8",
        )],
        markdown,
    ))
}

async fn export_pdf(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let annotations = state.annotations.read().await;

    let binary = match analyzer.get_binary(&id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let all_annotations: Vec<_> = binary
        .functions
        .iter()
        .flat_map(|f| {
            let addr = format!("0x{:x}", f.address);
            annotations.get_threads(&addr)
        })
        .collect();

    let report = export::AnalysisReport {
        binary_name: binary.name.clone(),
        binary_id: id.clone(),
        architecture: binary.architecture.as_str().to_string(),
        entry_point: format!("0x{:x}", binary.entry_point),
        functions: binary.functions.clone(),
        sections: binary.sections.clone(),
        symbols: binary.symbols.clone(),
        imports: binary.imports.clone(),
        exports: binary.exports.clone(),
        annotations: all_annotations,
        analysis_text: None,
    };

    match export::export_pdf(&report) {
        Ok(pdf_bytes) => {
            let disposition = format!("attachment; filename=\"{}_report.pdf\"", binary.name);
            let mut response = axum::response::Response::new(axum::body::Body::from(pdf_bytes));
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                "application/pdf".parse().unwrap(),
            );
            response.headers_mut().insert(
                axum::http::header::CONTENT_DISPOSITION,
                disposition.parse().unwrap(),
            );
            Ok(response)
        }
        Err(e) => {
            error!("PDF export failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn load_plugin(
    State(state): State<AppState>,
    Json(req): Json<LoadPluginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.plugins.load_plugin(&req.path) {
        Ok(name) => Ok(Json(PluginResponse { name, version: "unknown".to_string() })),
        Err(e) => {
            error!("Failed to load plugin: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn list_plugins(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let plugins = state.plugins.list_plugins();
    Json(plugins)
}

async fn run_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(req): Json<RunPluginRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let binary = match analyzer.get_binary(&req.binary_id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    match state.plugins.analyze(&name, &binary.data, &req.function_name) {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            error!("Plugin analysis failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn unload_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    match state.plugins.unload_plugin(&name) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
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
    parent_id: Option<String>,
}

#[derive(Deserialize)]
struct LoadPluginRequest {
    path: String,
}

#[derive(Serialize)]
struct PluginResponse {
    name: String,
    version: String,
}

#[derive(Deserialize)]
struct RunPluginRequest {
    binary_id: String,
    function_name: String,
}
