use axum::{
    extract::{Path, State, Json, WebSocketUpgrade, Query},
    http::StatusCode,
    middleware,
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
mod bookmarks;
mod config;
mod decompiler;
mod diff;
mod disasm;
mod entropy;
mod export;
mod graph;
mod idb;
mod llm;
mod marketplace;
mod openapi;
mod plugin;
mod security;
mod session;
mod strings;
mod websocket;
mod yara;

use binary::BinaryAnalyzer;
use annotations::AnnotationStore;
use bookmarks::BookmarkStore;
use config::Config;
use llm::LlmClient;
use marketplace::PluginMarketplace;
use plugin::PluginManager;
use security::{RateLimiter, RateLimitConfig};
use session::SessionStore;
use websocket::WsHub;

#[derive(Clone)]
struct AppState {
    analyzer: Arc<RwLock<BinaryAnalyzer>>,
    annotations: Arc<RwLock<AnnotationStore>>,
    bookmarks: Arc<RwLock<BookmarkStore>>,
    sessions: Arc<RwLock<SessionStore>>,
    llm: Arc<LlmClient>,
    hub: Arc<WsHub>,
    plugins: Arc<PluginManager>,
    marketplace: Arc<PluginMarketplace>,
    rate_limiter: Arc<RateLimiter>,
    config: Arc<Config>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = match Config::load("ghostbin.toml") {
        Ok(cfg) => {
            info!("Loaded configuration from ghostbin.toml");
            cfg
        }
        Err(e) => {
            info!("Using default configuration (failed to load ghostbin.toml: {})", e);
            Config::default()
        }
    };

    let llm = Arc::new(LlmClient::new(
        config.llm.base_url.clone(),
        config.llm.model.clone(),
    ));

    let sessions = Arc::new(RwLock::new(
        SessionStore::new("ghostbin_sessions.db")
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to open session database: {}. Using in-memory store.", e);
                SessionStore::new(":memory:").expect("Failed to create in-memory session store")
            })
    ));

    let rate_limiter = RateLimiter::new(RateLimitConfig {
        max_requests: config.analysis.max_report_functions as u32 * 10,
        window_seconds: 60,
        ..Default::default()
    });

    let state = AppState {
        analyzer: Arc::new(RwLock::new(BinaryAnalyzer::new())),
        annotations: Arc::new(RwLock::new(AnnotationStore::new()?)),
        bookmarks: Arc::new(RwLock::new(BookmarkStore::new())),
        sessions,
        llm,
        hub: Arc::new(WsHub::new()),
        plugins: Arc::new(PluginManager::new()),
        marketplace: PluginMarketplace::new(),
        rate_limiter,
        config: Arc::new(config.clone()),
    };

    let app = Router::new()
        .route("/", get(serve_ui))
        .route("/api/status", get(get_status))
        .route("/api/config", get(get_config))
        .route("/api/openapi.json", get(get_openapi_spec))
        .route("/api/docs", get(get_api_docs))
        .route("/api/rate-limit", get(get_rate_limit_status))
        .route("/api/binary/load", post(load_binary))
        .route("/api/binary/batch", post(batch_load))
        .route("/api/binary/:id/functions", get(list_functions))
        .route("/api/binary/:id/sections", get(list_sections))
        .route("/api/binary/:id/symbols", get(list_symbols))
        .route("/api/binary/:id/relocations", get(list_relocations))
        .route("/api/binary/:id/imports", get(list_imports))
        .route("/api/binary/:id/exports", get(list_exports))
        .route("/api/binary/:id/resources", get(list_resources))
        .route("/api/binary/:id/strings", get(list_strings))
        .route("/api/binary/:id/function/:addr/disasm", get(get_disassembly))
        .route("/api/binary/:id/function/:addr/decompile", post(decompile_function))
        .route("/api/binary/:id/function/:addr/analyze", post(ai_analyze))
        .route("/api/graph/:id/cfg", get(get_cfg))
        .route("/api/graph/:id/callgraph", get(get_call_graph))
        .route("/api/graph/:id/interactive", post(update_interactive_graph))
        .route("/api/import/database", post(import_database_handler))
        .route("/api/import/:id/apply", post(apply_import_handler))
        .route("/api/binary/:id/entropy", get(get_entropy))
        .route("/api/binary/:id/signatures", get(get_signatures))
        .route("/api/binary/diff", post(diff_binaries))
        .route("/api/binary/:id/patches", get(get_patches))
        .route("/api/binary/:id/symbols/rename", post(rename_symbol))
        .route("/api/annotations/:addr", get(get_annotation).post(add_annotation))
        .route("/api/annotations/:addr/threads", get(get_annotation_threads))
        .route("/api/bookmarks", get(list_bookmarks).post(create_bookmark))
        .route("/api/bookmarks/:id", delete(delete_bookmark))
        .route("/api/bookmarks/:id/rename", post(rename_bookmark))
        .route("/api/sessions", get(list_sessions).post(create_session))
        .route("/api/sessions/:id", get(get_session).delete(delete_session))
        .route("/api/sessions/:id/state", post(update_session_state))
        .route("/api/export/:id/markdown", post(export_markdown))
        .route("/api/export/:id/pdf", post(export_pdf))
        .route("/api/plugins/load", post(load_plugin))
        .route("/api/plugins/list", get(list_plugins))
        .route("/api/plugins/:name/analyze", post(run_plugin))
        .route("/api/plugins/:name", delete(unload_plugin))
        .route("/api/marketplace/plugins", get(list_marketplace_plugins))
        .route("/api/marketplace/plugins/:name", get(get_marketplace_plugin))
        .route("/api/marketplace/install", post(install_marketplace_plugin))
        .route("/api/marketplace/categories", get(get_marketplace_categories))
        .route("/api/marketplace/tags", get(get_marketplace_tags))
        .route("/api/marketplace/featured", get(get_featured_plugins))
        .route("/api/marketplace/recent", get(get_recent_plugins))
        .route("/api/marketplace/stats", get(get_marketplace_stats))
        .route("/ws", get(websocket_handler))
        .layer(middleware::from_fn(security::security_headers_middleware))
        .layer(middleware::from_fn(security::request_size_limit_middleware))
        .with_state(state);

    let bind_addr = format!("{}:{}", config.bind_addr, config.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("GhostBin v1.0.0 listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn serve_ui() -> impl IntoResponse {
    axum::response::Html(include_str!("../static/index.html"))
}

async fn get_status(State(state): State<AppState>) -> impl IntoResponse {
    let analyzer = state.analyzer.read().await;
    let binary_count = analyzer.binary_count();
    let annotations = state.annotations.read().await;
    let annotation_count = annotations.annotation_count();
    let bookmarks = state.bookmarks.read().await;
    let session_count = match state.sessions.read().await.list_sessions() {
        Ok(sessions) => sessions.len(),
        Err(_) => 0,
    };

    Json(StatusResponse {
        version: "1.0.0".to_string(),
        status: "healthy".to_string(),
        binaries_loaded: binary_count,
        annotation_count,
        bookmark_count: bookmarks.count(),
        session_count,
        plugins_loaded: state.plugins.list_plugins().len(),
        websocket_users: state.hub.user_count().await,
    })
}

async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    Json(ConfigResponse {
        bind_addr: state.config.bind_addr.clone(),
        port: state.config.port,
        llm_provider: state.config.llm.provider.clone(),
        llm_model: state.config.llm.model.clone(),
        analysis: state.config.analysis.clone(),
    })
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

async fn batch_load(
    State(state): State<AppState>,
    Json(req): Json<BatchLoadRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut analyzer = state.analyzer.write().await;
    let mut results = Vec::new();

    for item in req.binaries {
        match analyzer.load(&item.path).await {
            Ok(id) => results.push(BinaryResponse { id, name: item.name }),
            Err(e) => {
                error!("Failed to load binary {}: {}", item.path, e);
            }
        }
    }

    Ok(Json(BatchLoadResponse { results }))
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

async fn list_strings(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<StringQueryParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    let min_len = params.min_len.unwrap_or(state.config.analysis.min_string_length);

    match analyzer.get_strings(&id, min_len, params.pattern.as_deref()) {
        Ok(strings) => Ok(Json(strings)),
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

async fn get_call_graph(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_call_graph(&id) {
        Ok(graph) => Ok(Json(graph)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn update_interactive_graph(
    State(_state): State<AppState>,
    Json(req): Json<InteractiveGraphRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut state = graph::InteractiveGraphState::default();

    if let Some(dx) = req.pan_dx {
        if let Some(dy) = req.pan_dy {
            state.pan(dx, dy);
        }
    }

    if let Some(zoom) = req.zoom {
        state.zoom = zoom;
    }

    if let Some(node) = req.select_node {
        state.select_node(node);
    }

    Ok(Json(state))
}

async fn get_entropy(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.get_entropy(&id) {
        Ok(entropy) => Ok(Json(entropy)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn get_signatures(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;
    match analyzer.scan_signatures(&id) {
        Ok(matches) => Ok(Json(matches)),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn diff_binaries(
    State(state): State<AppState>,
    Json(req): Json<DiffRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;

    let binary_a = match analyzer.get_binary(&req.binary_a_id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let binary_b = match analyzer.get_binary(&req.binary_b_id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let old_funcs: Vec<(u64, String, u64)> = binary_a.functions.iter()
        .map(|f| (f.address, f.name.clone(), f.size))
        .collect();
    let new_funcs: Vec<(u64, String, u64)> = binary_b.functions.iter()
        .map(|f| (f.address, f.name.clone(), f.size))
        .collect();

    let (added_funcs, removed_funcs, modified_funcs) = diff::diff_functions(&old_funcs, &new_funcs);

    let old_strings: Vec<(u64, String)> = match analyzer.get_strings(&req.binary_a_id, 4, None) {
        Ok(strings) => strings.into_iter().map(|s| (s.address, s.content)).collect(),
        Err(_) => Vec::new(),
    };
    let new_strings: Vec<(u64, String)> = match analyzer.get_strings(&req.binary_b_id, 4, None) {
        Ok(strings) => strings.into_iter().map(|s| (s.address, s.content)).collect(),
        Err(_) => Vec::new(),
    };

    let (added_strings, removed_strings) = diff::diff_strings(&old_strings, &new_strings);

    let old_sections: Vec<(String, u64, u64)> = binary_a.sections.iter()
        .map(|s| (s.name.clone(), s.address, s.size))
        .collect();
    let new_sections: Vec<(String, u64, u64)> = binary_b.sections.iter()
        .map(|s| (s.name.clone(), s.address, s.size))
        .collect();

    let section_changes = diff::diff_sections(&old_sections, &new_sections);
    let similarity = diff::calculate_similarity(&old_funcs, &new_funcs);

    let result = diff::BinaryDiff {
        added_functions: added_funcs,
        removed_functions: removed_funcs,
        modified_functions: modified_funcs,
        added_strings,
        removed_strings,
        section_changes,
        similarity_score: similarity,
    };

    Ok(Json(result))
}

async fn get_patches(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<PatchQueryParams>,
) -> Result<impl IntoResponse, StatusCode> {
    let analyzer = state.analyzer.read().await;

    let binary = match analyzer.get_binary(&id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let compare_id = params.compare_with.ok_or(StatusCode::BAD_REQUEST)?;
    let compare_binary = match analyzer.get_binary(&compare_id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let patches = diff::detect_patches(&binary.data, &compare_binary.data);
    Ok(Json(patches))
}

async fn rename_symbol(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameSymbolRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut analyzer = state.analyzer.write().await;
    match analyzer.rename_symbol(&id, &req.old_name, &req.new_name) {
        Ok(()) => Ok(Json(RenameResponse { success: true, new_name: req.new_name })),
        Err(e) => {
            error!("Failed to rename symbol: {}", e);
            Err(StatusCode::NOT_FOUND)
        }
    }
}

async fn list_bookmarks(State(state): State<AppState>) -> impl IntoResponse {
    let bookmarks = state.bookmarks.read().await;
    Json(bookmarks.list_all().to_vec())
}

async fn create_bookmark(
    State(state): State<AppState>,
    Json(req): Json<CreateBookmarkRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut bookmarks = state.bookmarks.write().await;
    let bookmark = bookmarks::Bookmark {
        id: uuid::Uuid::new_v4().to_string(),
        binary_id: req.binary_id,
        address: req.address,
        name: req.name,
        description: req.description,
        category: req.category,
        color: req.color,
    };

    match bookmarks.add(bookmark.clone()) {
        Ok(()) => Ok((StatusCode::CREATED, Json(bookmark))),
        Err(_) => Err(StatusCode::CONFLICT),
    }
}

async fn delete_bookmark(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let mut bookmarks = state.bookmarks.write().await;
    match bookmarks.remove(&id) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn rename_bookmark(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<RenameBookmarkRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let mut bookmarks = state.bookmarks.write().await;
    match bookmarks.update_name(&id, req.name) {
        Ok(()) => Ok(StatusCode::OK),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn list_sessions(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.sessions.read().await;
    match sessions.list_sessions() {
        Ok(sessions) => Json(sessions),
        Err(_) => Json(Vec::<session::AnalysisSession>::new()),
    }
}

async fn create_session(
    State(state): State<AppState>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    let id = uuid::Uuid::new_v4().to_string();

    match sessions.create_session(id, req.binary_id, req.binary_name) {
        Ok(session) => Ok((StatusCode::CREATED, Json(session))),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;
    match sessions.get_session(&id) {
        Ok(Some(session)) => Ok(Json(session)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let sessions = state.sessions.read().await;
    match sessions.delete_session(&id) {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

async fn update_session_state(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSessionStateRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let sessions = state.sessions.read().await;

    let mut session = match sessions.get_session(&id) {
        Ok(Some(s)) => s,
        Ok(None) => return Err(StatusCode::NOT_FOUND),
        Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR),
    };

    if let Some(symbols) = req.renamed_symbols {
        session.state.renamed_symbols = symbols;
    }

    if let Some(viewport) = req.graph_viewport {
        session.state.graph_viewport = Some(viewport);
    }

    match sessions.update_session_state(&id, &session.state) {
        Ok(()) => Ok(Json(session)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
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

    let max_funcs = state.config.analysis.max_report_functions;
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
        functions: binary.functions[..binary.functions.len().min(max_funcs)].to_vec(),
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

    let max_funcs = state.config.analysis.max_report_functions;
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
        functions: binary.functions[..binary.functions.len().min(max_funcs)].to_vec(),
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

async fn import_database_handler(
    Json(req): Json<idb::ImportRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    match idb::import_database(&req.database_path) {
        Ok(import) => Ok(Json(import)),
        Err(e) => {
            error!("Failed to import database: {}", e);
            Err(StatusCode::UNPROCESSABLE_ENTITY)
        }
    }
}

async fn apply_import_handler(
    Path(id): Path<String>,
    State(state): State<AppState>,
    Json(req): Json<idb::ImportRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    let import = match idb::import_database(&req.database_path) {
        Ok(import) => import,
        Err(e) => {
            error!("Failed to import database: {}", e);
            return Err(StatusCode::UNPROCESSABLE_ENTITY);
        }
    };

    let mut analyzer = state.analyzer.write().await;
    let binary = match analyzer.get_binary_mut(&id) {
        Ok(b) => b,
        Err(_) => return Err(StatusCode::NOT_FOUND),
    };

    let mut annotations = state.annotations.write().await;
    match idb::apply_import(&import, binary, &mut annotations) {
        Ok(summary) => Ok(Json(summary)),
        Err(e) => {
            error!("Failed to apply import: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
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

#[derive(Deserialize)]
struct BatchBinaryItem {
    path: String,
    name: String,
}

#[derive(Deserialize)]
struct BatchLoadRequest {
    binaries: Vec<BatchBinaryItem>,
}

#[derive(Serialize)]
struct BatchLoadResponse {
    results: Vec<BinaryResponse>,
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
struct InteractiveGraphRequest {
    pan_dx: Option<f64>,
    pan_dy: Option<f64>,
    zoom: Option<f64>,
    select_node: Option<String>,
}

#[derive(Deserialize)]
struct DiffRequest {
    binary_a_id: String,
    binary_b_id: String,
}

#[derive(Deserialize)]
struct PatchQueryParams {
    compare_with: Option<String>,
}

#[derive(Deserialize)]
struct RenameSymbolRequest {
    old_name: String,
    new_name: String,
}

#[derive(Serialize)]
struct RenameResponse {
    success: bool,
    new_name: String,
}

#[derive(Deserialize)]
struct CreateBookmarkRequest {
    binary_id: String,
    address: u64,
    name: String,
    description: String,
    category: bookmarks::BookmarkCategory,
    color: String,
}

#[derive(Deserialize)]
struct RenameBookmarkRequest {
    name: String,
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    binary_id: String,
    binary_name: String,
}

#[derive(Deserialize)]
struct UpdateSessionStateRequest {
    renamed_symbols: Option<std::collections::HashMap<String, String>>,
    graph_viewport: Option<session::GraphViewport>,
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

#[derive(Serialize)]
struct StatusResponse {
    version: String,
    status: String,
    binaries_loaded: usize,
    annotation_count: usize,
    bookmark_count: usize,
    session_count: usize,
    plugins_loaded: usize,
    websocket_users: usize,
}

#[derive(Serialize)]
struct ConfigResponse {
    bind_addr: String,
    port: u16,
    llm_provider: String,
    llm_model: String,
    analysis: config::AnalysisConfig,
}

#[derive(Deserialize)]
struct StringQueryParams {
    min_len: Option<usize>,
    pattern: Option<String>,
}

async fn get_openapi_spec() -> impl IntoResponse {
    Json(openapi::get_openapi_json())
}

async fn get_api_docs() -> impl IntoResponse {
    axum::response::Html(r#"
<!DOCTYPE html>
<html>
<head>
    <title>GhostBin API Documentation</title>
    <meta charset="utf-8"/>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/openapi.json',
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis],
            layout: "BaseLayout"
        });
    </script>
</body>
</html>
"#.to_string())
}

async fn get_rate_limit_status(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.rate_limiter.get_status("127.0.0.1"))
}

async fn list_marketplace_plugins(
    State(state): State<AppState>,
    Json(query): Json<marketplace::PluginSearchQuery>,
) -> impl IntoResponse {
    Json(state.marketplace.list_plugins(Some(query)))
}

async fn get_marketplace_plugin(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.marketplace.get_plugin(&name) {
        Some(plugin) => Ok(Json(plugin)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn install_marketplace_plugin(
    State(state): State<AppState>,
    Json(req): Json<marketplace::InstallRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    match state.marketplace.install_plugin(&req.plugin_name, req.version.as_deref()) {
        Ok(result) => Ok(Json(result)),
        Err(e) => {
            error!("Failed to install plugin: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_marketplace_categories(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.marketplace.get_categories())
}

async fn get_marketplace_tags(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.marketplace.get_tags(20))
}

async fn get_featured_plugins(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.marketplace.get_featured_plugins(5))
}

async fn get_recent_plugins(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.marketplace.get_recently_updated(5))
}

async fn get_marketplace_stats(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.marketplace.get_stats())
}
