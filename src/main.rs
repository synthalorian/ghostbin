use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let llm_url = std::env::var("GHOSTBIN_LLM_URL")
        .unwrap_or_else(|_| "http://localhost:8080".to_string());
    let llm_model =
        std::env::var("GHOSTBIN_LLM_MODEL").unwrap_or_else(|_| "default".to_string());
    let bind =
        std::env::var("GHOSTBIN_BIND").unwrap_or_else(|_| "127.0.0.1:8081".to_string());

    let state = ghostbin::AppState::new(llm_url, llm_model)?;
    let app = ghostbin::build_app(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!("👻 GhostBin v1.0.0 listening on {}", listener.local_addr()?);
    info!("   LLM integration is optional; core disasm/decompile works fully offline.");

    axum::serve(listener, app).await?;
    Ok(())
}
