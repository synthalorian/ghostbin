//! API smoke tests: drive the real Axum router in-process via tower oneshot.
//! No network access required; the LLM URL points at a dead port on purpose
//! to verify graceful degradation.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ghostbin::{build_app, AppState};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;
use tower::ServiceExt;

fn fixture_path() -> PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let src = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.c");
        let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ghostbin_sample_api");
        let status = Command::new("cc")
            .args(["-O0", "-g", "-o"])
            .arg(&out)
            .arg(src)
            .status()
            .expect("failed to invoke cc to build test fixture");
        assert!(status.success());
        out
    })
    .clone()
}

fn test_state() -> AppState {
    // Port 9 (discard) is effectively guaranteed closed locally.
    AppState::new("http://127.0.0.1:9".to_string(), "test-model".to_string()).unwrap()
}

async fn body_json(resp: axum::response::Response) -> (StatusCode, Value) {
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

async fn load_test_binary(app: &axum::Router) -> String {
    let req = Request::post("/api/binary/load")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "path": fixture_path().to_str().unwrap(),
                "name": "sample"
            })
            .to_string(),
        ))
        .unwrap();
    let (status, body) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "load failed: {}", body);
    body["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn test_api_full_analysis_loop() {
    let app = build_app(test_state());
    let id = load_test_binary(&app).await;

    // Binary info
    let req = Request::get(format!("/api/binary/{}", id))
        .body(Body::empty())
        .unwrap();
    let (status, info) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["format"], "ELF");
    assert_eq!(info["architecture"], "x86_64");
    assert!(info["num_functions"].as_u64().unwrap() > 0);

    // Sections
    let req = Request::get(format!("/api/binary/{}/sections", id))
        .body(Body::empty())
        .unwrap();
    let (status, sections) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(sections
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == ".text"));

    // Functions
    let req = Request::get(format!("/api/binary/{}/functions", id))
        .body(Body::empty())
        .unwrap();
    let (status, functions) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let functions = functions.as_array().unwrap();
    let add = functions
        .iter()
        .find(|f| f["name"] == "add")
        .expect("function 'add' missing from API");
    let addr = format!("0x{:x}", add["address"].as_u64().unwrap());

    // Disassembly
    let req = Request::get(format!("/api/binary/{}/function/{}/disasm", id, addr))
        .body(Body::empty())
        .unwrap();
    let (status, disasm) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let disasm = disasm.as_array().unwrap();
    assert!(!disasm.is_empty());
    assert!(disasm.iter().any(|i| i["mnemonic"] == "add"));
    assert!(disasm.iter().any(|i| i["mnemonic"] == "ret"));

    // Decompile
    let req = Request::post(format!("/api/binary/{}/function/{}/decompile", id, addr))
        .body(Body::empty())
        .unwrap();
    let (status, decompiled) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(decompiled["pseudo_code"]
        .as_str()
        .unwrap()
        .contains("Decompiled function"));

    // CFG
    let req = Request::get(format!("/api/graph/{}/cfg", id))
        .body(Body::empty())
        .unwrap();
    let (status, cfg) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(cfg["nodes"].is_array());
    assert!(cfg["edges"].is_array());
}

#[tokio::test]
async fn test_api_llm_graceful_degradation() {
    let app = build_app(test_state());
    let id = load_test_binary(&app).await;

    // Status endpoint reports the LLM as unavailable but the app keeps working
    let req = Request::get("/api/llm/status").body(Body::empty()).unwrap();
    let (status, llm) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(llm["available"], false);
    assert_eq!(llm["model"], "test-model");

    // Analyze returns 503 with a helpful JSON error instead of hanging or 500
    let req = Request::get(format!("/api/binary/{}/functions", id))
        .body(Body::empty())
        .unwrap();
    let (_, functions) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    let addr = format!(
        "0x{:x}",
        functions[0]["address"].as_u64().unwrap()
    );

    let req = Request::post(format!("/api/binary/{}/function/{}/analyze", id, addr))
        .body(Body::empty())
        .unwrap();
    let (status, err) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("LLM unavailable"));
}

#[tokio::test]
async fn test_api_annotations_roundtrip() {
    let app = build_app(test_state());

    // Empty address returns an empty list (200)
    let req = Request::get("/api/annotations/0x1000")
        .body(Body::empty())
        .unwrap();
    let (status, anns) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(anns.as_array().unwrap().len(), 0);

    // Add two annotations
    for (text, author) in [("looks like auth", "synth"), ("check bounds", "claw")] {
        let req = Request::post("/api/annotations/0x1000")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({ "text": text, "author": author }).to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Read back
    let req = Request::get("/api/annotations/0x1000")
        .body(Body::empty())
        .unwrap();
    let (status, anns) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let anns = anns.as_array().unwrap();
    assert_eq!(anns.len(), 2);
    assert_eq!(anns[0]["text"], "looks like auth");
    assert_eq!(anns[1]["author"], "claw");
}

#[tokio::test]
async fn test_api_error_responses_are_json() {
    let app = build_app(test_state());

    // Unknown binary id → 404 JSON error
    let req = Request::get("/api/binary/nope/functions")
        .body(Body::empty())
        .unwrap();
    let (status, err) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(err["error"].is_string());

    // Bad binary path → 400 JSON error
    let req = Request::post("/api/binary/load")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "path": "/does/not/exist", "name": "x" }).to_string(),
        ))
        .unwrap();
    let (status, err) = body_json(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(err["error"].as_str().unwrap().contains("failed to load"));
}

#[tokio::test]
async fn test_ui_is_served() {
    let app = build_app(test_state());
    let req = Request::get("/").body(Body::empty()).unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("GhostBin"));
    assert!(html.contains("/api/binary/load"));
}
