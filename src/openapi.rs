use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// OpenAPI 3.0 spec for GhostBin API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: ApiInfo,
    pub servers: Vec<Server>,
    pub paths: HashMap<String, PathItem>,
    pub components: Components,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiInfo {
    pub title: String,
    pub version: String,
    pub description: String,
    pub contact: Contact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub email: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub url: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub get: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post: Option<Operation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delete: Option<Operation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operation {
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<Parameter>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<RequestBody>,
    pub responses: HashMap<String, Response>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub in_: String,
    #[serde(rename = "in")]
    pub location: String,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub schema: SchemaRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestBody {
    pub description: String,
    pub required: bool,
    pub content: HashMap<String, MediaType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaType {
    pub schema: SchemaRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<HashMap<String, MediaType>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaRef {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub schema_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<HashMap<String, SchemaRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<SchemaRef>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ref_path: Option<String>,
    #[serde(rename = "$ref", skip_serializing_if = "Option::is_none")]
    pub ref_field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Components {
    pub schemas: HashMap<String, SchemaRef>,
}

/// Generate the complete OpenAPI spec for GhostBin
pub fn generate_openapi_spec() -> OpenApiSpec {
    let mut paths = HashMap::new();

    // Status endpoint
    paths.insert(
        "/api/status".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "Get server status".to_string(),
                description: Some("Returns server health status and statistics".to_string()),
                tags: vec!["status".to_string()],
                parameters: None,
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Server status".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "version": "0.7.0",
                                                "status": "healthy",
                                                "binaries_loaded": 0,
                                                "annotation_count": 0,
                                                "bookmark_count": 0,
                                                "session_count": 0,
                                                "plugins_loaded": 0,
                                                "websocket_users": 0
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            post: None,
            delete: None,
        },
    );

    // Config endpoint
    paths.insert(
        "/api/config".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "Get server configuration".to_string(),
                description: Some("Returns current server configuration".to_string()),
                tags: vec!["config".to_string()],
                parameters: None,
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Configuration".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "bind_addr": "0.0.0.0",
                                                "port": 8081,
                                                "llm_provider": "llamacpp",
                                                "llm_model": "default"
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            post: None,
            delete: None,
        },
    );

    // Binary load endpoint
    paths.insert(
        "/api/binary/load".to_string(),
        PathItem {
            post: Some(Operation {
                summary: "Load a binary for analysis".to_string(),
                description: Some("Uploads and parses a binary file".to_string()),
                tags: vec!["binary".to_string()],
                parameters: None,
                request_body: Some(RequestBody {
                    description: "Binary load request".to_string(),
                    required: true,
                    content: {
                        let mut content = HashMap::new();
                        content.insert(
                            "application/json".to_string(),
                            MediaType {
                                schema: SchemaRef {
                                    schema_type: Some("object".to_string()),
                                    format: None,
                                    properties: None,
                                    items: None,
                                    required: None,
                                    example: Some(serde_json::json!({
                                        "path": "/path/to/binary",
                                        "name": "my_binary"
                                    })),
                                    ref_path: None,
                                    ref_field: None,
                                },
                                example: None,
                            },
                        );
                        content
                    },
                }),
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Binary loaded successfully".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "id": "bin_0",
                                                "name": "my_binary"
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses.insert(
                        "404".to_string(),
                        Response {
                            description: "Binary file not found".to_string(),
                            content: None,
                        },
                    );
                    responses.insert(
                        "500".to_string(),
                        Response {
                            description: "Internal server error".to_string(),
                            content: None,
                        },
                    );
                    responses
                },
            }),
            get: None,
            delete: None,
        },
    );

    // Binary functions endpoint
    paths.insert(
        "/api/binary/{id}/functions".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "List functions in a binary".to_string(),
                description: Some("Returns all detected functions in the binary".to_string()),
                tags: vec!["binary".to_string()],
                parameters: Some(vec![Parameter {
                    name: "id".to_string(),
                    in_: "path".to_string(),
                    location: "path".to_string(),
                    required: true,
                    description: Some("Binary ID".to_string()),
                    schema: SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: Some(serde_json::Value::String("bin_0".to_string())),
                        ref_path: None,
                        ref_field: None,
                    },
                }]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "List of functions".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("array".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!([
                                                {
                                                    "address": 4198400,
                                                    "name": "main",
                                                    "size": 128
                                                }
                                            ])),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            post: None,
            delete: None,
        },
    );

    // Disassembly endpoint
    paths.insert(
        "/api/binary/{id}/function/{addr}/disasm".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "Get disassembly for a function".to_string(),
                description: Some("Returns disassembled instructions for the specified function".to_string()),
                tags: vec!["disassembly".to_string()],
                parameters: Some(vec![
                    Parameter {
                        name: "id".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Binary ID".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("bin_0".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                    Parameter {
                        name: "addr".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Function address (hex, e.g., 0x401000)".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("0x401000".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                ]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Disassembled instructions".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("array".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!([
                                                {
                                                    "address": 4198400,
                                                    "bytes": [85, 72, 137, 229],
                                                    "mnemonic": "push",
                                                    "operands": "rbp"
                                                }
                                            ])),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            post: None,
            delete: None,
        },
    );

    // Decompile endpoint
    paths.insert(
        "/api/binary/{id}/function/{addr}/decompile".to_string(),
        PathItem {
            post: Some(Operation {
                summary: "Decompile a function".to_string(),
                description: Some("Returns C-like pseudo-code for the specified function".to_string()),
                tags: vec!["decompilation".to_string()],
                parameters: Some(vec![
                    Parameter {
                        name: "id".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Binary ID".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("bin_0".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                    Parameter {
                        name: "addr".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Function address".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("0x401000".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                ]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Decompiled pseudo-code".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "pseudo_code": "void func_unk() {\n    // ...\n}"
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            get: None,
            delete: None,
        },
    );

    // AI Analysis endpoint
    paths.insert(
        "/api/binary/{id}/function/{addr}/analyze".to_string(),
        PathItem {
            post: Some(Operation {
                summary: "AI analyze a function".to_string(),
                description: Some("Uses local LLM to analyze the function and provide insights".to_string()),
                tags: vec!["analysis".to_string()],
                parameters: Some(vec![
                    Parameter {
                        name: "id".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Binary ID".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("bin_0".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                    Parameter {
                        name: "addr".to_string(),
                        in_: "path".to_string(),
                        location: "path".to_string(),
                        required: true,
                        description: Some("Function address".to_string()),
                        schema: SchemaRef {
                            schema_type: Some("string".to_string()),
                            format: None,
                            properties: None,
                            items: None,
                            required: None,
                            example: Some(serde_json::Value::String("0x401000".to_string())),
                            ref_path: None,
                            ref_field: None,
                        },
                    },
                ]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "AI analysis result".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "analysis": "This function appears to be a string comparison routine..."
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            get: None,
            delete: None,
        },
    );

    // Graph endpoint
    paths.insert(
        "/api/graph/{id}/cfg".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "Get control flow graph".to_string(),
                description: Some("Returns CFG data for visualization".to_string()),
                tags: vec!["graph".to_string()],
                parameters: Some(vec![Parameter {
                    name: "id".to_string(),
                    in_: "path".to_string(),
                    location: "path".to_string(),
                    required: true,
                    description: Some("Binary ID".to_string()),
                    schema: SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: Some(serde_json::Value::String("bin_0".to_string())),
                        ref_path: None,
                        ref_field: None,
                    },
                }]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Control flow graph data".to_string(),
                            content: Some({
                                let mut content = HashMap::new();
                                content.insert(
                                    "application/json".to_string(),
                                    MediaType {
                                        schema: SchemaRef {
                                            schema_type: Some("object".to_string()),
                                            format: None,
                                            properties: None,
                                            items: None,
                                            required: None,
                                            example: Some(serde_json::json!({
                                                "nodes": [],
                                                "edges": []
                                            })),
                                            ref_path: None,
                                            ref_field: None,
                                        },
                                        example: None,
                                    },
                                );
                                content
                            }),
                        },
                    );
                    responses
                },
            }),
            post: None,
            delete: None,
        },
    );

    // Annotations endpoint
    paths.insert(
        "/api/annotations/{addr}".to_string(),
        PathItem {
            get: Some(Operation {
                summary: "Get annotations for an address".to_string(),
                description: Some("Returns all annotations at the specified address".to_string()),
                tags: vec!["annotations".to_string()],
                parameters: Some(vec![Parameter {
                    name: "addr".to_string(),
                    in_: "path".to_string(),
                    location: "path".to_string(),
                    required: true,
                    description: Some("Address".to_string()),
                    schema: SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: Some(serde_json::Value::String("0x401000".to_string())),
                        ref_path: None,
                        ref_field: None,
                    },
                }]),
                request_body: None,
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "200".to_string(),
                        Response {
                            description: "Annotation data".to_string(),
                            content: None,
                        },
                    );
                    responses
                },
            }),
            post: Some(Operation {
                summary: "Add annotation".to_string(),
                description: Some("Adds a new annotation at the specified address".to_string()),
                tags: vec!["annotations".to_string()],
                parameters: Some(vec![Parameter {
                    name: "addr".to_string(),
                    in_: "path".to_string(),
                    location: "path".to_string(),
                    required: true,
                    description: Some("Address".to_string()),
                    schema: SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: Some(serde_json::Value::String("0x401000".to_string())),
                        ref_path: None,
                        ref_field: None,
                    },
                }]),
                request_body: Some(RequestBody {
                    description: "Annotation content".to_string(),
                    required: true,
                    content: {
                        let mut content = HashMap::new();
                        content.insert(
                            "application/json".to_string(),
                            MediaType {
                                schema: SchemaRef {
                                    schema_type: Some("object".to_string()),
                                    format: None,
                                    properties: None,
                                    items: None,
                                    required: None,
                                    example: Some(serde_json::json!({
                                        "text": "This is a loop counter",
                                        "author": "analyst1",
                                        "parent_id": null
                                    })),
                                    ref_path: None,
                                    ref_field: None,
                                },
                                example: None,
                            },
                        );
                        content
                    },
                }),
                responses: {
                    let mut responses = HashMap::new();
                    responses.insert(
                        "201".to_string(),
                        Response {
                            description: "Annotation created".to_string(),
                            content: None,
                        },
                    );
                    responses
                },
            }),
            delete: None,
        },
    );

    let mut components = Components {
        schemas: HashMap::new(),
    };

    // Add common schemas
    components.schemas.insert(
        "Binary".to_string(),
        SchemaRef {
            schema_type: Some("object".to_string()),
            format: None,
            properties: Some({
                let mut props = HashMap::new();
                props.insert(
                    "id".to_string(),
                    SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: None,
                        ref_path: None,
                        ref_field: None,
                    },
                );
                props.insert(
                    "name".to_string(),
                    SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: None,
                        ref_path: None,
                        ref_field: None,
                    },
                );
                props
            }),
            items: None,
            required: Some(vec!["id".to_string(), "name".to_string()]),
            example: None,
            ref_path: None,
            ref_field: None,
        },
    );

    components.schemas.insert(
        "Function".to_string(),
        SchemaRef {
            schema_type: Some("object".to_string()),
            format: None,
            properties: Some({
                let mut props = HashMap::new();
                props.insert(
                    "address".to_string(),
                    SchemaRef {
                        schema_type: Some("integer".to_string()),
                        format: Some("uint64".to_string()),
                        properties: None,
                        items: None,
                        required: None,
                        example: None,
                        ref_path: None,
                        ref_field: None,
                    },
                );
                props.insert(
                    "name".to_string(),
                    SchemaRef {
                        schema_type: Some("string".to_string()),
                        format: None,
                        properties: None,
                        items: None,
                        required: None,
                        example: None,
                        ref_path: None,
                        ref_field: None,
                    },
                );
                props.insert(
                    "size".to_string(),
                    SchemaRef {
                        schema_type: Some("integer".to_string()),
                        format: Some("uint64".to_string()),
                        properties: None,
                        items: None,
                        required: None,
                        example: None,
                        ref_path: None,
                        ref_field: None,
                    },
                );
                props
            }),
            items: None,
            required: Some(vec!["address".to_string(), "name".to_string(), "size".to_string()]),
            example: None,
            ref_path: None,
            ref_field: None,
        },
    );

    OpenApiSpec {
        openapi: "3.0.3".to_string(),
        info: ApiInfo {
            title: "GhostBin API".to_string(),
            version: "0.7.0".to_string(),
            description: "AI-assisted reverse engineering platform. Fully offline. No cloud.".to_string(),
            contact: Contact {
                name: "GhostBin Team".to_string(),
                email: "support@ghostbin.dev".to_string(),
            },
        },
        servers: vec![
            Server {
                url: "http://localhost:8081".to_string(),
                description: "Local development server".to_string(),
            },
        ],
        paths,
        components,
    }
}

/// Get OpenAPI spec as JSON value
pub fn get_openapi_json() -> serde_json::Value {
    let spec = generate_openapi_spec();
    serde_json::to_value(spec).unwrap_or_else(|_| serde_json::json!({"error": "Failed to generate spec"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_openapi_spec() {
        let spec = generate_openapi_spec();
        assert_eq!(spec.openapi, "3.0.3");
        assert_eq!(spec.info.title, "GhostBin API");
        assert_eq!(spec.info.version, "0.7.0");
    }

    #[test]
    fn test_openapi_paths() {
        let spec = generate_openapi_spec();
        assert!(spec.paths.contains_key("/api/status"));
        assert!(spec.paths.contains_key("/api/config"));
        assert!(spec.paths.contains_key("/api/binary/load"));
        assert!(spec.paths.contains_key("/api/binary/{id}/functions"));
        assert!(spec.paths.contains_key("/api/binary/{id}/function/{addr}/disasm"));
        assert!(spec.paths.contains_key("/api/binary/{id}/function/{addr}/decompile"));
        assert!(spec.paths.contains_key("/api/binary/{id}/function/{addr}/analyze"));
        assert!(spec.paths.contains_key("/api/graph/{id}/cfg"));
        assert!(spec.paths.contains_key("/api/annotations/{addr}"));
    }

    #[test]
    fn test_openapi_json_output() {
        let json = get_openapi_json();
        assert!(json.get("openapi").is_some());
        assert!(json.get("info").is_some());
        assert!(json.get("paths").is_some());
    }

    #[test]
    fn test_components_schemas() {
        let spec = generate_openapi_spec();
        assert!(spec.components.schemas.contains_key("Binary"));
        assert!(spec.components.schemas.contains_key("Function"));
    }

    #[test]
    fn test_status_endpoint_spec() {
        let spec = generate_openapi_spec();
        let status_path = spec.paths.get("/api/status").unwrap();
        assert!(status_path.get.is_some());

        let get_op = status_path.get.as_ref().unwrap();
        assert_eq!(get_op.summary, "Get server status");
        assert!(get_op.tags.contains(&"status".to_string()));
    }

    #[test]
    fn test_binary_load_spec() {
        let spec = generate_openapi_spec();
        let load_path = spec.paths.get("/api/binary/load").unwrap();
        assert!(load_path.post.is_some());

        let post_op = load_path.post.as_ref().unwrap();
        assert_eq!(post_op.summary, "Load a binary for analysis");
        assert!(post_op.request_body.is_some());

        let responses = &post_op.responses;
        assert!(responses.contains_key("200"));
        assert!(responses.contains_key("404"));
        assert!(responses.contains_key("500"));
    }
}
