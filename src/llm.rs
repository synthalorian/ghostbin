use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub max_tokens: u32,
    pub temperature: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct ChatResponse {
    pub choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
pub struct Choice {
    pub message: Message,
}

/// Build the reverse-engineering analysis prompt for a disassembled function.
/// Pure function so it can be unit-tested without a running model.
pub fn build_analysis_prompt(disasm_text: &str) -> String {
    format!(
        "You are a reverse engineering assistant. Analyze the following disassembled function.\n\
        Provide:\n\
        1. A high-level summary of what this function does\n\
        2. Input parameters and return values\n\
        3. Any security concerns or vulnerabilities\n\
        4. Suggested function name and documentation\n\n\
        Disassembly:\n```asm\n{}\n```",
        disasm_text
    )
}

/// Parse an OpenAI-compatible chat completion response body into message text.
/// Pure function so it can be unit-tested with a canned response.
pub fn parse_chat_response(body: &str) -> anyhow::Result<String> {
    let chat_response: ChatResponse = serde_json::from_str(body)?;
    Ok(chat_response
        .choices
        .into_iter()
        .next()
        .map(|c| c.message.content)
        .unwrap_or_default())
}

pub struct LlmClient {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LlmClient {
    pub fn new(base_url: String, model: String) -> Self {
        LlmClient {
            client: reqwest::Client::builder()
                // Fail fast: the LLM is optional, the UI must never hang on it.
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(120))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            base_url,
            model,
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Quick reachability probe for the local model server.
    pub async fn check_available(&self) -> bool {
        self.client
            .get(format!("{}/v1/models", self.base_url))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
    }

    pub async fn analyze_function(
        &self,
        disassembly: &[crate::binary::Instruction],
    ) -> anyhow::Result<String> {
        let disasm_text = disassembly
            .iter()
            .map(|i| format!("0x{:x}: {} {}", i.address, i.mnemonic, i.operands))
            .collect::<Vec<_>>()
            .join("\n");

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: build_analysis_prompt(&disasm_text),
            }],
            max_tokens: 4096,
            temperature: 0.1,
        };

        let response = self
            .client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&request)
            .send()
            .await?;

        let body = response.text().await?;
        parse_chat_response(&body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_analysis_prompt_contains_disasm() {
        let prompt = build_analysis_prompt("0x1000: push rbp\n0x1001: mov rbp, rsp");
        assert!(prompt.contains("reverse engineering assistant"));
        assert!(prompt.contains("0x1000: push rbp"));
        assert!(prompt.contains("```asm"));
    }

    #[test]
    fn test_parse_chat_response_valid() {
        let body = r#"{
            "choices": [
                { "message": { "role": "assistant", "content": "Adds two integers." } }
            ]
        }"#;
        let text = parse_chat_response(body).unwrap();
        assert_eq!(text, "Adds two integers.");
    }

    #[test]
    fn test_parse_chat_response_empty_choices() {
        let body = r#"{ "choices": [] }"#;
        let text = parse_chat_response(body).unwrap();
        assert_eq!(text, "");
    }

    #[test]
    fn test_parse_chat_response_invalid_json() {
        assert!(parse_chat_response("not json").is_err());
    }
}
