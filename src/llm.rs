use reqwest;
use serde::{Deserialize, Serialize};

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

pub struct LlmClient {
    client: reqwest::Client,
    base_url: String,
    model: String,
}

impl LlmClient {
    pub fn new(base_url: String, model: String) -> Self {
        LlmClient {
            client: reqwest::Client::new(),
            base_url,
            model,
        }
    }

    pub async fn analyze_function(&self, disassembly: &[crate::binary::Instruction]) -> anyhow::Result<String> {
        let disasm_text = disassembly.iter()
            .map(|i| format!("0x{:x}: {} {}", i.address, i.mnemonic, i.operands))
            .collect::<Vec<_>>()
            .join("\n");

        let prompt = format!(
            "You are a reverse engineering assistant. Analyze the following disassembled function.\n\
            Provide:\n\
            1. A high-level summary of what this function does\n\
            2. Input parameters and return values\n\
            3. Any security concerns or vulnerabilities\n\
            4. Suggested function name and documentation\n\n\
            Disassembly:\n```asm\n{}\n```",
            disasm_text
        );

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt,
            }],
            max_tokens: 4096,
            temperature: 0.1,
        };

        let response = self.client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&request)
            .send()
            .await?;

        let chat_response: ChatResponse = response.json().await?;

        Ok(chat_response.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default())
    }

    pub async fn explain_instruction(&self, instruction: &str) -> anyhow::Result<String> {
        let prompt = format!(
            "Explain what this assembly instruction does in simple terms:\n{}\n\
            Also explain its significance in reverse engineering context.",
            instruction
        );

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![Message {
                role: "user".to_string(),
                content: prompt,
            }],
            max_tokens: 1024,
            temperature: 0.1,
        };

        let response = self.client
            .post(format!("{}/v1/chat/completions", self.base_url))
            .json(&request)
            .send()
            .await?;

        let chat_response: ChatResponse = response.json().await?;

        Ok(chat_response.choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .unwrap_or_default())
    }
}
