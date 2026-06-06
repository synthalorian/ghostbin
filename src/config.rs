use serde::{Deserialize, Serialize};
use std::path::Path;

/// GhostBin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Server bind address
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,
    /// LLM configuration
    #[serde(default)]
    pub llm: LlmConfig,
    /// Analysis configuration
    #[serde(default)]
    pub analysis: AnalysisConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// LLM provider (llamacpp, ollama, openai-compatible)
    #[serde(default = "default_llm_provider")]
    pub provider: String,
    /// Base URL for the LLM API
    #[serde(default = "default_llm_base_url")]
    pub base_url: String,
    /// Model name
    #[serde(default = "default_llm_model")]
    pub model: String,
    /// Maximum tokens per request
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Temperature for generation
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    /// Minimum string length to extract
    #[serde(default = "default_min_string_length")]
    pub min_string_length: usize,
    /// Maximum functions to include in reports
    #[serde(default = "default_max_report_functions")]
    pub max_report_functions: usize,
    /// Enable function boundary detection heuristics
    #[serde(default = "default_enable_heuristics")]
    pub enable_heuristics: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind_addr: default_bind_addr(),
            port: default_port(),
            llm: LlmConfig::default(),
            analysis: AnalysisConfig::default(),
        }
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        LlmConfig {
            provider: default_llm_provider(),
            base_url: default_llm_base_url(),
            model: default_llm_model(),
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
        }
    }
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        AnalysisConfig {
            min_string_length: default_min_string_length(),
            max_report_functions: default_max_report_functions(),
            enable_heuristics: default_enable_heuristics(),
        }
    }
}

fn default_bind_addr() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8081
}

fn default_llm_provider() -> String {
    "llamacpp".to_string()
}

fn default_llm_base_url() -> String {
    "http://localhost:8080".to_string()
}

fn default_llm_model() -> String {
    "default".to_string()
}

fn default_max_tokens() -> u32 {
    4096
}

fn default_temperature() -> f32 {
    0.1
}

fn default_min_string_length() -> usize {
    4
}

fn default_max_report_functions() -> usize {
    100
}

fn default_enable_heuristics() -> bool {
    true
}

impl Config {
    /// Load configuration from a TOML file, or return defaults if file doesn't exist
    pub fn load(path: &str) -> anyhow::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Config::default());
        }

        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    #[allow(dead_code)]
    /// Save current configuration to a TOML file
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.bind_addr, "0.0.0.0");
        assert_eq!(config.port, 8081);
        assert_eq!(config.llm.provider, "llamacpp");
        assert_eq!(config.llm.base_url, "http://localhost:8080");
        assert_eq!(config.llm.model, "default");
        assert_eq!(config.llm.max_tokens, 4096);
        assert_eq!(config.analysis.min_string_length, 4);
        assert!(config.analysis.enable_heuristics);
    }

    #[test]
    fn test_config_save_and_load() {
        let config = Config {
            bind_addr: "127.0.0.1".to_string(),
            port: 9090,
            llm: LlmConfig {
                provider: "ollama".to_string(),
                base_url: "http://localhost:11434".to_string(),
                model: "codellama".to_string(),
                max_tokens: 2048,
                temperature: 0.5,
            },
            analysis: AnalysisConfig {
                min_string_length: 8,
                max_report_functions: 50,
                enable_heuristics: false,
            },
        };

        let temp_path = "/tmp/ghostbin_test_config.toml";
        config.save(temp_path).unwrap();

        let loaded = Config::load(temp_path).unwrap();
        assert_eq!(loaded.bind_addr, "127.0.0.1");
        assert_eq!(loaded.port, 9090);
        assert_eq!(loaded.llm.provider, "ollama");
        assert_eq!(loaded.llm.max_tokens, 2048);
        assert_eq!(loaded.analysis.min_string_length, 8);
        assert!(!loaded.analysis.enable_heuristics);

        // Cleanup
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_load_nonexistent_file_returns_defaults() {
        let config = Config::load("/tmp/nonexistent_ghostbin_config.toml").unwrap();
        assert_eq!(config.port, 8081);
        assert_eq!(config.llm.provider, "llamacpp");
    }
}
