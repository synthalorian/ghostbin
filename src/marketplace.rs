use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Plugin marketplace entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplacePlugin {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub category: PluginCategory,
    pub download_url: String,
    pub checksum: String,
    pub rating: f32,
    pub download_count: u32,
    pub tags: Vec<String>,
    pub dependencies: Vec<String>,
    pub min_ghostbin_version: String,
    pub published_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    Analysis,
    Decompiler,
    Disassembler,
    Scanner,
    Utility,
    Visualization,
    Crypto,
    Packer,
    Other,
}

impl std::fmt::Display for PluginCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginCategory::Analysis => write!(f, "analysis"),
            PluginCategory::Decompiler => write!(f, "decompiler"),
            PluginCategory::Disassembler => write!(f, "disassembler"),
            PluginCategory::Scanner => write!(f, "scanner"),
            PluginCategory::Utility => write!(f, "utility"),
            PluginCategory::Visualization => write!(f, "visualization"),
            PluginCategory::Crypto => write!(f, "crypto"),
            PluginCategory::Packer => write!(f, "packer"),
            PluginCategory::Other => write!(f, "other"),
        }
    }
}

/// Plugin search query
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginSearchQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<PluginCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rating: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_by: Option<SortBy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortBy {
    Name,
    Rating,
    DownloadCount,
    UpdatedAt,
}

/// Plugin installation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRequest {
    pub plugin_name: String,
    pub version: Option<String>,
}

/// Plugin installation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    pub success: bool,
    pub plugin_name: String,
    pub version: String,
    pub message: String,
}

/// Plugin marketplace registry
pub struct PluginMarketplace {
    plugins: Mutex<HashMap<String, MarketplacePlugin>>,
}

impl PluginMarketplace {
    pub fn new() -> Arc<Self> {
        let marketplace = Arc::new(PluginMarketplace {
            plugins: Mutex::new(HashMap::new()),
        });

        // Seed with some example plugins
        marketplace.seed_example_plugins();
        marketplace
    }

    /// Seed the marketplace with example plugins
    fn seed_example_plugins(&self) {
        let mut plugins = self.plugins.lock().unwrap();

        let example_plugins = vec![
            MarketplacePlugin {
                name: "capa-analyzer".to_string(),
                version: "1.2.0".to_string(),
                description: "Automatically identifies capabilities in executable files using the capa rules".to_string(),
                author: "GhostBin Team".to_string(),
                category: PluginCategory::Analysis,
                download_url: "https://plugins.ghostbin.dev/capa-analyzer-1.2.0.so".to_string(),
                checksum: "sha256:abc123...".to_string(),
                rating: 4.5,
                download_count: 1523,
                tags: vec!["capabilities".to_string(), "malware".to_string(), "static-analysis".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2024-01-15T00:00:00Z".to_string(),
                updated_at: "2024-03-20T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "string-decoder".to_string(),
                version: "2.0.1".to_string(),
                description: "Detects and decodes obfuscated strings in binaries".to_string(),
                author: "ReverseEngineer42".to_string(),
                category: PluginCategory::Utility,
                download_url: "https://plugins.ghostbin.dev/string-decoder-2.0.1.so".to_string(),
                checksum: "sha256:def456...".to_string(),
                rating: 4.2,
                download_count: 892,
                tags: vec!["strings".to_string(), "deobfuscation".to_string(), "encoding".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2024-02-01T00:00:00Z".to_string(),
                updated_at: "2024-04-10T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "yara-scanner".to_string(),
                version: "1.5.0".to_string(),
                description: "Advanced YARA rule scanner with custom rule support".to_string(),
                author: "GhostBin Team".to_string(),
                category: PluginCategory::Scanner,
                download_url: "https://plugins.ghostbin.dev/yara-scanner-1.5.0.so".to_string(),
                checksum: "sha256:ghi789...".to_string(),
                rating: 4.8,
                download_count: 2104,
                tags: vec!["yara".to_string(), "signatures".to_string(), "malware".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2023-12-01T00:00:00Z".to_string(),
                updated_at: "2024-05-15T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "crypto-detector".to_string(),
                version: "1.0.3".to_string(),
                description: "Identifies cryptographic algorithms and constants in binaries".to_string(),
                author: "CryptoHunter".to_string(),
                category: PluginCategory::Crypto,
                download_url: "https://plugins.ghostbin.dev/crypto-detector-1.0.3.so".to_string(),
                checksum: "sha256:jkl012...".to_string(),
                rating: 4.0,
                download_count: 567,
                tags: vec!["crypto".to_string(), "constants".to_string(), "detection".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2024-03-01T00:00:00Z".to_string(),
                updated_at: "2024-03-15T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "packer-id".to_string(),
                version: "3.1.0".to_string(),
                description: "Identifies packers, cryptors, and protectors used in binaries".to_string(),
                author: "GhostBin Team".to_string(),
                category: PluginCategory::Packer,
                download_url: "https://plugins.ghostbin.dev/packer-id-3.1.0.so".to_string(),
                checksum: "sha256:mno345...".to_string(),
                rating: 4.6,
                download_count: 1834,
                tags: vec!["packers".to_string(), "protectors".to_string(), "identification".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2023-11-15T00:00:00Z".to_string(),
                updated_at: "2024-04-20T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "graph-enhancer".to_string(),
                version: "1.1.0".to_string(),
                description: "Enhances control flow graphs with additional analysis and visual features".to_string(),
                author: "VisMaster".to_string(),
                category: PluginCategory::Visualization,
                download_url: "https://plugins.ghostbin.dev/graph-enhancer-1.1.0.so".to_string(),
                checksum: "sha256:pqr678...".to_string(),
                rating: 4.3,
                download_count: 723,
                tags: vec!["graph".to_string(), "visualization".to_string(), "cfg".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.7.0".to_string(),
                published_at: "2024-04-01T00:00:00Z".to_string(),
                updated_at: "2024-05-01T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "decompiler-enhance".to_string(),
                version: "2.5.0".to_string(),
                description: "Improves decompiler output with better type inference and structure recovery".to_string(),
                author: "GhostBin Team".to_string(),
                category: PluginCategory::Decompiler,
                download_url: "https://plugins.ghostbin.dev/decompiler-enhance-2.5.0.so".to_string(),
                checksum: "sha256:stu901...".to_string(),
                rating: 4.7,
                download_count: 1567,
                tags: vec!["decompiler".to_string(), "types".to_string(), "structures".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.7.0".to_string(),
                published_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-05-10T00:00:00Z".to_string(),
            },
            MarketplacePlugin {
                name: "api-tracer".to_string(),
                version: "1.0.0".to_string(),
                description: "Traces and maps API calls to their documentation".to_string(),
                author: "ApiHunter".to_string(),
                category: PluginCategory::Analysis,
                download_url: "https://plugins.ghostbin.dev/api-tracer-1.0.0.so".to_string(),
                checksum: "sha256:vwx234...".to_string(),
                rating: 3.9,
                download_count: 312,
                tags: vec!["api".to_string(), "tracing".to_string(), "windows".to_string()],
                dependencies: vec![],
                min_ghostbin_version: "0.6.0".to_string(),
                published_at: "2024-05-01T00:00:00Z".to_string(),
                updated_at: "2024-05-01T00:00:00Z".to_string(),
            },
        ];

        for plugin in example_plugins {
            plugins.insert(plugin.name.clone(), plugin);
        }
    }

    /// List all available plugins with optional filtering
    pub fn list_plugins(&self, query: Option<PluginSearchQuery>) -> Vec<MarketplacePlugin> {
        let plugins = self.plugins.lock().unwrap();
        let mut results: Vec<MarketplacePlugin> = plugins.values().cloned().collect();

        if let Some(query) = query {
            // Filter by category
            if let Some(category) = query.category {
                results.retain(|p| p.category == category);
            }

            // Filter by search term
            if let Some(search) = query.search {
                let search_lower = search.to_lowercase();
                results.retain(|p| {
                    p.name.to_lowercase().contains(&search_lower)
                        || p.description.to_lowercase().contains(&search_lower)
                        || p.author.to_lowercase().contains(&search_lower)
                });
            }

            // Filter by tags
            if let Some(tags) = query.tags {
                results.retain(|p| tags.iter().all(|tag| p.tags.contains(tag)));
            }

            // Filter by minimum rating
            if let Some(min_rating) = query.min_rating {
                results.retain(|p| p.rating >= min_rating);
            }

            // Sort results
            match query.sort_by {
                Some(SortBy::Name) => {
                    results.sort_by(|a, b| a.name.cmp(&b.name));
                }
                Some(SortBy::Rating) => {
                    results.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap());
                }
                Some(SortBy::DownloadCount) => {
                    results.sort_by_key(|b| std::cmp::Reverse(b.download_count));
                }
                Some(SortBy::UpdatedAt) => {
                    results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                }
                None => {}
            }

            // Limit results
            if let Some(limit) = query.limit {
                results.truncate(limit);
            }
        }

        results
    }

    /// Get a specific plugin by name
    pub fn get_plugin(&self, name: &str) -> Option<MarketplacePlugin> {
        let plugins = self.plugins.lock().unwrap();
        plugins.get(name).cloned()
    }

    /// Get plugin categories with counts
    pub fn get_categories(&self) -> Vec<(PluginCategory, usize)> {
        let plugins = self.plugins.lock().unwrap();
        let mut counts: HashMap<PluginCategory, usize> = HashMap::new();

        for plugin in plugins.values() {
            *counts.entry(plugin.category.clone()).or_insert(0) += 1;
        }

        counts.into_iter().collect()
    }

    /// Get popular tags
    pub fn get_tags(&self, limit: usize) -> Vec<(String, usize)> {
        let plugins = self.plugins.lock().unwrap();
        let mut tag_counts: HashMap<String, usize> = HashMap::new();

        for plugin in plugins.values() {
            for tag in &plugin.tags {
                *tag_counts.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        let mut tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        tags.sort_by_key(|b| std::cmp::Reverse(b.1));
        tags.truncate(limit);
        tags
    }

    /// Install a plugin (placeholder - would download and load in production)
    pub fn install_plugin(&self, name: &str, _version: Option<&str>) -> anyhow::Result<InstallResult> {
        let plugins = self.plugins.lock().unwrap();

        if let Some(plugin) = plugins.get(name) {
            // In a real implementation, this would:
            // 1. Download the plugin from download_url
            // 2. Verify checksum
            // 3. Check compatibility with current GhostBin version
            // 4. Load the plugin

            Ok(InstallResult {
                success: true,
                plugin_name: plugin.name.clone(),
                version: plugin.version.clone(),
                message: format!("Plugin {} v{} would be installed from {}",
                    plugin.name, plugin.version, plugin.download_url),
            })
        } else {
            Err(anyhow::anyhow!("Plugin '{}' not found in marketplace", name))
        }
    }

    /// Get featured plugins (top rated)
    pub fn get_featured_plugins(&self, limit: usize) -> Vec<MarketplacePlugin> {
        let mut plugins = self.list_plugins(None);
        plugins.sort_by(|a, b| b.rating.partial_cmp(&a.rating).unwrap());
        plugins.truncate(limit);
        plugins
    }

    /// Get recently updated plugins
    pub fn get_recently_updated(&self, limit: usize) -> Vec<MarketplacePlugin> {
        let mut plugins = self.list_plugins(None);
        plugins.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        plugins.truncate(limit);
        plugins
    }
}

/// Marketplace statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceStats {
    pub total_plugins: usize,
    pub total_downloads: u32,
    pub categories: Vec<CategoryStat>,
    pub top_tags: Vec<TagStat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryStat {
    pub category: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagStat {
    pub tag: String,
    pub count: usize,
}

impl PluginMarketplace {
    /// Get marketplace statistics
    pub fn get_stats(&self) -> MarketplaceStats {
        let plugins = self.plugins.lock().unwrap();

        let total_plugins = plugins.len();
        let total_downloads = plugins.values().map(|p| p.download_count).sum();

        let mut category_counts: std::collections::HashMap<PluginCategory, usize> = std::collections::HashMap::new();
        let mut tag_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for plugin in plugins.values() {
            *category_counts.entry(plugin.category.clone()).or_insert(0) += 1;
            for tag in &plugin.tags {
                *tag_counts.entry(tag.clone()).or_insert(0) += 1;
            }
        }

        drop(plugins);

        let categories: Vec<CategoryStat> = category_counts
            .into_iter()
            .map(|(cat, count)| CategoryStat {
                category: cat.to_string(),
                count,
            })
            .collect();

        let mut tags: Vec<(String, usize)> = tag_counts.into_iter().collect();
        tags.sort_by_key(|b| std::cmp::Reverse(b.1));
        tags.truncate(10);

        let top_tags: Vec<TagStat> = tags
            .into_iter()
            .map(|(tag, count)| TagStat { tag, count })
            .collect();

        MarketplaceStats {
            total_plugins,
            total_downloads,
            categories,
            top_tags,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marketplace_creation() {
        let marketplace = PluginMarketplace::new();
        let plugins = marketplace.list_plugins(None);
        assert!(!plugins.is_empty(), "Marketplace should have seeded plugins");
    }

    #[test]
    fn test_list_all_plugins() {
        let marketplace = PluginMarketplace::new();
        let plugins = marketplace.list_plugins(None);
        assert!(plugins.len() >= 5, "Should have multiple plugins");
    }

    #[test]
    fn test_filter_by_category() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: Some(PluginCategory::Analysis),
            search: None,
            tags: None,
            min_rating: None,
            sort_by: None,
            limit: None,
        };

        let plugins = marketplace.list_plugins(Some(query));
        assert!(!plugins.is_empty());
        for plugin in &plugins {
            assert_eq!(plugin.category, PluginCategory::Analysis);
        }
    }

    #[test]
    fn test_filter_by_search() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: None,
            search: Some("crypto".to_string()),
            tags: None,
            min_rating: None,
            sort_by: None,
            limit: None,
        };

        let plugins = marketplace.list_plugins(Some(query));
        assert!(!plugins.is_empty());
        // At least one result should contain "crypto"
        assert!(
            plugins.iter().any(|p| p.name.contains("crypto") || p.description.contains("crypto")),
            "Should find crypto-related plugins"
        );
    }

    #[test]
    fn test_filter_by_rating() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: None,
            search: None,
            tags: None,
            min_rating: Some(4.5),
            sort_by: None,
            limit: None,
        };

        let plugins = marketplace.list_plugins(Some(query));
        for plugin in &plugins {
            assert!(
                plugin.rating >= 4.5,
                "Plugin {} has rating {} < 4.5",
                plugin.name,
                plugin.rating
            );
        }
    }

    #[test]
    fn test_sort_by_downloads() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: None,
            search: None,
            tags: None,
            min_rating: None,
            sort_by: Some(SortBy::DownloadCount),
            limit: None,
        };

        let plugins = marketplace.list_plugins(Some(query));
        if plugins.len() >= 2 {
            assert!(
                plugins[0].download_count >= plugins[1].download_count,
                "Should be sorted by download count descending"
            );
        }
    }

    #[test]
    fn test_limit_results() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: None,
            search: None,
            tags: None,
            min_rating: None,
            sort_by: None,
            limit: Some(3),
        };

        let plugins = marketplace.list_plugins(Some(query));
        assert_eq!(plugins.len(), 3, "Should return exactly 3 plugins");
    }

    #[test]
    fn test_get_plugin() {
        let marketplace = PluginMarketplace::new();

        // Should find an existing plugin
        let plugin = marketplace.get_plugin("yara-scanner");
        assert!(plugin.is_some());
        let plugin = plugin.unwrap();
        assert_eq!(plugin.name, "yara-scanner");
        assert_eq!(plugin.category, PluginCategory::Scanner);

        // Should not find non-existent plugin
        assert!(marketplace.get_plugin("non-existent").is_none());
    }

    #[test]
    fn test_get_categories() {
        let marketplace = PluginMarketplace::new();
        let categories = marketplace.get_categories();
        assert!(!categories.is_empty(), "Should have categories");

        // Should have multiple different categories
        let category_names: Vec<_> = categories.iter().map(|(c, _)| c.to_string()).collect();
        assert!(
            category_names.contains(&"analysis".to_string()),
            "Should have analysis category"
        );
    }

    #[test]
    fn test_get_tags() {
        let marketplace = PluginMarketplace::new();
        let tags = marketplace.get_tags(5);
        assert!(!tags.is_empty(), "Should have tags");
        assert!(tags.len() <= 5, "Should respect limit");

        // Tags should be sorted by count descending
        if tags.len() >= 2 {
            assert!(tags[0].1 >= tags[1].1);
        }
    }

    #[test]
    fn test_get_featured_plugins() {
        let marketplace = PluginMarketplace::new();
        let featured = marketplace.get_featured_plugins(3);
        assert_eq!(featured.len(), 3, "Should return exactly 3 featured plugins");

        // Should be sorted by rating descending
        if featured.len() >= 2 {
            assert!(
                featured[0].rating >= featured[1].rating,
                "Featured plugins should be sorted by rating"
            );
        }
    }

    #[test]
    fn test_get_stats() {
        let marketplace = PluginMarketplace::new();
        let stats = marketplace.get_stats();

        assert!(stats.total_plugins > 0, "Should have plugins");
        assert!(stats.total_downloads > 0, "Should have downloads");
        assert!(!stats.categories.is_empty(), "Should have categories");
        assert!(!stats.top_tags.is_empty(), "Should have top tags");
    }

    #[test]
    fn test_install_plugin() {
        let marketplace = PluginMarketplace::new();

        // Test installing existing plugin
        let result = marketplace.install_plugin("yara-scanner", None);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.success);
        assert_eq!(result.plugin_name, "yara-scanner");

        // Test installing non-existent plugin
        let result = marketplace.install_plugin("non-existent", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_plugin_category_display() {
        assert_eq!(PluginCategory::Analysis.to_string(), "analysis");
        assert_eq!(PluginCategory::Crypto.to_string(), "crypto");
        assert_eq!(PluginCategory::Visualization.to_string(), "visualization");
    }

    #[test]
    fn test_filter_by_tags() {
        let marketplace = PluginMarketplace::new();
        let query = PluginSearchQuery {
            category: None,
            search: None,
            tags: Some(vec!["malware".to_string()]),
            min_rating: None,
            sort_by: None,
            limit: None,
        };

        let plugins = marketplace.list_plugins(Some(query));
        for plugin in &plugins {
            assert!(
                plugin.tags.contains(&"malware".to_string()),
                "Plugin {} should have 'malware' tag",
                plugin.name
            );
        }
    }

    #[test]
    fn test_marketplace_stats_serialization() {
        let stats = MarketplaceStats {
            total_plugins: 10,
            total_downloads: 5000,
            categories: vec![
                CategoryStat {
                    category: "analysis".to_string(),
                    count: 5,
                },
            ],
            top_tags: vec![
                TagStat {
                    tag: "malware".to_string(),
                    count: 3,
                },
            ],
        };

        let json = serde_json::to_string(&stats);
        assert!(json.is_ok());
    }

    #[test]
    fn test_plugin_serialization() {
        let plugin = MarketplacePlugin {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A test plugin".to_string(),
            author: "Test Author".to_string(),
            category: PluginCategory::Utility,
            download_url: "https://example.com/plugin.so".to_string(),
            checksum: "sha256:test".to_string(),
            rating: 4.5,
            download_count: 100,
            tags: vec!["test".to_string()],
            dependencies: vec![],
            min_ghostbin_version: "0.7.0".to_string(),
            published_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&plugin).unwrap();
        assert!(json.contains("test-plugin"));
        assert!(json.contains("1.0.0"));
    }
}
