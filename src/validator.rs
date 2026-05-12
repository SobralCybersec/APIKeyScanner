use anyhow::Result;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyValidationResult {
    pub provider: String,
    pub key_type: String,
    pub is_valid: bool,
    pub status_code: Option<u16>,
    pub message: String,
    pub response_time_ms: u64,
}

pub struct KeyValidator {
    client: Client,
}

impl KeyValidator {
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .user_agent("APIKeyScanner-Validator/2.1")
            .build()?;
        
        Ok(Self { client })
    }

    /// Validate OpenAI API key (2026: supports sk-proj- and legacy sk-)
    pub async fn validate_openai(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("sk-") || key.len() < 20 {
            return KeyValidationResult {
                provider: "OpenAI".to_string(),
                key_type: "openai".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sk-')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self.client
            .get("https://api.openai.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "OpenAI".to_string(),
                    key_type: "openai".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "OpenAI".to_string(),
                key_type: "openai".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate Anthropic API key (2026: sk-ant-api03-)
    pub async fn validate_anthropic(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("sk-ant-") || key.len() < 20 {
            return KeyValidationResult {
                provider: "Anthropic".to_string(),
                key_type: "anthropic".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sk-ant-')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Use GET /v1/models (read-only endpoint)
        match self.client
            .get("https://api.anthropic.com/v1/models")
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01")
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "Anthropic".to_string(),
                    key_type: "anthropic".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Claude models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Anthropic".to_string(),
                key_type: "anthropic".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate Google/Gemini API key (2026: AIza format)
    pub async fn validate_google(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "Google".to_string(),
                key_type: "google".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self.client
            .get("https://generativelanguage.googleapis.com/v1beta/models")
            .header("x-goog-api-key", key)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "Google".to_string(),
                    key_type: "google".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Gemini models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Google".to_string(),
                key_type: "google".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate xAI (Grok) API key - NEW 2026
    pub async fn validate_xai(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "xAI".to_string(),
                key_type: "xai".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // xAI uses OpenAI-compatible endpoint
        match self.client
            .get("https://api.x.ai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "xAI".to_string(),
                    key_type: "xai".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Grok models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "xAI".to_string(),
                key_type: "xai".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate Groq API key - NEW 2026
    pub async fn validate_groq(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("gsk_") || key.len() < 20 {
            return KeyValidationResult {
                provider: "Groq".to_string(),
                key_type: "groq".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'gsk_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Groq uses OpenAI-compatible endpoint
        match self.client
            .get("https://api.groq.com/openai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "Groq".to_string(),
                    key_type: "groq".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Groq models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Groq".to_string(),
                key_type: "groq".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate DeepSeek API key - NEW 2026
    pub async fn validate_deepseek(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("sk-") || key.len() < 20 {
            return KeyValidationResult {
                provider: "DeepSeek".to_string(),
                key_type: "deepseek".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sk-')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // DeepSeek uses OpenAI-compatible endpoint
        match self.client
            .get("https://api.deepseek.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "DeepSeek".to_string(),
                    key_type: "deepseek".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - DeepSeek models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "DeepSeek".to_string(),
                key_type: "deepseek".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate GitHub token
    pub async fn validate_github(&self, token: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !token.starts_with("ghp_") && !token.starts_with("gho_") && !token.starts_with("ghu_") {
            return KeyValidationResult {
                provider: "GitHub".to_string(),
                key_type: "github".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'ghp_', 'gho_', or 'ghu_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self.client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {}", token))
            .header("User-Agent", "APIKeyScanner-Validator/2.1")
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "GitHub".to_string(),
                    key_type: "github".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Token verified - GitHub API accessible".to_string()
                    } else {
                        format!("✗ Token invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "GitHub".to_string(),
                key_type: "github".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate Stripe key
    pub async fn validate_stripe(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("sk_live_") && !key.starts_with("sk_test_") {
            return KeyValidationResult {
                provider: "Stripe".to_string(),
                key_type: "stripe".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sk_live_' or 'sk_test_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self.client
            .get("https://api.stripe.com/v1/balance")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "Stripe".to_string(),
                    key_type: "stripe".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Stripe API accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Stripe".to_string(),
                key_type: "stripe".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate AWS access key (format check only)
    pub fn validate_aws_format(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        let is_valid = key.starts_with("AKIA") && key.len() == 20;
        
        KeyValidationResult {
            provider: "AWS".to_string(),
            key_type: "aws".to_string(),
            is_valid,
            status_code: None,
            message: if is_valid {
                "✓ Format valid (live validation requires secret key)".to_string()
            } else {
                "✗ Invalid format (must start with 'AKIA' and be exactly 20 chars)".to_string()
            },
            response_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Validate Vercel token - NEW 2026
    pub async fn validate_vercel(&self, token: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !token.starts_with("vcp_") && !token.starts_with("vci_") && !token.starts_with("vck_") {
            return KeyValidationResult {
                provider: "Vercel".to_string(),
                key_type: "vercel".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'vcp_', 'vci_', or 'vck_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Vercel API - GET /v9/user
        match self.client
            .get("https://api.vercel.com/v9/user")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                
                KeyValidationResult {
                    provider: "Vercel".to_string(),
                    key_type: "vercel".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Token verified - Vercel API accessible".to_string()
                    } else {
                        format!("✗ Token invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Vercel".to_string(),
                key_type: "vercel".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate Supabase key - NEW 2026
    pub async fn validate_supabase(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        
        if !key.starts_with("sbp_") && !key.starts_with("eyJ") {
            return KeyValidationResult {
                provider: "Supabase".to_string(),
                key_type: "supabase".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sbp_' or be JWT)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        // Note: Supabase validation requires project URL, so we do format check only
        KeyValidationResult {
            provider: "Supabase".to_string(),
            key_type: "supabase".to_string(),
            is_valid: true,
            status_code: None,
            message: "✓ Format valid (live validation requires project URL)".to_string(),
            response_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Auto-detect and validate key based on format (2026 enhanced)
    pub async fn validate_auto(&self, key: &str) -> KeyValidationResult {
        // 2026 AI providers
        if key.starts_with("sk-proj-") || (key.starts_with("sk-") && !key.starts_with("sk-ant-") && !key.starts_with("sk_")) {
            // Check if it's DeepSeek (hex format) or OpenAI
            if key.len() == 51 && key.chars().skip(3).all(|c| c.is_ascii_hexdigit() || c == '-') {
                self.validate_deepseek(key).await
            } else {
                self.validate_openai(key).await
            }
        } else if key.starts_with("sk-ant-") {
            self.validate_anthropic(key).await
        } else if key.starts_with("AIza") {
            self.validate_google(key).await
        } else if key.starts_with("xai-") {
            self.validate_xai(key).await
        } else if key.starts_with("gsk_") {
            self.validate_groq(key).await
        } 
        // Cloud/Infrastructure
        else if key.starts_with("vcp_") || key.starts_with("vci_") || key.starts_with("vck_") {
            self.validate_vercel(key).await
        } else if key.starts_with("sbp_") || (key.starts_with("eyJ") && key.len() > 100) {
            self.validate_supabase(key).await
        }
        // Version control
        else if key.starts_with("ghp_") || key.starts_with("gho_") || key.starts_with("ghu_") {
            self.validate_github(key).await
        }
        // Cloud providers
        else if key.starts_with("AKIA") {
            self.validate_aws_format(key)
        }
        // Payment
        else if key.starts_with("sk_live_") || key.starts_with("sk_test_") {
            self.validate_stripe(key).await
        }
        else {
            KeyValidationResult {
                provider: "Unknown".to_string(),
                key_type: "unknown".to_string(),
                is_valid: false,
                status_code: None,
                message: "✗ Unknown key format - cannot auto-detect provider".to_string(),
                response_time_ms: 0,
            }
        }
    }

    /// Validate with scanner context when a provider does not have a unique key prefix.
    pub async fn validate_with_hint(&self, key: &str, key_type: &str) -> KeyValidationResult {
        let hint = key_type.to_lowercase();

        if hint.contains("anthropic") || hint.contains("claude") {
            self.validate_anthropic(key).await
        } else if hint.contains("deepseek") {
            self.validate_deepseek(key).await
        } else if hint.contains("groq") {
            self.validate_groq(key).await
        } else if hint.contains("openai")
            || hint.contains("chatgpt")
            || hint.contains("codex")
            || hint.contains("gpt")
            || hint.contains("dalle")
            || hint.contains("whisper")
        {
            self.validate_openai(key).await
        } else if hint.contains("google") || hint.contains("gemini") {
            self.validate_google(key).await
        } else if hint.contains("xai") {
            self.validate_xai(key).await
        } else if hint.contains("vercel") {
            self.validate_vercel(key).await
        } else if hint.contains("supabase") {
            self.validate_supabase(key).await
        } else if hint.contains("github") {
            self.validate_github(key).await
        } else if hint.contains("aws") {
            self.validate_aws_format(key)
        } else if hint.contains("stripe") {
            self.validate_stripe(key).await
        } else {
            self.validate_auto(key).await
        }
    }
}

/// Test all found keys and report which are still active (concurrent with rate limiting)
pub async fn test_findings(findings: &[crate::storage::PrivateFinding]) -> Result<Vec<KeyValidationResult>> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use futures::stream::{self, StreamExt};

    let validator = Arc::new(KeyValidator::new()?);
    let semaphore = Arc::new(Semaphore::new(5)); // 5 concurrent requests

    info!("Testing {} API keys for validity...", findings.len());

    let results: Vec<_> = stream::iter(findings.iter().enumerate())
        .map(|(i, finding)| {
            let validator = Arc::clone(&validator);
            let semaphore = Arc::clone(&semaphore);
            let finding = finding.clone();
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                info!("Testing key {}/{}: {} from {}", 
                    i + 1, findings.len(), finding.key_type, finding.repository);

                let result = validator
                    .validate_with_hint(&finding.full_key, &finding.key_type)
                    .await;
                
                if result.is_valid {
                    warn!("⚠️  ACTIVE KEY FOUND: {} - {} ({}ms)", 
                        result.provider, result.message, result.response_time_ms);
                } else {
                    info!("✓ Key inactive: {} - {}", result.provider, result.message);
                }

                // Rate limiting - 200ms between requests (5 req/sec per worker)
                tokio::time::sleep(Duration::from_millis(200)).await;
                result
            }
        })
        .buffer_unordered(5)
        .collect()
        .await;

    // Save results in multiple formats
    save_validation_results(&results, findings).await?;

    Ok(results)
}

/// Save validation results in JSON, CSV, and valid.json formats
async fn save_validation_results(results: &[KeyValidationResult], findings: &[crate::storage::PrivateFinding]) -> Result<()> {
    use tokio::fs;
    
    // Generate timestamp for filenames: YYYY-MM-DD_HH-MM-SS
    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    
    // 1. Save full results as JSON with timestamp
    let json_filename = format!("validation_results_{}.json", timestamp);
    let json_output = serde_json::to_string_pretty(&results)?;
    fs::write(&json_filename, json_output).await?;
    info!("Saved {}", json_filename);
    
    // 2. Save as CSV with timestamp
    let csv_filename = format!("validation_results_{}.csv", timestamp);
    let mut csv_content = String::from("Provider,Key Type,Valid,Status Code,Message,Response Time (ms),Repository,Key Preview,Full Key\n");
    for (result, finding) in results.iter().zip(findings.iter()) {
        let full_key = if result.is_valid { finding.full_key.as_str() } else { "" };
        csv_content.push_str(&format!(
            "\"{}\",\"{}\",{},{},\"{}\",{},\"{}\",\"{}\",\"{}\"\n",
            result.provider,
            result.key_type,
            result.is_valid,
            result.status_code.map(|c| c.to_string()).unwrap_or_else(|| "N/A".to_string()),
            result.message.replace('"', "''"),
            result.response_time_ms,
            finding.repository,
            finding.key_preview,
            full_key
        ));
    }
    fs::write(&csv_filename, csv_content).await?;
    info!("Saved {}", csv_filename);
    
    // 3. Save only valid keys as valid_TIMESTAMP.json
    let valid_filename = format!("valid_{}.json", timestamp);
    let valid_keys: Vec<ValidKeyInfo> = results.iter()
        .zip(findings.iter())
        .filter(|(result, _)| result.is_valid)
        .map(|(result, finding)| ValidKeyInfo {
            provider: result.provider.clone(),
            key_type: result.key_type.clone(),
            repository: finding.repository.clone(),
            file_path: finding.file_path.clone(),
            file_url: finding.file_url.clone(),
            key_preview: finding.key_preview.clone(),
            full_key: finding.full_key.clone(),  // Include full key for valid keys
            discovered_at: finding.discovered_at.clone(),
            validated_at: chrono::Utc::now().to_rfc3339(),
            status_code: result.status_code,
            message: result.message.clone(),
            response_time_ms: result.response_time_ms,
            severity: determine_severity(&result.provider, &result.key_type),
        })
        .collect();
    
    let valid_json = serde_json::to_string_pretty(&ValidKeysReport {
        scan_date: chrono::Utc::now().to_rfc3339(),
        total_tested: results.len(),
        valid_count: valid_keys.len(),
        invalid_count: results.len() - valid_keys.len(),
        valid_keys,
    })?;
    fs::write(&valid_filename, valid_json).await?;
    info!("Saved {} ({} active keys)", valid_filename, results.iter().filter(|r| r.is_valid).count());
    
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidKeyInfo {
    pub provider: String,
    pub key_type: String,
    pub repository: String,
    pub file_path: String,
    pub file_url: String,
    pub key_preview: String,
    pub full_key: String,  // NEW: Display full key for valid keys
    pub discovered_at: String,
    pub validated_at: String,
    pub status_code: Option<u16>,
    pub message: String,
    pub response_time_ms: u64,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidKeysReport {
    pub scan_date: String,
    pub total_tested: usize,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub valid_keys: Vec<ValidKeyInfo>,
}

fn determine_severity(provider: &str, key_type: &str) -> String {
    match (provider, key_type) {
        // Critical: Production cloud/payment keys
        ("AWS", _) | ("Stripe", "stripe-live") => "CRITICAL".to_string(),
        // High: AI providers with billing
        ("OpenAI", _) | ("Anthropic", _) | ("Google", _) => "HIGH".to_string(),
        // Medium: Development/test keys
        ("Stripe", "stripe-test") | ("GitHub", _) => "MEDIUM".to_string(),
        // Low: Other providers
        _ => "LOW".to_string(),
    }
}

/// Display validation results in a formatted table
#[allow(dead_code)]
pub fn display_validation_results(results: &[KeyValidationResult]) {
    display_validation_results_internal(results, None);
}

/// Display validation results and reveal full keys for confirmed active findings.
pub fn display_validation_results_with_findings(
    results: &[KeyValidationResult],
    findings: &[crate::storage::PrivateFinding],
) {
    display_validation_results_internal(results, Some(findings));
}

fn display_validation_results_internal(
    results: &[KeyValidationResult],
    findings: Option<&[crate::storage::PrivateFinding]>,
) {
    println!("\n╔══════════════════════════════════════════════════════════════════════╗");
    println!("║                    API Key Validation Results (2026)                ║");
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    let mut active_count = 0;
    let mut inactive_count = 0;
    let mut by_provider: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

    for (idx, result) in results.iter().enumerate() {
        let status_icon = if result.is_valid { "✓" } else { "✗" };
        let status_color = if result.is_valid { "\x1b[32m" } else { "\x1b[31m" };
        let reset = "\x1b[0m";

        println!("{}{} {:<15} {}{}", 
            status_color, status_icon, result.provider, result.message, reset);
        
        if let Some(code) = result.status_code {
            println!("  └─ HTTP {} | Response time: {}ms", code, result.response_time_ms);
        } else {
            println!("  └─ Response time: {}ms", result.response_time_ms);
        }
        if result.is_valid {
            if let Some(finding) = findings.and_then(|items| items.get(idx)) {
                println!("  └─ Full key: {}", finding.full_key);
            }
        }
        println!();

        if result.is_valid {
            active_count += 1;
            by_provider.entry(result.provider.clone()).or_insert((0, 0)).0 += 1;
        } else {
            inactive_count += 1;
            by_provider.entry(result.provider.clone()).or_insert((0, 0)).1 += 1;
        }
    }

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!("║  Summary: {} active | {} inactive | {} total", 
        active_count, inactive_count, results.len());
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    if !by_provider.is_empty() {
        println!("By Provider:");
        for (provider, (active, inactive)) in by_provider.iter() {
            println!("   {} - {} active, {} inactive", provider, active, inactive);
        }
        println!();
    }

    if active_count > 0 {
        println!("WARNING: {} ACTIVE API keys found!", active_count);
        println!("   These keys are still valid and should be revoked immediately!");
        println!("   Active keys saved to: valid_TIMESTAMP.json with full_key included\n");
    }
    
    println!("Validation reports generated:");
    println!("   • validation_results.json - Full results");
    println!("   • validation_results.csv - Spreadsheet format");
    println!("   • valid_TIMESTAMP.json - Active keys only, includes full_key ({})", active_count);
    println!();
}
