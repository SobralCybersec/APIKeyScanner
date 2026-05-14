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
            .user_agent("APIKeyScanner-Validator/2.2")
            .build()?;

        Ok(Self { client })
    }

    /// Validate an OpenAI API key (`sk-proj-*` / `sk-*`).
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

        match self
            .client
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

    /// Validate an OpenAI admin key (`sk-admin-*`).
    pub async fn validate_openai_admin(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();

        if !key.starts_with("sk-admin-") || key.len() < 20 {
            return KeyValidationResult {
                provider: "OpenAI".to_string(),
                key_type: "openai-admin".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'sk-admin-')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self
            .client
            .get("https://api.openai.com/v1/organization/admin_api_keys")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "OpenAI".to_string(),
                    key_type: "openai-admin".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Admin key verified - administration endpoint accessible".to_string()
                    } else {
                        format!("✗ Admin key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "OpenAI".to_string(),
                key_type: "openai-admin".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate an Anthropic API key (`sk-ant-*`).
    ///
    /// Uses the read-only `GET /v1/models` endpoint so no tokens are consumed.
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

        match self
            .client
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

    /// Validate a Google / Gemini API key.
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

        match self
            .client
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

    /// Validate an xAI (Grok) API key (`xai-*`).
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

        match self
            .client
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

    /// Validate a Groq API key (`gsk_*`).
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

        match self
            .client
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

    /// Validate a Mistral AI API key.
    pub async fn validate_mistral(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "Mistral".to_string(),
                key_type: "mistral".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://api.mistral.ai/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "Mistral".to_string(),
                    key_type: "mistral".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Mistral models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Mistral".to_string(),
                key_type: "mistral".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Cohere API key.
    pub async fn validate_cohere(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "Cohere".to_string(),
                key_type: "cohere".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://api.cohere.com/v1/models")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "Cohere".to_string(),
                    key_type: "cohere".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Cohere models accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Cohere".to_string(),
                key_type: "cohere".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Hugging Face token (`hf_*`).
    pub async fn validate_huggingface(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if !key.starts_with("hf_") || key.len() < 20 {
            return KeyValidationResult {
                provider: "HuggingFace".to_string(),
                key_type: "huggingface".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'hf_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://huggingface.co/api/whoami-v2")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "HuggingFace".to_string(),
                    key_type: "huggingface".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Token verified - HuggingFace account accessible".to_string()
                    } else {
                        format!("✗ Token invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "HuggingFace".to_string(),
                key_type: "huggingface".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Replicate API token (`r8_*`).
    pub async fn validate_replicate(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if !key.starts_with("r8_") || key.len() < 20 {
            return KeyValidationResult {
                provider: "Replicate".to_string(),
                key_type: "replicate".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'r8_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://api.replicate.com/v1/account")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "Replicate".to_string(),
                    key_type: "replicate".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Token verified - Replicate account accessible".to_string()
                    } else {
                        format!("✗ Token invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Replicate".to_string(),
                key_type: "replicate".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Perplexity API key (`pplx-*`).
    pub async fn validate_perplexity(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "Perplexity".to_string(),
                key_type: "perplexity".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        // GET /v1/models is unauthenticated on Perplexity; use a minimal chat
        // completion that returns 400 (bad request) for valid keys and 401 for
        // invalid ones — no tokens are consumed on a 400.
        match self
            .client
            .post("https://api.perplexity.ai/chat/completions")
            .header("Authorization", format!("Bearer {}", key))
            .header("Content-Type", "application/json")
            .body(r#"{"model":"sonar","messages":[{"role":"user","content":"hi"}],"max_tokens":1}"#)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                // 200 = valid + response; 400 = valid key, bad params; 401/403 = invalid
                let is_valid = status == 200 || status == 400;
                KeyValidationResult {
                    provider: "Perplexity".to_string(),
                    key_type: "perplexity".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Perplexity API accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Perplexity".to_string(),
                key_type: "perplexity".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Slack token (`xoxb-*` / `xoxp-*` / `xoxa-*`).
    pub async fn validate_slack(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        let valid_prefix = key.starts_with("xoxb-")
            || key.starts_with("xoxp-")
            || key.starts_with("xoxa-");
        if !valid_prefix {
            return KeyValidationResult {
                provider: "Slack".to_string(),
                key_type: "slack".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'xoxb-', 'xoxp-', or 'xoxa-')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .post("https://slack.com/api/auth.test")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                // Slack always returns HTTP 200; validity is in the JSON `ok` field.
                let body = response.text().await.unwrap_or_default();
                let is_valid = status == 200
                    && body.contains("\"ok\":true");
                KeyValidationResult {
                    provider: "Slack".to_string(),
                    key_type: "slack".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ Token verified - Slack workspace accessible".to_string()
                    } else {
                        "✗ Token invalid or revoked".to_string()
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Slack".to_string(),
                key_type: "slack".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a SendGrid API key (`SG.*`).
    pub async fn validate_sendgrid(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if !key.starts_with("SG.") || key.len() < 20 {
            return KeyValidationResult {
                provider: "SendGrid".to_string(),
                key_type: "sendgrid".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'SG.')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://api.sendgrid.com/v3/user/profile")
            .header("Authorization", format!("Bearer {}", key))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "SendGrid".to_string(),
                    key_type: "sendgrid".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - SendGrid profile accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "SendGrid".to_string(),
                key_type: "sendgrid".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a Pinecone API key (`pcsk_*` or legacy UUID).
    pub async fn validate_pinecone(&self, key: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();
        if key.len() < 20 {
            return KeyValidationResult {
                provider: "Pinecone".to_string(),
                key_type: "pinecone".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (too short)".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }
        match self
            .client
            .get("https://api.pinecone.io/indexes")
            .header("Api-Key", key)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status().as_u16();
                let is_valid = status == 200;
                KeyValidationResult {
                    provider: "Pinecone".to_string(),
                    key_type: "pinecone".to_string(),
                    is_valid,
                    status_code: Some(status),
                    message: if is_valid {
                        "✓ API key verified - Pinecone indexes accessible".to_string()
                    } else {
                        format!("✗ API key invalid or expired (HTTP {})", status)
                    },
                    response_time_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => KeyValidationResult {
                provider: "Pinecone".to_string(),
                key_type: "pinecone".to_string(),
                is_valid: false,
                status_code: None,
                message: format!("✗ Network error: {}", e),
                response_time_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    /// Validate a DeepSeek API key.
    ///
    /// DeepSeek keys start with `sk-` but can be distinguished from OpenAI keys
    /// by using the scanner's `key_type` hint (`validate_with_hint`) rather than
    /// relying on fragile length / character heuristics.
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

        match self
            .client
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

    /// Validate a GitHub personal access token.
    pub async fn validate_github(&self, token: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();

        let valid_prefix = token.starts_with("ghp_")
            || token.starts_with("gho_")
            || token.starts_with("ghu_")
            || token.starts_with("ghs_")
            || token.starts_with("ghr_")
            || token.starts_with("github_pat_");

        if !valid_prefix {
            return KeyValidationResult {
                provider: "GitHub".to_string(),
                key_type: "github".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with a supported GitHub token prefix)"
                    .to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self
            .client
            .get("https://api.github.com/user")
            .header("Authorization", format!("token {}", token))
            .header("User-Agent", "APIKeyScanner-Validator/2.2")
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

    /// Validate a Stripe secret key (`sk_live_*` / `sk_test_*`).
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

        match self
            .client
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

    /// Validate an AWS access key ID (format check only — the secret key is
    /// required for a live API call).
    pub fn validate_aws_format(&self, key: &str) -> KeyValidationResult {
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
            response_time_ms: 0,
        }
    }

    /// Validate a Vercel API token (`vcp_*` / `vci_*` / `vck_*`).
    pub async fn validate_vercel(&self, token: &str) -> KeyValidationResult {
        let start = std::time::Instant::now();

        if !token.starts_with("vcp_")
            && !token.starts_with("vci_")
            && !token.starts_with("vck_")
        {
            return KeyValidationResult {
                provider: "Vercel".to_string(),
                key_type: "vercel".to_string(),
                is_valid: false,
                status_code: None,
                message: "Invalid format (must start with 'vcp_', 'vci_', or 'vck_')".to_string(),
                response_time_ms: start.elapsed().as_millis() as u64,
            };
        }

        match self
            .client
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

    /// Validate a Supabase key.
    ///
    /// Full live validation requires the project URL, so this is a format
    /// check only.
    pub fn validate_supabase(&self, key: &str) -> KeyValidationResult {
        let is_valid = key.starts_with("sbp_") || key.starts_with("eyJ");
        KeyValidationResult {
            provider: "Supabase".to_string(),
            key_type: "supabase".to_string(),
            is_valid,
            status_code: None,
            message: if is_valid {
                "✓ Format valid (live validation requires project URL)".to_string()
            } else {
                "✗ Invalid format (must start with 'sbp_' or be a JWT)".to_string()
            },
            response_time_ms: 0,
        }
    }

    /// Auto-detect the provider from key prefix and validate.
    ///
    /// For ambiguous `sk-` prefixes (OpenAI vs DeepSeek), prefer
    /// `validate_with_hint` which uses the scanner's `key_type` label to
    /// disambiguate without fragile heuristics.
    pub async fn validate_auto(&self, key: &str) -> KeyValidationResult {
        if key.starts_with("sk-admin-") {
            self.validate_openai_admin(key).await
        } else if key.starts_with("sk-ant-") {
            self.validate_anthropic(key).await
        } else if key.starts_with("sk-proj-") {
            // Project-scoped OpenAI keys always use the `sk-proj-` prefix.
            self.validate_openai(key).await
        } else if key.starts_with("sk_live_") || key.starts_with("sk_test_") {
            self.validate_stripe(key).await
        } else if key.starts_with("AIza") {
            self.validate_google(key).await
        } else if key.starts_with("xai-") {
            self.validate_xai(key).await
        } else if key.starts_with("gsk_") {
            self.validate_groq(key).await
        } else if key.starts_with("vcp_") || key.starts_with("vci_") || key.starts_with("vck_") {
            self.validate_vercel(key).await
        } else if key.starts_with("sbp_") || (key.starts_with("eyJ") && key.len() > 100) {
            self.validate_supabase(key)
        } else if key.starts_with("hf_") {
            self.validate_huggingface(key).await
        } else if key.starts_with("r8_") {
            self.validate_replicate(key).await
        } else if key.starts_with("pplx-") {
            self.validate_perplexity(key).await
        } else if key.starts_with("xoxb-") || key.starts_with("xoxp-") || key.starts_with("xoxa-") {
            self.validate_slack(key).await
        } else if key.starts_with("SG.") {
            self.validate_sendgrid(key).await
        } else if key.starts_with("pcsk_") {
            self.validate_pinecone(key).await
        } else if key.starts_with("ghp_")
            || key.starts_with("gho_")
            || key.starts_with("ghu_")
            || key.starts_with("ghs_")
            || key.starts_with("ghr_")
            || key.starts_with("github_pat_")
        {
            self.validate_github(key).await
        } else if key.starts_with("AKIA") {
            self.validate_aws_format(key)
        } else if key.starts_with("sk-") {
            // Generic `sk-` fallback — treat as standard OpenAI key.
            // Use `validate_with_hint` when a `key_type` label is available.
            self.validate_openai(key).await
        } else {
            KeyValidationResult {
                provider: "Unknown".to_string(),
                key_type: "unknown".to_string(),
                is_valid: false,
                status_code: None,
                message: "✗ Unknown key format — cannot auto-detect provider".to_string(),
                response_time_ms: 0,
            }
        }
    }

    /// Validate using the scanner's `key_type` label as a hint.
    ///
    /// This is the preferred entry point when a label is available because it
    /// correctly disambiguates providers that share a key prefix (e.g. OpenAI
    /// and DeepSeek both use `sk-`).
    pub async fn validate_with_hint(&self, key: &str, key_type: &str) -> KeyValidationResult {
        let hint = key_type.to_ascii_lowercase();

        // Resolve unambiguous prefixes first via auto-detect.
        // Only fall through to hint-based logic for genuinely ambiguous cases.
        if key.starts_with("sk-admin-") {
            return self.validate_openai_admin(key).await;
        }
        if key.starts_with("sk-ant-") {
            return self.validate_anthropic(key).await;
        }
        if key.starts_with("sk-proj-") {
            return self.validate_openai(key).await;
        }

        // Hint-based disambiguation for shared prefixes.
        if key.starts_with("sk-") {
            if hint.contains("deepseek") {
                return self.validate_deepseek(key).await;
            }
            if hint.contains("openai")
                || hint.contains("chatgpt")
                || hint.contains("codex")
                || hint.contains("gpt")
                || hint.contains("dalle")
                || hint.contains("whisper")
            {
                return self.validate_openai(key).await;
            }
            // Default `sk-` to OpenAI when hint is inconclusive.
            return self.validate_openai(key).await;
        }

        // Hint-based routing for providers with no unique prefix.
        if hint.contains("mistral") {
            return self.validate_mistral(key).await;
        }
        if hint.contains("cohere") {
            return self.validate_cohere(key).await;
        }
        if hint.contains("huggingface") || hint.contains("hf-") || hint == "hf-env" {
            return self.validate_huggingface(key).await;
        }
        if hint.contains("replicate") {
            return self.validate_replicate(key).await;
        }
        if hint.contains("perplexity") || hint.contains("pplx") {
            return self.validate_perplexity(key).await;
        }
        if hint.contains("slack") {
            return self.validate_slack(key).await;
        }
        if hint.contains("sendgrid") {
            return self.validate_sendgrid(key).await;
        }
        if hint.contains("pinecone") {
            return self.validate_pinecone(key).await;
        }

        // All remaining keys have unambiguous prefixes — delegate to auto.
        self.validate_auto(key).await
    }
}

// ---------------------------------------------------------------------------
// Batch testing
// ---------------------------------------------------------------------------

/// Test all found keys and report which are still active.
pub async fn test_findings(
    findings: &[crate::storage::PrivateFinding],
) -> Result<Vec<KeyValidationResult>> {
    use std::sync::Arc;
    use tokio::sync::Semaphore;
    use futures::stream::{self, StreamExt};

    // 5 concurrent validation requests; stays well within typical rate limits.
    let validator = Arc::new(KeyValidator::new()?);
    let semaphore = Arc::new(Semaphore::new(5));

    info!("Testing {} API keys for validity...", findings.len());

    let total = findings.len();
    let results: Vec<_> = stream::iter(findings.iter().cloned().enumerate())
        .map(|(i, finding)| {
            let validator = Arc::clone(&validator);
            let semaphore = Arc::clone(&semaphore);
            async move {
                let _permit = semaphore.acquire().await.expect("semaphore closed");

                info!(
                    "Testing key {}/{}: {} from {}",
                    i + 1,
                    total,
                    finding.key_type,
                    finding.repository
                );

                let result = validator
                    .validate_with_hint(&finding.full_key, &finding.key_type)
                    .await;

                if result.is_valid {
                    warn!(
                        "⚠️  ACTIVE KEY FOUND: {} - {} ({}ms)",
                        result.provider, result.message, result.response_time_ms
                    );
                } else {
                    info!("✓ Key inactive: {} - {}", result.provider, result.message);
                }

                // 200 ms inter-request delay ≈ 5 req/s per worker.
                tokio::time::sleep(Duration::from_millis(200)).await;
                result
            }
        })
        .buffer_unordered(5)
        .collect()
        .await;

    save_validation_results(&results, findings).await?;

    Ok(results)
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

async fn save_validation_results(
    results: &[KeyValidationResult],
    findings: &[crate::storage::PrivateFinding],
) -> Result<()> {
    use tokio::fs;

    let timestamp = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();

    // 1. Full JSON results.
    let json_filename = format!("validation_results_{}.json", timestamp);
    fs::write(&json_filename, serde_json::to_string_pretty(&results)?).await?;
    info!("Saved {}", json_filename);

    // 2. CSV results.
    let csv_filename = format!("validation_results_{}.csv", timestamp);
    let mut csv = String::from(
        "Provider,Key Type,Valid,Status Code,Message,Response Time (ms),Repository,Key Preview,Full Key\n",
    );
    for (result, finding) in results.iter().zip(findings.iter()) {
        let full_key = if result.is_valid { finding.full_key.as_str() } else { "" };
        csv.push_str(&format!(
            "\"{}\",\"{}\",{},{},\"{}\",{},\"{}\",\"{}\",\"{}\"\n",
            result.provider,
            result.key_type,
            result.is_valid,
            result
                .status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            result.message.replace('"', "''"),
            result.response_time_ms,
            finding.repository,
            finding.key_preview,
            full_key
        ));
    }
    fs::write(&csv_filename, csv).await?;
    info!("Saved {}", csv_filename);

    // 3. Active-keys-only JSON.
    let valid_filename = format!("valid_{}.json", timestamp);
    let valid_keys: Vec<ValidKeyInfo> = results
        .iter()
        .zip(findings.iter())
        .filter(|(result, _)| result.is_valid)
        .map(|(result, finding)| ValidKeyInfo {
            provider: result.provider.clone(),
            key_type: result.key_type.clone(),
            repository: finding.repository.clone(),
            file_path: finding.file_path.clone(),
            file_url: finding.file_url.clone(),
            key_preview: finding.key_preview.clone(),
            full_key: finding.full_key.clone(),
            discovered_at: finding.discovered_at.clone(),
            validated_at: chrono::Utc::now().to_rfc3339(),
            status_code: result.status_code,
            message: result.message.clone(),
            response_time_ms: result.response_time_ms,
            severity: determine_severity(&result.provider, &result.key_type),
        })
        .collect();

    let active_count = valid_keys.len();
    fs::write(
        &valid_filename,
        serde_json::to_string_pretty(&ValidKeysReport {
            scan_date: chrono::Utc::now().to_rfc3339(),
            total_tested: results.len(),
            valid_count: active_count,
            invalid_count: results.len() - active_count,
            valid_keys,
        })?,
    )
    .await?;
    info!("Saved {} ({} active keys)", valid_filename, active_count);

    Ok(())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidKeyInfo {
    pub provider: String,
    pub key_type: String,
    pub repository: String,
    pub file_path: String,
    pub file_url: String,
    pub key_preview: String,
    /// Full key — only populated for confirmed-active findings.
    pub full_key: String,
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
    match provider {
        "AWS" => "CRITICAL",
        "Stripe" if key_type.contains("live") => "CRITICAL",
        "OpenAI" | "Anthropic" | "Google" | "xAI" | "DeepSeek" | "Groq" => "HIGH",
        "Mistral" | "Cohere" | "HuggingFace" | "Replicate" | "Perplexity" => "HIGH",
        "Stripe" | "GitHub" | "SendGrid" | "Twilio" | "Pinecone" => "MEDIUM",
        "Slack" | "Cloudflare" | "Databricks" | "Shopify" | "Vercel" => "MEDIUM",
        _ => "LOW",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Display validation results in a formatted table (no findings context).
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

    let mut active_count = 0usize;
    let mut inactive_count = 0usize;
    // (active, inactive) per provider
    let mut by_provider: std::collections::HashMap<String, (usize, usize)> =
        std::collections::HashMap::new();

    for (idx, result) in results.iter().enumerate() {
        let (icon, color) = if result.is_valid {
            ("✓", "\x1b[32m")
        } else {
            ("✗", "\x1b[31m")
        };
        let reset = "\x1b[0m";

        println!(
            "{}{} {:<15} {}{}",
            color, icon, result.provider, result.message, reset
        );

        match result.status_code {
            Some(code) => println!(
                "  └─ HTTP {} | Response time: {}ms",
                code, result.response_time_ms
            ),
            None => println!("  └─ Response time: {}ms", result.response_time_ms),
        }

        if result.is_valid {
            if let Some(finding) = findings.and_then(|items| items.get(idx)) {
                println!("  └─ Full key: {}", finding.full_key);
            }
        }
        println!();

        let entry = by_provider
            .entry(result.provider.clone())
            .or_insert((0, 0));
        if result.is_valid {
            active_count += 1;
            entry.0 += 1;
        } else {
            inactive_count += 1;
            entry.1 += 1;
        }
    }

    println!("╔══════════════════════════════════════════════════════════════════════╗");
    println!(
        "║  Summary: {} active | {} inactive | {} total",
        active_count,
        inactive_count,
        results.len()
    );
    println!("╚══════════════════════════════════════════════════════════════════════╝\n");

    if !by_provider.is_empty() {
        println!("By Provider:");
        for (provider, (active, inactive)) in &by_provider {
            println!("   {} - {} active, {} inactive", provider, active, inactive);
        }
        println!();
    }

    if active_count > 0 {
        println!("WARNING: {} ACTIVE API key(s) found!", active_count);
        println!("   These keys are still valid and should be revoked immediately!");
        println!("   Active keys saved to: valid_TIMESTAMP.json (full_key included)\n");
    }

    println!("Validation reports generated:");
    println!("   • validation_results_TIMESTAMP.json — full results");
    println!("   • validation_results_TIMESTAMP.csv  — spreadsheet format");
    println!(
        "   • valid_TIMESTAMP.json              — active keys only ({} found)",
        active_count
    );
    println!();
}
