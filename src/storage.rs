use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicFinding {
    pub repository: String,
    pub file_path: String,
    pub file_url: String,
    pub commit_sha: Option<String>,
    pub discovered_at: String,
    pub key_type: String,
    pub key_preview: String,
    pub line_number: Option<usize>,
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateFinding {
    pub repository: String,
    pub file_path: String,
    pub file_url: String,
    pub commit_sha: Option<String>,
    pub discovered_at: String,
    pub key_type: String,
    pub full_key: String,  // NEVER committed to git
    pub key_preview: String,
    pub line_number: Option<usize>,
    pub entropy: Option<f64>,
}

impl From<&PrivateFinding> for PublicFinding {
    fn from(private: &PrivateFinding) -> Self {
        Self {
            repository: private.repository.clone(),
            file_path: private.file_path.clone(),
            file_url: private.file_url.clone(),
            commit_sha: private.commit_sha.clone(),
            discovered_at: private.discovered_at.clone(),
            key_type: private.key_type.clone(),
            key_preview: private.key_preview.clone(),
            line_number: private.line_number,
            entropy: private.entropy,
        }
    }
}

pub struct SecureStorage {
    public_dir: PathBuf,
    private_dir: PathBuf,
}

impl SecureStorage {
    pub fn new() -> Self {
        Self {
            public_dir: PathBuf::from("data"),
            private_dir: PathBuf::from("private_keys"),  // In .gitignore
        }
    }

    pub async fn save_findings(&self, findings: &[PrivateFinding]) -> Result<()> {
        // Create directories
        fs::create_dir_all(&self.public_dir).await?;
        fs::create_dir_all(&self.private_dir).await?;

        // Save public findings (safe for git)
        let public_findings: Vec<PublicFinding> = findings.iter().map(|f| f.into()).collect();
        let public_json = serde_json::to_string_pretty(&public_findings)?;
        fs::write(self.public_dir.join("latest.json"), public_json).await?;

        // Save private findings (NEVER committed)
        let private_json = serde_json::to_string_pretty(&findings)?;
        fs::write(self.private_dir.join("full_keys.json"), private_json).await?;

        Ok(())
    }

    pub async fn load_public_findings(&self) -> Result<Vec<PublicFinding>> {
        let path = self.public_dir.join("latest.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&data)?)
    }

    pub async fn load_private_findings(&self) -> Result<Vec<PrivateFinding>> {
        let path = self.private_dir.join("full_keys.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        let data = fs::read_to_string(path).await?;
        Ok(serde_json::from_str(&data)?)
    }
}
