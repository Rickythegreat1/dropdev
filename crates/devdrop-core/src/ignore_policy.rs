use serde::{Deserialize, Serialize};

/// Classification assigned by the ignored/generated/secret path policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathClassification {
    /// Eligible for normal tracking.
    Tracked,
    /// Generated or dependency content excluded from CAS by default.
    Generated,
    /// Secret-bearing path; only metadata such as key names/fingerprints may be modeled.
    Secret,
}

/// Ignore policy for generated and secret paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgnorePolicy {
    /// Generated paths excluded by default.
    pub generated_paths: Vec<String>,
    /// Secret paths whose raw values must never be captured.
    pub secret_paths: Vec<String>,
}

impl Default for IgnorePolicy {
    fn default() -> Self {
        Self {
            generated_paths: vec![
                "node_modules".to_string(),
                ".next".to_string(),
                "dist".to_string(),
                "target".to_string(),
                "*.log".to_string(),
                "logs".to_string(),
            ],
            secret_paths: vec![".env".to_string(), ".env.*".to_string()],
        }
    }
}

impl IgnorePolicy {
    /// Returns the policy classification for a path.
    pub fn classify(&self, path: &str) -> PathClassification {
        let normalized = path.replace('\\', "/");
        let file_name = normalized.rsplit('/').next().unwrap_or(normalized.as_str());

        if self.matches_secret(file_name) {
            return PathClassification::Secret;
        }

        if normalized
            .split('/')
            .any(|part| matches!(part, "node_modules" | ".next" | "dist" | "target" | "logs"))
            || file_name.ends_with(".log")
        {
            return PathClassification::Generated;
        }

        PathClassification::Tracked
    }

    /// Returns true when the path is generated and excluded from content storage.
    pub fn excludes(&self, path: &str) -> bool {
        self.classify(path) == PathClassification::Generated
    }

    /// Returns true when the path is secret metadata only.
    pub fn is_secret_path(&self, path: &str) -> bool {
        self.classify(path) == PathClassification::Secret
    }

    fn matches_secret(&self, file_name: &str) -> bool {
        self.secret_paths.iter().any(|pattern| {
            pattern == file_name
                || (pattern == ".env.*" && file_name.starts_with(".env."))
                || (pattern == ".env" && file_name == ".env")
        })
    }
}
