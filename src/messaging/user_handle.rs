use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{Hash, Hasher};

/// UserHandle is a human-readable, non-network identifier for users in messaging.
/// It is distinct from four-word network endpoints.
#[derive(Clone, Eq, Serialize, Deserialize)]
pub struct UserHandle(String);

impl UserHandle {
    /// Create a new handle after basic validation
    pub fn new<S: Into<String>>(s: S) -> Result<Self, String> {
        let v = s.into().trim().to_string();
        if v.is_empty() {
            return Err("handle cannot be empty".to_string());
        }
        if v.len() > 64 {
            return Err("handle too long (max 64)".to_string());
        }
        if v.chars().any(|c| c.is_control()) {
            return Err("handle contains control characters".to_string());
        }
        Ok(UserHandle(v))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for UserHandle {
    fn from(s: &str) -> Self {
        UserHandle(s.trim().to_string())
    }
}

impl From<String> for UserHandle {
    fn from(s: String) -> Self {
        UserHandle(s.trim().to_string())
    }
}

impl fmt::Debug for UserHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UserHandle({})", self.0)
    }
}

impl fmt::Display for UserHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq for UserHandle {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Hash for UserHandle {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

