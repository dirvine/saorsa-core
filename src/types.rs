// Shared simple types used across modules
use serde::{Deserialize, Serialize};

/// Forward entry (transport endpoint advertisement)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Forward {
    pub proto: String,
    pub addr: String,
    pub exp: u64,
}

