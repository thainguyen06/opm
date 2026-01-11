use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: String,
    pub name: String,
    pub server_url: String,
    pub token: Option<String>,
    pub reconnect_interval: u64, // seconds
    pub heartbeat_interval: u64, // seconds
}

impl AgentConfig {
    pub fn new(server_url: String, name: Option<String>, token: Option<String>) -> Self {
        let id = Uuid::new_v4().to_string();
        let name = name.unwrap_or_else(|| {
            hostname::get()
                .ok()
                .and_then(|h| h.into_string().ok())
                .unwrap_or_else(|| format!("agent-{}", &id[..8]))
        });

        Self {
            id,
            name,
            server_url,
            token,
            reconnect_interval: 5,  // 5 seconds default
            heartbeat_interval: 30, // 30 seconds default
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AgentStatus {
    Connected,
    Disconnected,
    Connecting,
    Reconnecting,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub status: AgentStatus,
    pub connection_type: String, // "in" for server, "out" for client
    pub last_seen: SystemTime,
    pub address: Option<String>,
}

impl AgentInfo {
    pub fn new(id: String, name: String, connection_type: String) -> Self {
        Self {
            id,
            name,
            status: AgentStatus::Connecting,
            connection_type,
            last_seen: SystemTime::now(),
            address: None,
        }
    }
}
