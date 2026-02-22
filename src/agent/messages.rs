use serde::{Deserialize, Serialize};

/// Response to an action request
#[derive(Serialize, Deserialize, Debug)]
pub struct ActionResponse {
    pub request_id: String,
    pub success: bool,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LogResponse {
    pub request_id: String,
    pub success: bool,
    pub message: String,
    pub logs: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileResponse {
    pub request_id: String,
    pub success: bool,
    pub message: String,
    pub content: String,
}

/// Message protocol for agent-server WebSocket communication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AgentMessage {
    /// Agent registration message
    Register {
        id: String,
        name: String,
        hostname: Option<String>,
        api_endpoint: Option<String>,
    },
    /// Heartbeat/ping message
    Heartbeat { id: String },
    /// System information update message
    SystemInfoUpdate {
        id: String,
        system_info: super::types::SystemInfo,
    },
    /// Process list update message
    ProcessUpdate {
        id: String,
        processes: Vec<serde_json::Value>,
    },
    /// Action request from server to agent
    ActionRequest {
        request_id: String,
        process_id: usize,
        method: String,
    },
    LogRequest {
        request_id: String,
        process_id: usize,
        kind: String,
    },
    FileRequest {
        request_id: String,
        path: String,
    },
    /// Action response from agent to server
    ActionResponse {
        request_id: String,
        success: bool,
        message: String,
    },
    LogResponse {
        request_id: String,
        success: bool,
        message: String,
        logs: Vec<String>,
    },
    FileResponse {
        request_id: String,
        success: bool,
        message: String,
        content: String,
    },
    /// Save request from server to agent
    SaveRequest { request_id: String },
    /// Response message
    Response { success: bool, message: String },
    /// Ping message from server to agent
    Ping,
    /// Pong response from agent
    Pong,
}
