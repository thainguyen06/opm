use super::types::AgentInfo;
use crate::process::ProcessItem;
use crate::agent::messages::ActionResponse;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// Registry for managing connected agents on the server side
#[derive(Clone)]
pub struct AgentRegistry {
    agents: Arc<RwLock<HashMap<String, AgentInfo>>>,
    agent_processes: Arc<RwLock<HashMap<String, Vec<ProcessItem>>>>,
    /// Channel senders for communicating with agent WebSocket connections
    agent_senders: Arc<RwLock<HashMap<String, mpsc::UnboundedSender<String>>>>,
    /// Pending action responses keyed by request_id
    pending_actions: Arc<RwLock<HashMap<String, oneshot::Sender<ActionResponse>>>>,
}

impl AgentRegistry {
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
            agent_processes: Arc::new(RwLock::new(HashMap::new())),
            agent_senders: Arc::new(RwLock::new(HashMap::new())),
            pending_actions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn register(&self, agent: AgentInfo) {
        let mut agents = self.agents.write().unwrap();
        agents.insert(agent.id.clone(), agent);
    }

    pub fn register_with_sender(&self, agent: AgentInfo, sender: mpsc::UnboundedSender<String>) {
        let agent_id = agent.id.clone();
        let mut agents = self.agents.write().unwrap();
        agents.insert(agent_id.clone(), agent);

        let mut senders = self.agent_senders.write().unwrap();
        senders.insert(agent_id, sender);
    }

    pub fn unregister(&self, id: &str) {
        let mut agents = self.agents.write().unwrap();
        agents.remove(id);
        // Also remove process data
        let mut processes = self.agent_processes.write().unwrap();
        processes.remove(id);
        // Remove sender
        let mut senders = self.agent_senders.write().unwrap();
        senders.remove(id);
    }

    pub fn get(&self, id: &str) -> Option<AgentInfo> {
        let agents = self.agents.read().unwrap();
        agents.get(id).cloned()
    }

    pub fn list(&self) -> Vec<AgentInfo> {
        let agents = self.agents.read().unwrap();
        agents.values().cloned().collect()
    }

    pub fn update_heartbeat(&self, id: &str) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(id) {
            agent.last_seen = std::time::SystemTime::now();
            true
        } else {
            false
        }
    }

    pub fn update_system_info(&self, id: &str, system_info: super::types::SystemInfo) -> bool {
        let mut agents = self.agents.write().unwrap();
        if let Some(agent) = agents.get_mut(id) {
            agent.system_info = Some(system_info);
            true
        } else {
            false
        }
    }

     pub fn update_processes(&self, id: &str, processes: Vec<ProcessItem>) {
         let mut agent_processes = self.agent_processes.write().unwrap();
         agent_processes.insert(id.to_string(), processes);
         log::debug!("[Registry] Process list updated for agent {}", id);
     }

    pub fn get_processes(&self, id: &str) -> Option<Vec<ProcessItem>> {
        let agent_processes = self.agent_processes.read().unwrap();
        agent_processes.get(id).map(|v| {
            // Manually clone by serializing and deserializing
            v.iter()
                .filter_map(|p| {
                    serde_json::to_value(p)
                        .ok()
                        .and_then(|v| serde_json::from_value(v).ok())
                })
                .collect()
        })
    }

    /// Send a message to an agent via its WebSocket connection
    pub fn send_to_agent(&self, agent_id: &str, message: String) -> Result<(), String> {
        let senders = self.agent_senders.read().unwrap();
        if let Some(sender) = senders.get(agent_id) {
            sender
                .send(message)
                .map_err(|e| format!("Failed to send message: {}", e))
        } else {
            Err(format!("Agent {} not connected via WebSocket", agent_id))
        }
    }

    /// Send an action request to an agent and return a receiver for the response
    pub fn send_action_request(
        &self,
        agent_id: &str,
        request_id: String,
        process_id: usize,
        method: String,
    ) -> Result<oneshot::Receiver<ActionResponse>, String> {
        let action_request = super::messages::AgentMessage::ActionRequest {
            request_id: request_id.clone(),
            process_id,
            method,
        };

        let action_json = serde_json::to_string(&action_request)
            .map_err(|e| format!("Failed to serialize action request: {}", e))?;

        // Create a channel for the response
        let (tx, rx) = oneshot::channel();

        // Store the sender in pending actions
        {
            let mut pending = self.pending_actions.write().unwrap();
            pending.insert(request_id, tx);
        }

        // Send the request to the agent
        self.send_to_agent(agent_id, action_json)?;

        Ok(rx)
    }

    /// Handle an action response from an agent
    pub fn handle_action_response(&self, response: ActionResponse) {
        let mut pending = self.pending_actions.write().unwrap();
        if let Some(sender) = pending.remove(&response.request_id) {
            let _ = sender.send(response);
        }
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::new()
    }
}
